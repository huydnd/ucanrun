//! Requests an agent writes itself, checked against the owner's secret rules.

use super::{Error, ExecSpec, HttpSpec, Profile, RISK_HIGH, RISK_LOW, TMPL_RE, err, gourl, refs};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// Labels requests built from a `Call`.
pub const ADHOC_PROFILE: &str = "agent-call";

/// One named field of a multi-field secret. A public field (host, port, user,
/// database) is shown to agents with its value and may appear anywhere.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FieldMeta {
    pub name: String,
    pub public: bool,
}

/// What the owner writes next to a secret: what it is for and where it may be
/// sent. Agents see it; they never see the value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretMeta {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Hosts the secret may be sent to, such as "api.github.com" or
    /// "*.example.com". Empty means it cannot be used in agent calls.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Lets agents use the secret in commands they write. The host cannot be
    /// checked for a command, so these count as high risk.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub allow_commands: bool,
    /// TOTP when approving a request that uses this secret: empty follows the
    /// risk level (high risk needs it), `always` or `never`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub totp: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldMeta>,
}

pub const TOTP_ALWAYS: &str = "always";
pub const TOTP_NEVER: &str = "never";

/// Whether approving a request needs a TOTP code. A secret set to `always`
/// forces it; otherwise high risk needs it unless every secret involved is
/// set to `never`. High risk with no secret at all still needs it.
pub fn needs_totp(risk: &str, secrets: &[String], meta: &BTreeMap<String, SecretMeta>) -> bool {
    let mode = |n: &String| -> &str {
        let m = meta
            .get(n.as_str())
            .or_else(|| n.rsplit_once('.').and_then(|(base, _)| meta.get(base)));
        m.map_or("", |m| m.totp.as_str())
    };
    if secrets.iter().any(|n| mode(n) == TOTP_ALWAYS) {
        return true;
    }
    risk == RISK_HIGH && (secrets.is_empty() || secrets.iter().any(|n| mode(n) != TOTP_NEVER))
}

static HOST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(:[0-9]{1,5})?$")
        .unwrap()
});
static FIELD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_]{0,31}$").unwrap());

impl SecretMeta {
    pub fn validate(&self) -> Result<(), Error> {
        if self.description.chars().count() > 300 {
            return err("description is limited to 300 characters");
        }
        if self
            .description
            .chars()
            .any(|c| c != '\n' && gourl::is_control_or_format(c))
        {
            return err("description contains a control character");
        }
        if self.hosts.len() > 20 {
            return err("at most 20 hosts");
        }
        if !matches!(self.totp.as_str(), "" | TOTP_ALWAYS | TOTP_NEVER) {
            return err("totp must be empty, always or never");
        }
        for h in &self.hosts {
            if !HOST_RE.is_match(h) {
                return err(format!(
                    "bad host {}, use a name such as api.example.com",
                    gourl::quote(h)
                ));
            }
        }
        for (i, f) in self.fields.iter().enumerate() {
            if !FIELD_RE.is_match(&f.name) {
                return err(format!("bad field name {}", gourl::quote(&f.name)));
            }
            if self.fields[..i].iter().any(|g| g.name == f.name) {
                return err(format!("duplicate field {}", gourl::quote(&f.name)));
            }
        }
        Ok(())
    }

    fn allows_host(&self, u: &gourl::GoUrl) -> bool {
        let host = u.host.to_lowercase();
        let name = u.hostname().to_lowercase();
        self.hosts.iter().any(|h| {
            if let Some(suffix) = h.strip_prefix("*.") {
                return name.ends_with(&format!(".{suffix}"));
            }
            *h == host || (*h == name && u.port().is_empty())
        })
    }

    fn field(&self, name: &str) -> Option<&FieldMeta> {
        self.fields.iter().find(|f| f.name == name)
    }
}

/// Splits a secret reference into the secret and an optional field. The exact
/// name wins; otherwise the last dot separates the field.
pub fn split_ref<'a>(r: &'a str, known: &dyn Fn(&str) -> bool) -> (&'a str, Option<&'a str>) {
    if known(r) {
        return (r, None);
    }
    if let Some((s, f)) = r.rsplit_once('.')
        && known(s)
    {
        return (s, Some(f));
    }
    (r, None)
}

/// A callback for `Profile::validate_with`: true when the reference names a
/// public field of a secret in `meta`.
pub fn public_fn(meta: &BTreeMap<String, SecretMeta>) -> impl Fn(&str) -> bool + '_ {
    move |r| matches!(classify(r, meta), Ok(Kind::Public))
}

#[derive(Debug, PartialEq)]
enum Kind {
    Public,
    Private,
}

/// Looks a reference up in the owner's metadata.
fn classify(r: &str, meta: &BTreeMap<String, SecretMeta>) -> Result<Kind, Error> {
    let (s, f) = split_ref(r, &|n| meta.contains_key(n));
    let Some(m) = meta.get(s) else {
        return err(format!("unknown secret {}", gourl::quote(r)));
    };
    match f {
        Some(f) => match m.field(f) {
            Some(fm) if fm.public => Ok(Kind::Public),
            Some(_) => Ok(Kind::Private),
            None => err(format!(
                "unknown field {} of secret {}",
                gourl::quote(f),
                gourl::quote(s)
            )),
        },
        None if !m.fields.is_empty() => err(format!(
            "secret {} has fields, use {{{{secret:{s}.FIELD}}}}",
            gourl::quote(s)
        )),
        None => Ok(Kind::Private),
    }
}

/// An agent's request, with `{{secret:name}}` where a secret goes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Call {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecSpec>,
}

/// Turns an agent's call into a profile, enforcing where each secret may go.
/// The result also passes through `validate` and `render` like any profile.
pub fn from_call(c: &Call, meta: &BTreeMap<String, SecretMeta>) -> Result<Profile, Error> {
    let mut p = Profile {
        name: ADHOC_PROFILE.to_string(),
        risk: RISK_LOW.to_string(),
        description: "agent call".to_string(),
        ..Default::default()
    };
    if c.http.is_none() == c.exec.is_none() {
        return err("a call is either http or exec");
    }
    let mut used = 0;
    if let Some(h) = &c.http {
        // No private secret outside header values: the URL and body are the
        // agent's own text, and a secret in a body can end up stored and public.
        let strip = |s: &str| {
            TMPL_RE
                .replace_all(s, |m: &regex::Captures| {
                    if m.get(1).is_some() && matches!(classify(&m[2], meta), Ok(Kind::Public)) {
                        String::new()
                    } else {
                        m[0].to_string()
                    }
                })
                .into_owned()
        };
        if strip(&h.url).contains("{{") || strip(&h.body).contains("{{") {
            return err("secrets go in headers only, never in the url or body");
        }
        let u = match gourl::parse(&h.url) {
            Some(u)
                if (u.scheme == "https" || u.scheme == "http")
                    && !u.host.is_empty()
                    && !u.has_user =>
            {
                u
            }
            _ => return err("url must be absolute http(s) without user info"),
        };
        for (k, v) in &h.headers {
            if k.contains("{{") {
                return err("no templates in header names");
            }
            let (ps, ss) = refs(v);
            if !ps.is_empty() {
                return err("only {{secret:name}} templates are allowed");
            }
            for n in ss {
                if classify(&n, meta)? == Kind::Public {
                    continue;
                }
                let (s, _) = split_ref(&n, &|x| meta.contains_key(x));
                if !meta[s].allows_host(&u) {
                    return err(format!(
                        "secret {} may not be sent to {}",
                        gourl::quote(&n),
                        u.host
                    ));
                }
                used += 1;
            }
        }
        p.http = Some(h.clone());
    }
    if let Some(e) = &c.exec {
        p.risk = RISK_HIGH.to_string();
        let mut texts: Vec<&str> = vec![&e.stdin];
        texts.extend(e.argv.iter().map(String::as_str));
        texts.extend(e.env.values().map(String::as_str));
        texts.extend(e.files.values().map(String::as_str));
        for t in texts {
            let (ps, ss) = refs(t);
            if !ps.is_empty() {
                return err("only {{secret:name}} templates are allowed");
            }
            for n in ss {
                if classify(&n, meta)? == Kind::Public {
                    continue;
                }
                let (s, _) = split_ref(&n, &|x| meta.contains_key(x));
                if !meta[s].allow_commands {
                    return err(format!(
                        "secret {} is not allowed in commands",
                        gourl::quote(&n)
                    ));
                }
                used += 1;
            }
        }
        p.exec = Some(e.clone());
    }
    if used == 0 {
        return err("the call uses no secret, so run it yourself");
    }
    p.validate_with(&public_fn(meta))?;
    Ok(p)
}
