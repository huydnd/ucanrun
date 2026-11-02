//! A connection describes one service once: where it lives and how to sign in.

use super::{CHOICE_REF, Error, Profile, SECRET_NAME_RE, err, gourl, name_ok};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::LazyLock;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Connection {
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub title: String,
    pub base_url: String,
    pub auth: Auth,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

/// Auth types put the secret in a header. Secrets never go in a URL.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Auth {
    /// none, bearer, token or header
    #[serde(rename = "type")]
    pub kind: String,
    /// For type header.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub header: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub secret: String,
    /// Lets the approver pick the secret for each request, such as a personal
    /// or a work account. `secret` is then empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
}

static HEADER_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9-]{1,64}$").unwrap());

impl Connection {
    pub fn validate(&self) -> Result<(), Error> {
        if !name_ok(&self.name) {
            return err("connection name must match [a-z0-9][a-z0-9_-]*");
        }
        if self.base_url.contains("{{") {
            return err("the base url of a connection is fixed and takes no values");
        }
        match gourl::parse(&self.base_url) {
            Some(u)
                if (u.scheme == "https" || u.scheme == "http")
                    && !u.host.is_empty()
                    && !u.has_user =>
            {
                if !u.query.is_empty() || !u.fragment.is_empty() {
                    return err("base url must not have a query or fragment");
                }
            }
            _ => return err("base url must look like https://api.example.com"),
        }
        for (k, v) in &self.headers {
            if !HEADER_NAME_RE.is_match(k) || v.contains("{{") {
                return err(format!(
                    "header {} must be a plain name with a fixed value",
                    gourl::quote(k)
                ));
            }
        }
        let a = &self.auth;
        match a.kind.as_str() {
            "none" => {
                if !a.secret.is_empty() || !a.choices.is_empty() {
                    return err("auth none takes no secret");
                }
                return Ok(());
            }
            "bearer" | "token" => {}
            "header" => {
                if !HEADER_NAME_RE.is_match(&a.header) {
                    return err("auth header needs a header name");
                }
            }
            _ => return err("auth type must be none, bearer, token or header"),
        }
        if a.secret.is_empty() == a.choices.is_empty() {
            return err("auth needs either one secret or a list of choices");
        }
        for n in std::iter::once(&a.secret).chain(&a.choices) {
            if n.is_empty() && a.secret.is_empty() {
                continue;
            }
            if n.starts_with('_') || n == CHOICE_REF || !SECRET_NAME_RE.is_match(n) {
                return err(format!("bad secret name {}", gourl::quote(n)));
            }
        }
        Ok(())
    }

    fn auth_header(&self) -> (String, String) {
        let r = if self.auth.choices.is_empty() {
            format!("{{{{secret:{}}}}}", self.auth.secret)
        } else {
            format!("{{{{secret:{CHOICE_REF}}}}}")
        };
        match self.auth.kind.as_str() {
            "bearer" => ("Authorization".into(), format!("Bearer {r}")),
            "token" => ("Authorization".into(), format!("token {r}")),
            "header" => (self.auth.header.clone(), r),
            _ => (String::new(), String::new()),
        }
    }
}

/// Turns a profile that uses a connection into a self-contained one. The
/// result goes through the normal `validate` and `render`, so every rule still
/// applies. Profiles without a connection come back unchanged.
pub fn resolve(p: &Profile, conns: &BTreeMap<String, Connection>) -> Result<Profile, Error> {
    if p.connection.is_empty() {
        return Ok(p.clone());
    }
    let Some(c) = conns.get(&p.connection) else {
        return err(format!(
            "unknown connection {}",
            gourl::quote(&p.connection)
        ));
    };
    c.validate()?;
    let src = match (&p.http, &p.exec) {
        (Some(h), None) => h,
        _ => return err("a profile with a connection must be an http request"),
    };
    let path = &src.url;
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains("://")
        || path.contains('\\')
    {
        return err("with a connection the url is a path that starts with /");
    }
    if !p.secret_choices.is_empty() {
        return err("secret choices belong to the connection");
    }
    let mut h = src.clone();
    h.url = format!("{}{}", c.base_url.trim_end_matches('/'), path);
    h.headers = c.headers.clone();
    let (ak, av) = c.auth_header();
    for (k, v) in &src.headers {
        if !ak.is_empty() && k.eq_ignore_ascii_case(&ak) {
            return err(format!(
                "header {} is set by the connection",
                gourl::quote(k)
            ));
        }
        h.headers.insert(k.clone(), v.clone());
    }
    if !ak.is_empty() {
        h.headers.insert(ak, av);
    }
    let mut out = p.clone();
    out.connection.clear();
    out.http = Some(h);
    out.secret_choices = c.auth.choices.clone();
    Ok(out)
}
