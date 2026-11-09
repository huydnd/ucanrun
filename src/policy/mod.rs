//! Profiles: the only actions an agent may request. Agents supply parameter
//! values; humans author everything else. Error strings match the Go version
//! because the web UI translates them by their text.

mod adhoc;
mod connection;
mod exec;
pub mod gourl;

#[cfg(test)]
mod tests;

pub use adhoc::{
    ADHOC_PROFILE, APPROVE_AUTO, Call, FieldMeta, SecretMeta, TOTP_ALWAYS, TOTP_NEVER,
    auto_approved, from_call, needs_totp, public_fn, secret_of, split_ref, valid_workspace,
};
pub use connection::{Auth, Connection, resolve};
pub use exec::{RunResult, redact, run, run_with};

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::LazyLock;

pub const RISK_LOW: &str = "low";
pub const RISK_HIGH: &str = "high";

/// The secret placeholder the approver fills in: `{{secret:choice}}`.
pub const CHOICE_REF: &str = "choice";

/// A policy error; `Display` is the message the UI matches on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub(crate) fn err<T>(msg: impl Into<String>) -> Result<T, Error> {
    Err(Error(msg.into()))
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Param {
    pub name: String,
    pub pattern: String,
    pub required: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpSpec {
    pub method: String,
    pub url: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub body: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecSpec {
    pub argv: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Written to the program, for tools such as `sudo -S`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub stdin: String,
    /// Created mode 0600 in the private working directory and removed after
    /// the run, for tools that only read a key from a path.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, String>,
    /// Only on a runner: `{{secret:NAME}}` holding the sudo password. The
    /// runner starts the program through `sudo -S` with it.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sudo: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    pub name: String,
    pub description: String,
    pub risk: String,
    #[serde(skip_serializing_if = "is_false")]
    pub auto_approve: bool,
    #[serde(skip_serializing_if = "is_zero")]
    pub timeout_sec: i64,
    /// What the approver may pick for `{{secret:choice}}`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secret_choices: Vec<String>,
    /// Names a Connection. `http.url` is then a path such as "/repos".
    #[serde(skip_serializing_if = "String::is_empty")]
    pub connection: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<Param>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecSpec>,
    /// Runs the command on this enrolled runner instead of the server.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub runner: String,
}

/// A fully rendered request except for secret placeholders.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Action {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecSpec>,
    pub timeout_sec: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub runner: String,
}

/// Whether `p` is an absolute Windows path such as `C:\\Windows\\x.exe`.
pub fn windows_abs(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

/// The program name of a path, lower case and without `.exe`, for either OS.
fn program_base(p: &str) -> String {
    let base = p
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(p)
        .to_ascii_lowercase();
    base.strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(base)
}

static NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9_-]{0,63}$").unwrap());
pub(crate) static SECRET_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$").unwrap());
static PARAM_NAME_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_]*$").unwrap());
static ENV_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap());
static FILE_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$").unwrap());
// Go's \s is ASCII only.
pub(crate) static TMPL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\{\{[\t\n\x0c\r ]*(secret:)?([A-Za-z0-9_.-]+)[\t\n\x0c\r ]*\}\}").unwrap()
});

pub(crate) fn name_ok(s: &str) -> bool {
    NAME_RE.is_match(s)
}

/// Parameter and secret names referenced by `s`, as written.
pub(crate) fn refs(s: &str) -> (Vec<String>, Vec<String>) {
    let (mut params, mut secrets) = (vec![], vec![]);
    for m in TMPL_RE.captures_iter(s) {
        if m.get(1).is_some() {
            secrets.push(m[2].to_string());
        } else {
            params.push(m[2].to_string());
        }
    }
    (params, secrets)
}

/// True when a secret reference is a public field, which may appear anywhere.
pub type PublicFn<'a> = &'a dyn Fn(&str) -> bool;

fn no_public(_: &str) -> bool {
    false
}

impl Profile {
    /// Enforces the rules that keep a secret from leaving for an
    /// agent-chosen destination.
    pub fn validate(&self) -> Result<(), Error> {
        self.validate_with(&no_public)
    }

    /// Like `validate`, but references for which `public` is true (public
    /// fields of multi-field secrets) may appear in the url and argv.
    pub fn validate_with(&self, public: PublicFn) -> Result<(), Error> {
        if !self.connection.is_empty() {
            // Checked in full once resolved against its connection. Here only
            // the shape is checked, using a stand-in host.
            let h = match &self.http {
                Some(h) if h.url.starts_with('/') => h,
                _ => return err("with a connection the url is a path that starts with /"),
            };
            let mut q = self.clone();
            let mut h = h.clone();
            h.url = format!("https://connection.invalid{}", h.url);
            q.http = Some(h);
            q.connection.clear();
            return q.validate_with(public);
        }
        if !NAME_RE.is_match(&self.name) {
            return err("profile name must match [a-z0-9][a-z0-9_-]*");
        }
        if self.risk != RISK_LOW && self.risk != RISK_HIGH {
            return err("risk must be low or high");
        }
        if self.auto_approve && self.risk == RISK_HIGH {
            return err("a high risk profile cannot auto-approve");
        }
        if self.http.is_none() == self.exec.is_none() {
            return err("exactly one of http or exec is required");
        }
        if !self.runner.is_empty() {
            if !NAME_RE.is_match(&self.runner) {
                return err("runner name must match [a-z0-9][a-z0-9_-]*");
            }
            if self.exec.is_none() {
                return err("a runner only runs commands");
            }
        }
        if !(0..=600).contains(&self.timeout_sec) {
            return err("timeout_sec must be 0..600");
        }
        let mut declared = BTreeSet::new();
        let mut used = BTreeSet::new();
        for q in &self.params {
            if !PARAM_NAME_RE.is_match(&q.name) {
                return err(format!("bad param name {}", gourl::quote(&q.name)));
            }
            if !declared.insert(q.name.clone()) {
                return err(format!("duplicate param {}", gourl::quote(&q.name)));
            }
            if q.pattern.is_empty() {
                return err(format!("param {} needs a pattern", gourl::quote(&q.name)));
            }
            if let Err(e) = Regex::new(&q.pattern) {
                return err(format!("param {}: {e}", gourl::quote(&q.name)));
            }
        }
        let mut texts: Vec<&str> = vec![];
        if let Some(h) = &self.http {
            match h.method.as_str() {
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" => {}
                _ => return err("unsupported http method"),
            }
            // The scheme, host and start of the path must be literal.
            let (head, templated) = match h.url.split_once("{{") {
                Some((a, _)) => (a, true),
                None => (h.url.as_str(), false),
            };
            match gourl::parse(head) {
                Some(u) if (u.scheme == "https" || u.scheme == "http") && !u.host.is_empty() => {}
                _ => return err("url must start with a literal http(s)://host"),
            }
            let after = head.split_once("://").map_or("", |x| x.1);
            if templated && !after.contains('/') {
                return err("template is not allowed in the url host");
            }
            if refs(&h.url).1.iter().any(|n| !public(n)) {
                return err("secrets are not allowed in the url");
            }
            texts.push(&h.url);
            texts.push(&h.body);
            for (k, v) in &h.headers {
                if k.contains("{{") {
                    return err("template is not allowed in a header name");
                }
                // HTTP forbids them anyway; on the approval screen they could
                // add fake lines or reorder text.
                if v.chars().any(gourl::is_control_or_format) {
                    return err(format!(
                        "header {} contains a control character",
                        gourl::quote(k)
                    ));
                }
                texts.push(v);
            }
        }
        if let Some(e) = &self.exec {
            let a0 = e.argv.first().map(String::as_str).unwrap_or("");
            // A runner may be a Windows machine.
            let abs = a0.starts_with('/') || (!self.runner.is_empty() && windows_abs(a0));
            if !abs || a0.contains("{{") {
                return err("argv[0] must be a literal absolute path");
            }
            let base = program_base(a0);
            if matches!(
                base.as_str(),
                "sh" | "bash"
                    | "dash"
                    | "ash"
                    | "zsh"
                    | "env"
                    | "python"
                    | "python3"
                    | "perl"
                    | "ruby"
                    | "node"
                    | "busybox"
                    | "awk"
                    | "sed"
                    | "find"
                    | "xargs"
                    | "sudo"
                    | "su"
                    | "nohup"
                    | "timeout"
                    | "doas"
                    | "pkexec"
                    | "cmd"
                    | "powershell"
                    | "pwsh"
                    | "wscript"
                    | "cscript"
                    | "mshta"
                    | "rundll32"
                    | "regsvr32"
                    | "wsl"
                    | "runas"
            ) {
                return err("interpreters are not allowed, they turn params into code");
            }
            for k in e.env.keys() {
                if !ENV_NAME_RE.is_match(k) || dangerous_env(k) {
                    return err(format!(
                        "env {} is not allowed, it changes how the program runs",
                        gourl::quote(k)
                    ));
                }
            }
            for a in &e.argv {
                if refs(a).1.iter().any(|n| !public(n)) {
                    return err("secrets are only allowed in exec env, argv is visible in /proc");
                }
            }
            if !e.sudo.is_empty() {
                if self.runner.is_empty() {
                    return err("sudo is only for commands on a runner");
                }
                let whole = TMPL_RE
                    .captures(&e.sudo)
                    .is_some_and(|c| c[0].len() == e.sudo.len() && c.get(1).is_some());
                if !whole {
                    return err("sudo must be one {{secret:NAME}} holding the password");
                }
                // sudo resets the environment, so a secret there would be lost,
                // and passing it on argv would show it in /proc.
                if !e.env.is_empty() {
                    return err("with sudo, put secrets in stdin or files: sudo drops env");
                }
                texts.push(&e.sudo);
            }
            texts.extend(e.argv.iter().map(String::as_str));
            texts.push(&e.stdin);
            texts.extend(e.env.values().map(String::as_str));
            for (k, v) in &e.files {
                if !FILE_NAME_RE.is_match(k) {
                    return err(format!(
                        "file name {} must be a plain name",
                        gourl::quote(k)
                    ));
                }
                if !refs(v).0.is_empty() {
                    return err("a file may only contain secrets");
                }
                texts.push(v);
            }
        }
        for t in &texts {
            let (ps, ss) = refs(t);
            for n in ps {
                if !declared.contains(&n) {
                    return err(format!("undeclared param {}", gourl::quote(&n)));
                }
                used.insert(n);
            }
            for n in ss {
                if n.starts_with('_') {
                    return err(format!(
                        "internal secret {} cannot be used",
                        gourl::quote(&n)
                    ));
                }
            }
        }
        let picks = texts
            .iter()
            .any(|t| refs(t).1.iter().any(|n| n == CHOICE_REF));
        if picks && self.secret_choices.is_empty() {
            return err("secret_choices is required for {{secret:choice}}");
        }
        if !picks && !self.secret_choices.is_empty() {
            return err("secret_choices needs a {{secret:choice}} placeholder");
        }
        if picks && self.auto_approve {
            return err("a secret choice needs a human, so it cannot auto-approve");
        }
        for n in &self.secret_choices {
            if n.starts_with('_') || n == CHOICE_REF || !SECRET_NAME_RE.is_match(n) {
                return err(format!("bad secret choice {}", gourl::quote(n)));
            }
        }
        // An unused param never reaches the approver's screen, so it would be
        // an unreviewed channel from the agent into the log.
        for q in &self.params {
            if !used.contains(&q.name) {
                return err(format!(
                    "param {} is declared but never used",
                    gourl::quote(&q.name)
                ));
            }
        }
        Ok(())
    }

    /// Rejects unknown, missing or non-matching values.
    pub fn check_params(&self, input: &BTreeMap<String, String>) -> Result<(), Error> {
        for q in &self.params {
            let Some(v) = input.get(&q.name) else {
                if q.required {
                    return err(format!("missing param {}", gourl::quote(&q.name)));
                }
                continue;
            };
            let re =
                Regex::new(&format!("^(?:{})$", q.pattern)).map_err(|e| Error(e.to_string()))?;
            if v.len() > 4096 || !re.is_match(v) {
                return err(format!(
                    "param {} does not match its pattern",
                    gourl::quote(&q.name)
                ));
            }
            // A value must never be able to form a template, or an agent
            // could pull an arbitrary secret into a request.
            if v.contains("{{") || v.contains("}}") {
                return err(format!(
                    "param {} must not contain template braces",
                    gourl::quote(&q.name)
                ));
            }
            // Control and bidi characters can make the approval text lie.
            if v.chars().any(gourl::is_control_or_format) {
                return err(format!(
                    "param {} contains a control character",
                    gourl::quote(&q.name)
                ));
            }
        }
        for k in input.keys() {
            if !self.params.iter().any(|q| &q.name == k) {
                return err(format!("unknown param {}", gourl::quote(k)));
            }
        }
        Ok(())
    }

    /// Checks params and produces the immutable action.
    pub fn render(&self, params: &BTreeMap<String, String>) -> Result<Action, Error> {
        self.check_params(params)?;
        let raw = |s: &str| s.to_string();
        let mut a = Action {
            timeout_sec: if self.timeout_sec == 0 {
                30
            } else {
                self.timeout_sec
            },
            ..Default::default()
        };
        if let Some(h) = &self.http {
            let u = render_url(&h.url, params)?;
            let mut out = HttpSpec {
                method: h.method.clone(),
                url: u,
                ..Default::default()
            };
            let (mut is_json, mut is_form) = (false, false);
            for (k, v) in &h.headers {
                out.headers.insert(k.clone(), subst(v, params, &raw));
                if k.eq_ignore_ascii_case("content-type") {
                    is_json = v.contains("json");
                    is_form = v.contains("x-www-form-urlencoded");
                }
            }
            let esc: &dyn Fn(&str) -> String = if is_json {
                &gourl::json_escape
            } else if is_form {
                &gourl::query_escape
            } else {
                &raw
            };
            out.body = subst(&h.body, params, esc);
            a.http = Some(out);
        }
        if let Some(e) = &self.exec {
            let mut out = ExecSpec::default();
            for s in &e.argv {
                let v = subst(s, params, &raw);
                // "--upload-pack=..." style values would turn data into an option.
                if v.starts_with('-') && !s.starts_with('-') {
                    return err("a param may not start a command line option");
                }
                out.argv.push(v);
            }
            for (k, v) in &e.env {
                out.env.insert(k.clone(), subst(v, params, &raw));
            }
            out.stdin = subst(&e.stdin, params, &raw);
            out.files = e.files.clone();
            out.sudo = e.sudo.clone();
            a.exec = Some(out);
        }
        a.runner = self.runner.clone();
        // Defence in depth: rendering must not add a secret the profile never named.
        let allowed: BTreeSet<String> = Action {
            http: self.http.clone(),
            exec: self.exec.clone(),
            ..Default::default()
        }
        .secrets()
        .into_iter()
        .collect();
        for n in a.secrets() {
            if !allowed.contains(&n) {
                return err(format!(
                    "rendered action references undeclared secret {}",
                    gourl::quote(&n)
                ));
            }
        }
        Ok(a)
    }

    /// Advice for the author. `validate` decides what is forbidden; this only
    /// points out choices that are legal but often unintended.
    pub fn lint(&self) -> Vec<String> {
        let mut out = vec![];
        if let Some(h) = &self.http {
            let mut text = h.headers.values().cloned().collect::<Vec<_>>().join(" ");
            text.push_str(&h.body);
            if h.url.starts_with("http://") && !refs(&text).1.is_empty() {
                let head = h.url.split("{{").next().unwrap_or("");
                if let Some(u) = gourl::parse(head)
                    && u.hostname().contains('.')
                {
                    out.push(
                        "Secret sẽ đi qua HTTP không mã hoá. Hãy dùng https cho dịch vụ bên ngoài."
                            .to_string(),
                    );
                }
            }
            if h.method != "GET" && self.auto_approve {
                out.push(
                    "Tự chạy với phương thức ghi: agent thay đổi được dữ liệu mà không ai duyệt."
                        .to_string(),
                );
            }
            if h.method == "DELETE" && self.risk != RISK_HIGH {
                out.push("Hành động xoá nên đặt mức cần TOTP.".to_string());
            }
        }
        if self.exec.is_some() {
            out.push("Chạy lệnh là lựa chọn rủi ro hơn gọi API, vì chương trình đó có thể làm nhiều hơn bạn thấy.".to_string());
            if self.auto_approve {
                out.push("Chạy lệnh mà không ai duyệt là rủi ro cao.".to_string());
            }
        }
        for q in &self.params {
            if q.pattern == ".*" || q.pattern == ".+" {
                out.push(format!(
                    "Giá trị \"{}\" nhận mọi thứ. Hãy giới hạn kiểu dữ liệu.",
                    q.name
                ));
            }
        }
        out
    }
}

fn dangerous_env(k: &str) -> bool {
    let u = k.to_uppercase();
    const PREFIXES: [&str; 12] = [
        "LD_",
        "DYLD_",
        "GIT_SSH",
        "GIT_CONFIG",
        "GIT_EXEC",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "BASH_",
        "PYTHON",
        "NODE_",
        "PERL",
        "RUBY",
    ];
    PREFIXES.iter().any(|p| u.starts_with(p))
        || matches!(
            u.as_str(),
            "PATH"
                | "HOME"
                | "IFS"
                | "ENV"
                | "SHELL"
                | "HTTP_PROXY"
                | "HTTPS_PROXY"
                | "ALL_PROXY"
                | "CURL_HOME"
                | "TMPDIR"
        )
}

fn subst(s: &str, params: &BTreeMap<String, String>, esc: &dyn Fn(&str) -> String) -> String {
    TMPL_RE
        .replace_all(s, |c: &regex::Captures| {
            if c.get(1).is_some() {
                // Secrets resolve at execution, after approval.
                return c[0].to_string();
            }
            esc(params.get(&c[2]).map_or("", String::as_str))
        })
        .into_owned()
}

/// Escapes by position: "&" and "=" are harmless in a path but split a query
/// string. A "." or ".." segment is refused, because path escaping keeps dots
/// and the server would resolve the traversal.
fn render_url(u: &str, params: &BTreeMap<String, String>) -> Result<String, Error> {
    let (base, query) = match u.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (u, None),
    };
    let mut out = subst(base, params, &gourl::path_escape);
    if let Some(i) = out.find("://")
        && out[i + 3..].split('/').any(|seg| seg == "." || seg == "..")
    {
        return err("a param may not create a . or .. path segment");
    }
    if let Some(q) = query {
        out.push('?');
        out.push_str(&subst(q, params, &gourl::query_escape));
    }
    Ok(out)
}

impl Action {
    /// Secret references the action uses, as written (`db.password`), sorted.
    pub fn secrets(&self) -> Vec<String> {
        let mut seen = BTreeSet::new();
        let mut add = |s: &str| seen.extend(refs(s).1);
        if let Some(h) = &self.http {
            add(&h.url);
            add(&h.body);
            h.headers.values().for_each(|v| add(v));
        }
        if let Some(e) = &self.exec {
            e.argv.iter().for_each(|v| add(v));
            e.env.values().for_each(|v| add(v));
            add(&e.stdin);
            e.files.values().for_each(|v| add(v));
            add(&e.sudo);
        }
        seen.into_iter().collect()
    }

    /// The text a human approves. It comes from the rendered action, not from
    /// anything the agent wrote, and never contains a secret value.
    pub fn display(&self) -> String {
        let choice = format!("{{{{secret:{CHOICE_REF}}}}}");
        // Values the agent wrote must not add lines or reorder text on the
        // approval screen, so control and bidi characters are shown escaped.
        // Only the body keeps its line breaks.
        let mask_with = |s: &str, lines: bool| {
            let s = s.replace(&choice, "‹secret bạn chọn khi duyệt›");
            let s = TMPL_RE.replace_all(&s, "‹secret:$2›").into_owned();
            visible(&s, lines)
        };
        let mask = |s: &str| mask_with(s, false);
        let mut b = String::new();
        if let Some(h) = &self.http {
            b.push_str(&format!("{} {}", h.method, mask(&h.url)));
            for (k, v) in &h.headers {
                b.push_str(&format!("\n{k}: {}", mask(v)));
            }
            if !h.body.is_empty() {
                b.push_str(&format!("\n\n{}", mask_with(&h.body, true)));
            }
        }
        if let Some(e) = &self.exec {
            let q: Vec<String> = e.argv.iter().map(|s| mask(&gourl::quote(s))).collect();
            b.push_str(&q.join(" "));
            for (k, v) in &e.env {
                b.push_str(&format!("\nenv {k}={}", mask(v)));
            }
            if !e.stdin.is_empty() {
                b.push_str(&format!("\nstdin: {}", mask(&e.stdin)));
            }
            for (k, v) in &e.files {
                b.push_str(&format!("\nfile {k}: {}", mask(v)));
            }
            if !e.sudo.is_empty() {
                b.push_str(&format!("\nsudo: {}", mask(&e.sudo)));
            }
        }
        if !self.runner.is_empty() {
            b.push_str(&format!("\nrunner: {}", self.runner));
        }
        b
    }

    /// A copy that uses the secret the approver picked. The agent never
    /// influences this: the name comes from the decision, checked against the
    /// profile's list.
    pub fn with_choice(&self, name: &str) -> Action {
        let from = format!("{{{{secret:{CHOICE_REF}}}}}");
        let to = format!("{{{{secret:{name}}}}}");
        let r = |s: &str| s.replace(&from, &to);
        let m = |m: &BTreeMap<String, String>| -> BTreeMap<String, String> {
            m.iter().map(|(k, v)| (k.clone(), r(v))).collect()
        };
        let mut c = self.clone();
        if let Some(h) = &mut c.http {
            h.headers = m(&h.headers);
            h.body = r(&h.body);
        }
        if let Some(e) = &mut c.exec {
            e.env = m(&e.env);
            e.files = m(&e.files);
            e.stdin = r(&e.stdin);
            e.sudo = r(&e.sudo);
        }
        c
    }
}

/// Binds an approval to this exact action, profile and caller. Not equal to
/// the Go hash; approvals do not cross implementations.
pub fn hash(p: &Profile, a: &Action, caller: &str) -> String {
    let v = serde_json::json!({ "P": p, "A": a, "C": caller });
    let b = serde_json::to_vec(&v).unwrap_or_default();
    hex::encode(Sha256::digest(b))
}

/// Escapes control and format characters, keeping line breaks if `lines`.
fn visible(s: &str, lines: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' if lines => out.push('\n'),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if gourl::is_control_or_format(c) => {
                out.push_str(&format!("\\u{{{:04x}}}", c as u32))
            }
            c => out.push(c),
        }
    }
    out
}

/// Replaces secret placeholders. Used only by the executor.
pub fn expand(s: &str, get: &dyn Fn(&str) -> String) -> String {
    TMPL_RE
        .replace_all(s, |c: &regex::Captures| {
            if c.get(1).is_none() {
                return c[0].to_string();
            }
            get(&c[2])
        })
        .into_owned()
}
