//! The agent side of the API, used by `ucr run`, `ucr doctor` and `ucr mcp`.

use std::time::Duration;

use serde_json::{Value, json};

pub struct Client {
    pub url: String,
    pub token: String,
    /// Agent software, sent for the run log. `ucr mcp` fills it from the
    /// MCP handshake.
    pub app: String,
    device: String,
    http: reqwest::Client,
}

/// Header values must be visible ASCII; anything else would fail the request.
fn header_safe(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(64)
        .collect()
}

/// This machine's host name, for the run log.
#[cfg(windows)]
pub fn host_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

/// This machine's host name, for the run log.
#[cfg(not(windows))]
pub fn host_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its length and gethostname writes at most that.
    let r = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if r != 0 {
        return String::new();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// The exit status `ucr` uses for an agent error code, after sysexits.h:
/// 77 when only the human can grant it, 75 when trying again later can work.
pub fn exit_code(err: &str) -> i32 {
    let code = err
        .split_once("[code: ")
        .and_then(|(_, r)| r.split_once(']'))
        .map_or("", |(c, _)| c);
    match code {
        "locked" | "rate_limited" => 75,
        "forbidden"
        | "invalid_token"
        | "missing_token"
        | "no_hosts"
        | "host_not_allowed"
        | "commands_not_allowed"
        | "exec_off" => 77,
        "unknown_secret" | "not_found" | "unknown_runner" => 78,
        "runner_offline" => 75,
        "" => 1,
        _ => 65,
    }
}

impl Client {
    pub fn new(url: &str, token: &str) -> Client {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(130))
            .build()
            .expect("http client");
        Client {
            url: url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            app: "ucr".into(),
            device: host_name(),
            http,
        }
    }

    /// Reads UCANRUN_URL and UCANRUN_TOKEN, then what `ucr login` saved:
    /// the Windows Credential Manager, or ~/.config/ucanrun/token.
    pub fn from_env() -> Result<Client, String> {
        let saved = crate::tokenstore::load().unwrap_or_default();
        let env = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
        let url = env("UCANRUN_URL")
            .or_else(|| (!saved.url.is_empty()).then(|| saved.url.clone()))
            .unwrap_or_else(|| "http://127.0.0.1:8781".into());
        let token = env("UCANRUN_TOKEN").unwrap_or(saved.token);
        if token.is_empty() {
            return Err(format!(
                "no agent token: run ucr login, or set UCANRUN_TOKEN [code: missing_token]\nAsk the human: Create an agent token on the Agent tokens tab, then run ucr login (saved in {}).",
                crate::tokenstore::location()
            ));
        }
        Ok(Client::new(&url, &token))
    }

    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, String> {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.url))
            .header("X-Ucanrun-Device", header_safe(&self.device))
            .header("X-Ucanrun-App", header_safe(&self.app));
        // No header at all without a token, so the server says missing_token.
        if !self.token.is_empty() {
            req = req.bearer_auth(&self.token);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|e| e.without_url().to_string())?;
        let status = resp.status();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            let msg = v.get("error").and_then(Value::as_str).unwrap_or("");
            let mut e = format!("ucanrun: {msg} (HTTP {})", status.as_u16());
            // Agents branch on the code; the human fixes what ask_human says.
            if let Some(c) = v.get("code").and_then(Value::as_str) {
                e.push_str(&format!(" [code: {c}]"));
            }
            if let Some(a) = v.get("ask_human").and_then(Value::as_str) {
                e.push_str(&format!("\nAsk the human: {a}"));
            }
            return Err(e);
        }
        Ok(v)
    }

    pub async fn profiles(&self) -> Result<Value, String> {
        self.send(reqwest::Method::GET, "/v1/profiles", None).await
    }
    pub async fn runners(&self) -> Result<Value, String> {
        self.send(reqwest::Method::GET, "/v1/runners", None).await
    }
    pub async fn secrets(&self) -> Result<Value, String> {
        self.send(reqwest::Method::GET, "/v1/secrets", None).await
    }
    pub async fn run(
        &self,
        profile: &str,
        params: Value,
        reason: &str,
        wait: u64,
    ) -> Result<Value, String> {
        self.send(
            reqwest::Method::POST,
            "/v1/requests",
            Some(json!({"profile": profile, "params": params, "reason": reason, "wait_sec": wait})),
        )
        .await
    }
    pub async fn call(&self, call: Value, reason: &str, wait: u64) -> Result<Value, String> {
        self.send(
            reqwest::Method::POST,
            "/v1/requests",
            Some(json!({"call": call, "reason": reason, "wait_sec": wait})),
        )
        .await
    }
    pub async fn request(&self, id: &str) -> Result<Value, String> {
        self.send(reqwest::Method::GET, &format!("/v1/requests/{id}"), None)
            .await
    }

    /// Checks that an agent is set up, without ever printing the token.
    pub async fn doctor(&self) -> Vec<Check> {
        let mut out = vec![Check {
            name: "token",
            ok: !self.token.is_empty(),
            detail: if self.token.is_empty() {
                "missing".into()
            } else {
                "token found".into()
            },
        }];
        match self.http.get(format!("{}/healthz", self.url)).send().await {
            Ok(r) if r.status().is_success() => out.push(Check {
                name: "healthz",
                ok: true,
                detail: "200 OK".into(),
            }),
            Ok(r) => out.push(Check {
                name: "healthz",
                ok: false,
                detail: format!("HTTP {}", r.status().as_u16()),
            }),
            Err(e) => out.push(Check {
                name: "healthz",
                ok: false,
                detail: e.without_url().to_string(),
            }),
        }
        match self.profiles().await {
            Ok(Value::Array(a)) => out.push(Check {
                name: "profiles",
                ok: true,
                detail: format!("{} profiles", a.len()),
            }),
            Ok(_) => out.push(Check {
                name: "profiles",
                ok: true,
                detail: "ok".into(),
            }),
            Err(e) if e.contains("HTTP 423") => out.push(Check {
                name: "profiles",
                ok: false,
                detail: "vault locked, sign in on the web".into(),
            }),
            Err(e) if e.contains("HTTP 403") => out.push(Check {
                name: "profiles",
                ok: false,
                detail: "token rejected".into(),
            }),
            Err(e) => out.push(Check {
                name: "profiles",
                ok: false,
                detail: e,
            }),
        }
        out
    }
}
