//! Running an approved action. Secrets are resolved here, after approval, and
//! every private value is redacted from the result.

use super::{Action, ExecSpec, HttpSpec, expand, gourl};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use zeroize::Zeroize;

const MAX_READ: usize = 1 << 20;
const MAX_OUTPUT: usize = 64 << 10;

/// Outcome of running an action (Go's `policy.Result`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunResult {
    pub ok: bool,
    pub exit: i32,
    pub output: String,
}

fn fail(msg: impl Into<String>) -> RunResult {
    RunResult {
        ok: false,
        exit: -1,
        output: msg.into(),
    }
}

/// Removes secret values and common encodings of them.
pub fn redact<T: AsRef<[u8]>>(s: &str, secrets: &[T]) -> String {
    let mut forms: Vec<String> = vec![];
    for v in secrets {
        let v = v.as_ref();
        if v.len() < 4 {
            continue;
        }
        let t = String::from_utf8_lossy(v).into_owned();
        forms.extend([
            t.clone(),
            t.trim().to_string(),
            STANDARD.encode(v),
            STANDARD_NO_PAD.encode(v),
            URL_SAFE.encode(v),
            URL_SAFE_NO_PAD.encode(v),
            hex::encode(v),
            hex::encode_upper(v),
            gourl::query_escape(&t),
            gourl::path_escape(&t),
            gourl::json_escape(&t),
        ]);
    }
    forms.sort_by_key(|f| std::cmp::Reverse(f.len()));
    let mut s = s.to_string();
    for f in forms.iter().filter(|f| !f.is_empty()) {
        s = s.replace(f.as_str(), "[REDACTED]");
    }
    s
}

fn clip(s: String) -> String {
    if s.len() <= MAX_OUTPUT {
        return s;
    }
    let mut n = MAX_OUTPUT;
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    format!("{}\n[output truncated]", &s[..n])
}

/// Runs the action. `get_secret` receives each reference as written
/// (`db.password`) and returns its value.
pub async fn run<F>(a: &Action, get_secret: F) -> RunResult
where
    F: Fn(&str) -> Result<Vec<u8>, String>,
{
    run_with(a, get_secret, &BTreeSet::new()).await
}

/// Like `run`, but values of the references in `public` are not redacted from
/// the output (agents may see public fields).
pub async fn run_with<F>(a: &Action, get_secret: F, public: &BTreeSet<String>) -> RunResult
where
    F: Fn(&str) -> Result<Vec<u8>, String>,
{
    let mut values: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for n in a.secrets() {
        match get_secret(&n) {
            Ok(v) => {
                values.insert(n, v);
            }
            Err(_) => return fail(format!("secret {} unavailable", gourl::quote(&n))),
        }
    }
    let get = |n: &str| {
        values
            .get(n)
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default()
    };
    let timeout = Duration::from_secs(if a.timeout_sec > 0 {
        a.timeout_sec as u64
    } else {
        30
    });
    let mut r = if let Some(h) = &a.http {
        run_http(h, &get, timeout).await
    } else if let Some(e) = &a.exec {
        run_exec(e, &get, timeout).await
    } else {
        fail("nothing to run")
    };
    let list: Vec<&Vec<u8>> = values
        .iter()
        .filter(|(n, _)| !public.contains(*n))
        .map(|(_, v)| v)
        .collect();
    r.output = clip(redact(&r.output, &list));
    values.values_mut().for_each(|v| v.zeroize());
    r
}

fn client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    // A redirect could carry the Authorization header somewhere unapproved.
    C.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("http client")
    })
}

// The getter is Sync so the run future can move between threads.
async fn run_http(
    h: &HttpSpec,
    get: &(dyn Fn(&str) -> String + Sync),
    timeout: Duration,
) -> RunResult {
    let Ok(method) = reqwest::Method::from_bytes(h.method.as_bytes()) else {
        return fail("bad request");
    };
    let mut req = client()
        .request(method, expand(&h.url, get))
        .timeout(timeout);
    for (k, v) in &h.headers {
        let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_bytes()),
            reqwest::header::HeaderValue::from_str(&expand(v, get)),
        ) else {
            return fail("bad request");
        };
        req = req.header(name, val);
    }
    if !h.body.is_empty() {
        req = req.body(expand(&h.body, get));
    }
    let fut = async {
        let mut resp = match req.send().await {
            Ok(r) => r,
            Err(e) => return fail(error_text(e)),
        };
        let code = resp.status().as_u16();
        let mut body: Vec<u8> = vec![];
        while body.len() < MAX_READ {
            match resp.chunk().await {
                Ok(Some(c)) => {
                    let room = MAX_READ - body.len();
                    body.extend_from_slice(&c[..c.len().min(room)]);
                }
                _ => break,
            }
        }
        RunResult {
            ok: (200..300).contains(&code),
            exit: i32::from(code),
            output: format!("HTTP {code}\n{}", String::from_utf8_lossy(&body)),
        }
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(r) => r,
        Err(_) => fail("context deadline exceeded"),
    }
}

/// The error chain without the URL, which may hold expanded public fields.
fn error_text(e: reqwest::Error) -> String {
    use std::error::Error as _;
    let e = e.without_url();
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(x) = src {
        s.push_str(": ");
        s.push_str(&x.to_string());
        src = x.source();
    }
    s
}

fn make_home() -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    loop {
        let p = std::env::temp_dir().join(format!("ucr-run-{:016x}", rand::random::<u64>()));
        match std::fs::DirBuilder::new().mode(0o700).create(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

async fn run_exec(
    e: &ExecSpec,
    get: &(dyn Fn(&str) -> String + Sync),
    timeout: Duration,
) -> RunResult {
    // A private HOME stops one run from planting config for the next.
    let Ok(home) = make_home() else {
        return fail("could not prepare a working directory");
    };
    let r = exec_in(e, get, timeout, &home).await;
    let _ = std::fs::remove_dir_all(&home);
    r
}

async fn exec_in(
    e: &ExecSpec,
    get: &(dyn Fn(&str) -> String + Sync),
    timeout: Duration,
    home: &std::path::Path,
) -> RunResult {
    use std::os::unix::fs::OpenOptionsExt;
    let Some(prog) = e.argv.first() else {
        return fail("could not start: empty command");
    };
    for (name, v) in &e.files {
        let mut data = expand(v, get);
        if !data.ends_with('\n') {
            data.push('\n'); // OpenSSH refuses a key without a final newline
        }
        let w = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(home.join(name))
            .and_then(|mut f| std::io::Write::write_all(&mut f, data.as_bytes()));
        if w.is_err() {
            return fail("could not write a temporary file");
        }
    }
    let mut cmd = Command::new(prog);
    cmd.args(&e.argv[1..])
        .current_dir(home)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", home)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    for (k, v) in &e.env {
        cmd.env(k, expand(v, get));
    }
    let stdin = if e.stdin.is_empty() {
        None
    } else {
        Some(format!("{}\n", expand(&e.stdin, get)))
    };
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(err) => return fail(format!("could not start: {err}")),
    };
    if let (Some(data), Some(mut si)) = (stdin, child.stdin.take()) {
        tokio::spawn(async move {
            let _ = si.write_all(data.as_bytes()).await;
        });
    }
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let mut readers = vec![];
    if let Some(o) = child.stdout.take() {
        readers.push(tokio::spawn(pump(o, buf.clone())));
    }
    if let Some(o) = child.stderr.take() {
        readers.push(tokio::spawn(pump(o, buf.clone())));
    }
    let pid = child.id();
    let mut timed_out = false;
    let status = tokio::select! {
        s = child.wait() => s,
        _ = tokio::time::sleep(timeout) => {
            timed_out = true;
            if let Some(pid) = pid {
                // SAFETY: plain kill(2) on the child's own process group.
                unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
            }
            let _ = child.start_kill();
            child.wait().await
        }
    };
    // Like Go's WaitDelay: do not wait forever for a holder of the pipes.
    for r in readers {
        let _ = tokio::time::timeout(Duration::from_secs(2), r).await;
    }
    let out = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
    let mut r = RunResult {
        ok: matches!(&status, Ok(s) if s.success()),
        exit: status.ok().and_then(|s| s.code()).unwrap_or(-1),
        output: out,
    };
    if timed_out {
        r.output.push_str("\n[timed out]");
        r.ok = false;
    }
    r
}

async fn pump<R: tokio::io::AsyncRead + Unpin>(mut r: R, buf: Arc<Mutex<Vec<u8>>>) {
    let mut chunk = [0u8; 8192];
    while let Ok(n) = r.read(&mut chunk).await {
        if n == 0 {
            break;
        }
        let mut b = buf.lock().unwrap();
        let room = MAX_READ.saturating_sub(b.len());
        b.extend_from_slice(&chunk[..n.min(room)]);
    }
}
