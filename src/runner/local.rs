//! The runner side: `ucr runner enroll`, `serve` and `status`.
//!
//! A runner keeps its keys in `runner.json` and the owner's rules in
//! `runner.toml`, next to each other in the user's config directory. It only
//! ever connects out to the server, asks for work, checks each job against
//! the pinned server key and its own rules, runs it, and signs the result.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use age::secrecy::ExposeSecret;
use age::x25519;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::proto::{
    self, EnrollIn, EnrollOut, Info, Job, JobResult, PollIn, PollOut, Signed, VERSION,
};
use crate::policy::{self, Action, ExecSpec, Profile, RISK_HIGH};

/// What `enroll` saves. Readable by the runner's user only.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub name: String,
    pub server: String,
    pub token: String,
    pub server_key: String,
    pub sign_seed: String,
    pub age_identity: String,
}

impl Config {
    fn signing_key(&self) -> Result<SigningKey, String> {
        let raw = Zeroizing::new(B64.decode(&self.sign_seed).map_err(|_| "bad runner.json")?);
        let seed: [u8; 32] = raw.as_slice().try_into().map_err(|_| "bad runner.json")?;
        Ok(SigningKey::from_bytes(&seed))
    }

    fn identity(&self) -> Result<x25519::Identity, String> {
        x25519::Identity::from_str(&self.age_identity).map_err(|_| "bad runner.json".to_string())
    }
}

/// The owner's rules for this machine, in `runner.toml`. A job outside them
/// is refused even when the server signed it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    /// Programs that may start, as absolute paths. `"*"` allows any.
    pub allow: Vec<String>,
    /// Lets approved jobs run those programs through sudo, with the
    /// password the job carries.
    pub sudo: bool,
    /// Refuses jobs that were approved without a TOTP code.
    pub require_totp: bool,
}

impl Default for Rules {
    fn default() -> Rules {
        Rules {
            allow: vec![],
            sudo: false,
            require_totp: true,
        }
    }
}

const RULES_TEMPLATE: &str = r#"# ucanrun runner rules. The runner reads this file before every job, so
# changes apply at once. A job outside these rules is refused, even when the
# server approved and signed it.

# Programs this runner may start, as absolute paths. Empty: nothing runs.
# "*" allows any program, which leaves the decision to the approver alone.
allow = []

# Let approved jobs run the programs above through sudo, with the password
# the job carries (a secret in ucanrun). The runner's own user needs sudo
# rights for them.
sudo = false

# Refuse jobs that were approved without a TOTP code.
require_totp = true
"#;

const WINDOWS_RULES_EXAMPLE: &str = r#"
# Example for Windows:
# allow = ['C:\Windows\System32\ipconfig.exe', 'C:\Program Files\Git\cmd\git.exe']
"#;

/// The directory with runner.json and runner.toml.
pub fn dir() -> PathBuf {
    if let Ok(d) = std::env::var("UCANRUN_RUNNER_DIR")
        && !d.is_empty()
    {
        return PathBuf::from(d);
    }
    #[cfg(windows)]
    {
        PathBuf::from(std::env::var("APPDATA").unwrap_or_default()).join("ucanrun")
    }
    #[cfg(not(windows))]
    {
        match std::env::var("XDG_CONFIG_HOME") {
            Ok(d) if !d.is_empty() => PathBuf::from(d).join("ucanrun"),
            _ => PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config/ucanrun"),
        }
    }
}

fn private_write(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(&tmp).map_err(|e| e.to_string())?;
    std::io::Write::write_all(&mut f, data).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

fn make_dir() -> Result<PathBuf, String> {
    let d = dir();
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(&d).map_err(|e| e.to_string())?;
    Ok(d)
}

pub fn load_config() -> Result<Config, String> {
    let p = dir().join("runner.json");
    let raw = std::fs::read(&p).map_err(|_| {
        format!(
            "this machine is not enrolled ({} is missing): run ucr runner enroll URL CODE",
            p.display()
        )
    })?;
    serde_json::from_slice(&raw).map_err(|_| format!("{} is not valid", p.display()))
}

pub fn load_rules() -> Result<Rules, String> {
    let p = dir().join("runner.toml");
    let s = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    toml::from_str(&s).map_err(|e| format!("{}: {e}", p.display()))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[cfg(unix)]
fn uid() -> i64 {
    // SAFETY: getuid has no preconditions and cannot fail.
    i64::from(unsafe { libc::getuid() })
}

#[cfg(not(unix))]
fn uid() -> i64 {
    -1
}

/// Whether this process holds administrator rights: an elevated token on
/// Windows, uid 0 elsewhere.
#[cfg(windows)]
fn elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    // SAFETY: the token handle is opened for this process only, read into a
    // struct of the size passed, and closed.
    unsafe {
        let mut h: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h) == 0 {
            return false;
        }
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(
            h,
            TokenElevation,
            (&mut e as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(h);
        ok != 0 && e.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
fn elevated() -> bool {
    uid() == 0
}

fn user_name() -> String {
    for k in ["USER", "USERNAME", "LOGNAME"] {
        if let Ok(v) = std::env::var(k)
            && !v.is_empty()
        {
            return v;
        }
    }
    String::new()
}

/// What this runner reports about itself, from its rules as they are now.
pub fn info() -> Info {
    let (rules, policy_error) = match load_rules() {
        Ok(r) => (r, String::new()),
        Err(e) => (Rules::default(), e),
    };
    Info {
        version: env!("CARGO_PKG_VERSION").into(),
        host: crate::client::host_name(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        user: user_name(),
        uid: uid(),
        root: elevated(),
        sudo: rules.sudo && cfg!(unix),
        require_totp: rules.require_totp,
        allow: rules.allow,
        policy_error,
    }
}

/// Lower case and only [a-z0-9_-], for a default runner name.
fn default_name() -> String {
    let n: String = crate::client::host_name()
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    let n = n.trim_matches('-').to_string();
    if n.is_empty() { "runner".into() } else { n }
}

/// `ucr runner enroll URL CODE [--name NAME] [--force]`
pub async fn enroll(args: &[String]) -> Result<(), String> {
    let mut pos = vec![];
    let (mut name, mut force) = (String::new(), false);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" if i + 1 < args.len() => {
                name = args[i + 1].clone();
                i += 1;
            }
            "--force" => force = true,
            a => pos.push(a.to_string()),
        }
        i += 1;
    }
    if pos.len() != 2 {
        return Err("usage: ucr runner enroll URL CODE [--name NAME] [--force]".into());
    }
    let server = pos[0].trim_end_matches('/').to_string();
    if !(server.starts_with("http://") || server.starts_with("https://")) {
        return Err("the URL must start with http:// or https://".into());
    }
    if name.is_empty() {
        name = default_name();
    }
    let d = make_dir()?;
    if d.join("runner.json").exists() && !force {
        return Err(format!(
            "this machine is already enrolled as a runner ({}); add --force to replace it",
            d.join("runner.json").display()
        ));
    }
    let sign = SigningKey::generate(&mut rand::rngs::OsRng);
    let id = x25519::Identity::generate();
    let body = EnrollIn {
        code: pos[1].clone(),
        name: name.clone(),
        sign_key: proto::public_b64(&sign),
        age_key: id.to_public().to_string(),
        info: info(),
    };
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = http
        .post(format!("{server}/v1/runner/enroll"))
        .json(&body)
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    let status = resp.status();
    let v: serde_json::Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        let msg = v.get("error").and_then(|x| x.as_str()).unwrap_or("");
        return Err(format!("enroll failed: {msg} (HTTP {})", status.as_u16()));
    }
    let out: EnrollOut = serde_json::from_value(v).map_err(|_| "bad answer from the server")?;
    proto::verifying_key(&out.server_key)?;
    let cfg = Config {
        name: out.name.clone(),
        server,
        token: out.token,
        server_key: out.server_key.clone(),
        sign_seed: B64.encode(sign.to_bytes()),
        age_identity: id.to_string().expose_secret().to_string(),
    };
    let json = Zeroizing::new(serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?);
    private_write(&d.join("runner.json"), &json)?;
    let rules = d.join("runner.toml");
    if !rules.exists() {
        let mut t = RULES_TEMPLATE.to_string();
        if cfg!(windows) {
            t.push_str(WINDOWS_RULES_EXAMPLE);
        }
        private_write(&rules, t.as_bytes())?;
    }
    println!("Enrolled as runner \"{}\".", out.name);
    println!("Server key:  {}", proto::fingerprint(&out.server_key));
    println!(
        "Runner key:  {}",
        proto::fingerprint(&proto::public_b64(&sign))
    );
    println!("Compare both with the Devices card in the ucanrun web UI.");
    println!(
        "Rules:       {} (nothing runs until you list programs there)",
        rules.display()
    );
    println!("Start it:    ucr runner serve");
    Ok(())
}

/// `ucr runner status`
pub fn status() -> Result<(), String> {
    let cfg = load_config()?;
    let sign = cfg.signing_key()?;
    println!("Runner:      {}", cfg.name);
    println!("Server:      {}", cfg.server);
    println!("Server key:  {}", proto::fingerprint(&cfg.server_key));
    println!(
        "Runner key:  {}",
        proto::fingerprint(&proto::public_b64(&sign))
    );
    let i = info();
    println!("User:        {} (uid {})", i.user, i.uid);
    if !i.policy_error.is_empty() {
        println!("Rules:       ERROR {}: nothing will run", i.policy_error);
        return Err("fix runner.toml".into());
    }
    let allow = if i.allow.is_empty() {
        "nothing".to_string()
    } else {
        i.allow.join(", ")
    };
    println!("Allows:      {allow}");
    println!("sudo:        {}", if i.sudo { "yes" } else { "no" });
    println!("TOTP needed: {}", if i.require_totp { "yes" } else { "no" });
    if i.root {
        println!(
            "WARNING: this runner has administrator rights. Run it as its own user (on Windows, not elevated)."
        );
    }
    Ok(())
}

/// `ucr runner forget`: removes the keys. The server still lists the runner
/// until it is removed there.
pub fn forget() -> Result<(), String> {
    let p = dir().join("runner.json");
    match std::fs::remove_file(&p) {
        Ok(()) => {
            println!(
                "Removed {}. Remove the runner in the web UI too.",
                p.display()
            );
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("Not enrolled.");
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Checks a job against this runner's identity and rules. Returns why it is
/// refused, or nothing.
pub fn check(
    job: &Job,
    name: &str,
    rules: &Rules,
    seen: &mut HashMap<String, i64>,
) -> Result<(), String> {
    if job.v != VERSION {
        return Err(format!("job version {} is not supported", job.v));
    }
    if job.runner != name {
        return Err(format!("the job is for runner \"{}\"", job.runner));
    }
    let now = now_unix();
    if now > job.not_after {
        return Err("the job has expired".into());
    }
    seen.retain(|_, till| *till >= now);
    if job.job.len() < 16 || seen.contains_key(&job.job) {
        return Err("the job was already received".into());
    }
    seen.insert(job.job.clone(), job.not_after);
    if rules.require_totp && !job.totp {
        return Err("this runner only takes jobs approved with TOTP".into());
    }
    let e = &job.exec;
    let a0 = e.argv.first().map(String::as_str).unwrap_or("");
    let abs = if cfg!(windows) {
        policy::windows_abs(a0)
    } else {
        a0.starts_with('/')
    };
    if !abs {
        return Err(format!("{a0:?} is not an absolute path on this machine"));
    }
    let listed = rules.allow.iter().any(|p| {
        p == "*"
            || if cfg!(windows) {
                p.eq_ignore_ascii_case(a0)
            } else {
                p == a0
            }
    });
    if !listed {
        return Err(format!("{a0} is not in the allow list of runner.toml"));
    }
    if !e.sudo.is_empty() {
        if cfg!(windows) {
            return Err("sudo is not available on Windows".into());
        }
        if !rules.sudo {
            return Err("sudo is off in runner.toml".into());
        }
    }
    // The same rules the server applies, checked again here, so a server
    // that was taken over still cannot hand over a shell.
    let p = Profile {
        name: "runner-job".into(),
        risk: RISK_HIGH.into(),
        runner: name.into(),
        exec: Some(e.clone()),
        timeout_sec: job.timeout_sec.clamp(0, 600),
        ..Default::default()
    };
    let public: BTreeSet<&str> = job.public.iter().map(String::as_str).collect();
    p.validate_with(&|r: &str| public.contains(r))
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(unix)]
fn sudo_path() -> Option<&'static str> {
    ["/usr/bin/sudo", "/bin/sudo", "/usr/local/bin/sudo"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
}

#[cfg(not(unix))]
fn sudo_path() -> Option<&'static str> {
    None
}

/// The command as it really starts: through `sudo -S` when the job asks.
fn command_of(e: &ExecSpec) -> Result<ExecSpec, String> {
    let mut x = e.clone();
    if e.sudo.is_empty() {
        return Ok(x);
    }
    let sudo = sudo_path().ok_or("sudo is not installed")?;
    // -k ignores cached credentials, so each job needs the password it
    // carries; -p "" keeps the prompt out of the output.
    let mut argv: Vec<String> = [sudo, "-S", "-k", "-p", "", "--"]
        .map(String::from)
        .to_vec();
    argv.extend(e.argv.iter().cloned());
    x.argv = argv;
    x.stdin = if e.stdin.is_empty() {
        e.sudo.clone()
    } else {
        format!("{}\n{}", e.sudo, e.stdin)
    };
    x.sudo.clear();
    Ok(x)
}

async fn run_job(job: &Job, id: &x25519::Identity) -> policy::RunResult {
    let values = match proto::unseal(id, &job.secrets) {
        Ok(v) => v,
        Err(e) => {
            return policy::RunResult {
                ok: false,
                exit: -1,
                output: e,
            };
        }
    };
    let exec = match command_of(&job.exec) {
        Ok(x) => x,
        Err(e) => {
            return policy::RunResult {
                ok: false,
                exit: -1,
                output: e,
            };
        }
    };
    let action = Action {
        exec: Some(exec),
        timeout_sec: if job.timeout_sec > 0 {
            job.timeout_sec.min(600)
        } else {
            30
        },
        ..Default::default()
    };
    let public: BTreeSet<String> = job.public.iter().cloned().collect();
    let get = |n: &str| {
        values
            .get(n)
            .map(|v| v.to_vec())
            .ok_or_else(|| format!("secret {n} missing"))
    };
    policy::run_with(&action, get, &public).await
}

/// One line per job in `runner.log`, each holding the hash of the line
/// before it, so a removed or edited line shows.
struct Log {
    path: PathBuf,
    last: Mutex<String>,
}

impl Log {
    fn open() -> Log {
        let path = dir().join("runner.log");
        let last = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| {
                s.lines()
                    .last()
                    .map(|l| hex::encode(Sha256::digest(l.as_bytes())))
            })
            .unwrap_or_default();
        Log {
            path,
            last: Mutex::new(last),
        }
    }

    fn write(&self, v: serde_json::Value) {
        let mut last = self.last.lock().unwrap();
        let mut v = v;
        let t = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        v["time"] = serde_json::json!(t);
        v["prev"] = serde_json::json!(*last);
        let line = v.to_string();
        let mut o = std::fs::OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        if let Ok(mut f) = o.open(&self.path) {
            let _ = std::io::Write::write_all(&mut f, format!("{line}\n").as_bytes());
        }
        *last = hex::encode(Sha256::digest(line.as_bytes()));
    }
}

struct Ctx {
    cfg: Config,
    sign: SigningKey,
    id: x25519::Identity,
    server_key: ed25519_dalek::VerifyingKey,
    http: reqwest::Client,
    seen: Mutex<HashMap<String, i64>>,
    log: Log,
}

async fn handle(ctx: Arc<Ctx>, env: Signed) {
    let job: Job = match env.open(&ctx.server_key) {
        Ok(j) => j,
        Err(e) => {
            // Without a valid signature nothing in it can be trusted, not
            // even the id to answer to.
            eprintln!("runner: ignored a job: {e}");
            ctx.log
                .write(serde_json::json!({"event": "bad_signature", "error": e}));
            return;
        }
    };
    let verdict = load_rules().and_then(|r| {
        let mut seen = ctx.seen.lock().unwrap();
        check(&job, &ctx.cfg.name, &r, &mut seen)
    });
    let started = std::time::Instant::now();
    let (res, refused) = match verdict {
        Err(why) => (
            policy::RunResult {
                ok: false,
                exit: -1,
                output: format!("runner {} refused: {why}", ctx.cfg.name),
            },
            true,
        ),
        Ok(()) => (run_job(&job, &ctx.id).await, false),
    };
    ctx.log.write(serde_json::json!({
        "event": if refused { "refused" } else { "ran" },
        "id": job.id, "job": job.job, "hash": job.hash, "approved_by": job.approved_by,
        "argv0": job.exec.argv.first(), "sudo": !job.exec.sudo.is_empty(),
        "ok": res.ok, "exit": res.exit, "ms": started.elapsed().as_millis() as u64,
        "why": if refused { res.output.clone() } else { String::new() },
    }));
    let out = JobResult {
        v: VERSION,
        job: job.job.clone(),
        id: job.id.clone(),
        runner: ctx.cfg.name.clone(),
        ok: res.ok,
        exit: res.exit,
        output: res.output,
        refused,
    };
    let signed = Signed::new(&ctx.sign, &out);
    for attempt in 0..4u64 {
        let r = ctx
            .http
            .post(format!("{}/v1/runner/result", ctx.cfg.server))
            .bearer_auth(&ctx.cfg.token)
            .json(&signed)
            .send()
            .await;
        match r {
            Ok(r) if r.status().is_success() => return,
            // The server no longer waits for it; retrying will not help.
            Ok(r) if r.status().as_u16() == 404 || r.status().as_u16() == 410 => return,
            _ => tokio::time::sleep(Duration::from_secs(2 << attempt)).await,
        }
    }
    eprintln!("runner: could not deliver the result of {}", job.id);
}

/// `ucr runner serve`: asks the server for work until stopped.
pub async fn serve() -> Result<(), String> {
    let cfg = load_config()?;
    let sign = cfg.signing_key()?;
    let id = cfg.identity()?;
    let server_key = proto::verifying_key(&cfg.server_key)?;
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(proto::POLL_WAIT_SECS + 20))
        .build()
        .map_err(|e| e.to_string())?;
    let first = info();
    if !first.policy_error.is_empty() {
        eprintln!(
            "runner: {}; nothing will run until it is fixed",
            first.policy_error
        );
    }
    if first.root {
        eprintln!(
            "runner: WARNING: running with administrator rights. Run it as its own user (on Windows, not elevated)."
        );
    }
    eprintln!(
        "runner \"{}\" asking {} for work (server key {})",
        cfg.name,
        cfg.server,
        proto::fingerprint(&cfg.server_key)
    );
    let ctx = Arc::new(Ctx {
        cfg,
        sign,
        id,
        server_key,
        http,
        seen: Mutex::new(HashMap::new()),
        log: Log::open(),
    });
    let mut backoff = 2u64;
    let mut said_locked = false;
    loop {
        let r = ctx
            .http
            .post(format!("{}/v1/runner/poll", ctx.cfg.server))
            .bearer_auth(&ctx.cfg.token)
            .json(&PollIn { info: info() })
            .send()
            .await;
        match r {
            Ok(r) if r.status().is_success() => {
                backoff = 2;
                said_locked = false;
                let out: PollOut = r.json().await.unwrap_or_default();
                for env in out.jobs {
                    tokio::spawn(handle(ctx.clone(), env));
                }
            }
            Ok(r) if matches!(r.status().as_u16(), 401 | 403) => {
                return Err("the server rejected this runner: it was removed. Enroll again with a new code.".into());
            }
            Ok(r) if r.status().as_u16() == 423 => {
                if !said_locked {
                    eprintln!("runner: the vault is locked; waiting until someone signs in");
                    said_locked = true;
                }
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
            Ok(r) => {
                eprintln!("runner: server answered HTTP {}", r.status().as_u16());
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
            }
            Err(e) => {
                eprintln!("runner: {}", e.without_url());
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
            }
        }
    }
}

/// Values the command needs, for tests.
#[cfg(test)]
pub(crate) fn values(m: &[(&str, &str)]) -> std::collections::BTreeMap<String, Zeroizing<Vec<u8>>> {
    m.iter()
        .map(|(k, v)| (k.to_string(), Zeroizing::new(v.as_bytes().to_vec())))
        .collect()
}

#[cfg(test)]
mod unit {
    use super::*;

    fn job(argv: &[&str]) -> Job {
        Job {
            v: VERSION,
            id: "r1".into(),
            job: format!("{:032x}", rand::random::<u128>()),
            runner: "box".into(),
            not_after: now_unix() + 60,
            totp: true,
            exec: ExecSpec {
                argv: argv.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn rules(allow: &[&str]) -> Rules {
        Rules {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            sudo: true,
            require_totp: true,
        }
    }

    #[test]
    #[cfg(unix)]
    fn checks_identity_time_replay_and_rules() {
        let mut seen = HashMap::new();
        let r = rules(&["/usr/bin/id"]);
        assert!(check(&job(&["/usr/bin/id"]), "box", &r, &mut seen).is_ok());
        // The same job again.
        let once = job(&["/usr/bin/id"]);
        assert!(check(&once, "box", &r, &mut seen).is_ok());
        let e = check(&once, "box", &r, &mut seen).unwrap_err();
        assert!(e.contains("already"), "{e}");
        let mut seen = HashMap::new();
        assert!(check(&job(&["/usr/bin/id"]), "other", &r, &mut seen).is_err());
        let mut old = job(&["/usr/bin/id"]);
        old.not_after = now_unix() - 1;
        assert!(
            check(&old, "box", &r, &mut seen)
                .unwrap_err()
                .contains("expired")
        );
        let e = check(&job(&["/usr/bin/rm", "-rf", "/"]), "box", &r, &mut seen).unwrap_err();
        assert!(e.contains("allow list"), "{e}");
        // Even with "*", the shared rules still stop a shell.
        let e = check(
            &job(&["/bin/sh", "-c", "id"]),
            "box",
            &rules(&["*"]),
            &mut seen,
        )
        .unwrap_err();
        assert!(e.contains("interpreters"), "{e}");
        let mut no_totp = job(&["/usr/bin/id"]);
        no_totp.job = "fedcba9876543210fedc".into();
        no_totp.totp = false;
        assert!(
            check(&no_totp, "box", &r, &mut seen)
                .unwrap_err()
                .contains("TOTP")
        );
        let mut s = job(&["/usr/bin/id"]);
        s.job = "aaaabbbbccccddddeeee".into();
        s.exec.sudo = "{{secret:pw}}".into();
        let mut off = r.clone();
        off.sudo = false;
        assert!(
            check(&s, "box", &off, &mut seen)
                .unwrap_err()
                .contains("sudo is off")
        );
    }

    #[test]
    #[cfg(unix)]
    fn sudo_wraps_the_command_and_feeds_the_password_first() {
        let e = ExecSpec {
            argv: vec!["/usr/bin/id".into(), "-u".into()],
            stdin: "{{secret:data}}".into(),
            sudo: "{{secret:pw}}".into(),
            ..Default::default()
        };
        if sudo_path().is_none() {
            return;
        }
        let x = command_of(&e).unwrap();
        assert_eq!(&x.argv[1..6], &["-S", "-k", "-p", "", "--"]);
        assert_eq!(&x.argv[6..], &["/usr/bin/id", "-u"]);
        assert_eq!(x.stdin, "{{secret:pw}}\n{{secret:data}}");
        assert!(x.sudo.is_empty());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn runs_with_sealed_secrets_and_redacts() {
        let id = x25519::Identity::generate();
        let sealed = proto::seal(
            &id.to_public().to_string(),
            &values(&[("k", "s3cr3t-value")]),
        )
        .unwrap();
        let cat = ["/bin/cat", "/usr/bin/cat"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
            .unwrap();
        let mut j = job(&[cat]);
        j.exec.stdin = "{{secret:k}}".into();
        j.secrets = sealed;
        let r = run_job(&j, &id).await;
        assert!(r.ok, "{r:?}");
        assert!(!r.output.contains("s3cr3t-value"), "{}", r.output);
        assert!(r.output.contains("[REDACTED]"));
    }

    #[test]
    fn rules_template_parses_to_safe_defaults() {
        let r: Rules = toml::from_str(RULES_TEMPLATE).unwrap();
        assert_eq!(r, Rules::default());
        let w: Rules = toml::from_str(&format!("{RULES_TEMPLATE}{WINDOWS_RULES_EXAMPLE}")).unwrap();
        assert!(w.allow.is_empty());
        assert!(
            toml::from_str::<Rules>("alow = []").is_err(),
            "typos must not pass silently"
        );
    }
}
