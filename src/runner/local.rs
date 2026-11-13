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
    self, EnrollIn, EnrollOut, Info, Job, JobBody, JobResult, MAX_JOB_LIFE_SECS, PollIn, PollOut,
    ResultBody, Signed, VERSION,
};
use crate::policy::{self, Action, ExecSpec, Profile, RISK_HIGH};

/// What `enroll` saves. Readable by the runner's user only.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Protocol version this machine was enrolled with.
    pub v: u32,
    pub name: String,
    pub server: String,
    pub server_key: String,
    /// age recipient results are sealed to.
    pub server_age: String,
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
    /// Runs only jobs approved with one of the passkeys pinned in
    /// `passkeys.json`, checked here, so a server taken over cannot order
    /// anything on its own.
    pub require_passkey: bool,
}

impl Default for Rules {
    fn default() -> Rules {
        Rules {
            allow: vec![],
            sudo: false,
            require_totp: true,
            require_passkey: false,
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

# Run only jobs approved with one of your passkeys, checked on this machine
# against the passkeys pinned in passkeys.json. Even a server taken over
# cannot order a job then. Pin or refresh them with: ucr runner trust-passkeys
require_passkey = false
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
    let c: Config =
        serde_json::from_slice(&raw).map_err(|_| format!("{} is not valid", p.display()))?;
    if c.v < VERSION || c.server_age.is_empty() {
        return Err(
            "this machine was enrolled by an older ucr; create a new code in the web UI and run ucr runner enroll URL CODE --force"
                .into(),
        );
    }
    Ok(c)
}

pub fn load_rules() -> Result<Rules, String> {
    let p = dir().join("runner.toml");
    let s = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    toml::from_str(&s).map_err(|e| format!("{}: {e}", p.display()))
}

/// The passkeys this runner trusts, from `passkeys.json`.
pub fn load_pins() -> Option<proto::PinnedPasskeys> {
    let b = std::fs::read(dir().join("passkeys.json")).ok()?;
    serde_json::from_slice(&b).ok()
}

fn save_pins(p: &proto::PinnedPasskeys) -> Result<(), String> {
    let b = serde_json::to_vec_pretty(p).map_err(|e| e.to_string())?;
    private_write(&dir().join("passkeys.json"), &b)
}

/// Checks the passkey answer that came with a job against the pinned
/// passkeys and the job itself. Returns the pins with the used passkey's
/// counter moved on.
pub fn check_passkey(
    body: &JobBody,
    pins: Option<&proto::PinnedPasskeys>,
) -> Result<proto::PinnedPasskeys, String> {
    let Some(pins) = pins.filter(|p| !p.keys.is_empty()) else {
        return Err("no passkey is pinned on this runner; run ucr runner trust-passkeys".into());
    };
    let Some(a) = &body.approval else {
        return Err("this runner only takes jobs approved with a passkey".into());
    };
    // Recompute what was approved from what arrived: a server that changed
    // the command cannot keep the signature valid.
    let action = Action {
        exec: Some(body.exec.clone()),
        timeout_sec: body.timeout_sec,
        runner: body.runner.clone(),
        ..Default::default()
    };
    let ch = proto::approval_challenge(&proto::action_digest(&action), &body.hash, &a.nonce);
    let rp = crate::webauthn::Rp {
        id: pins.rp_id.clone(),
        origin: pins.origin.clone(),
    };
    let (i, count) = crate::webauthn::finish_assert(&rp, &ch, &a.credential, &pins.keys)
        .map_err(|e| format!("passkey approval rejected: {e}"))?;
    let mut out = pins.clone();
    out.keys[i].sign_count = count;
    Ok(out)
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
        require_passkey: rules.require_passkey,
        passkeys: load_pins().map_or(0, |p| p.keys.len()),
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
///
/// The code never leaves this machine: the request carries an HMAC made
/// with it, and the server answers with one over its own keys, which is
/// checked before anything is saved.
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
    let code = proto::normalize_code(&pos[1]);
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
    let mut body = EnrollIn {
        v: VERSION,
        name: name.clone(),
        sign_key: proto::public_b64(&sign),
        age_key: id.to_public().to_string(),
        // The rules follow sealed, with the first poll; the server's key is
        // not known yet.
        info: Info {
            version: env!("CARGO_PKG_VERSION").into(),
            ..Default::default()
        },
        ..Default::default()
    };
    body.proof = body.proof_for(&code);
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
    // Only the server that showed this code can make this proof, so a
    // machine in the middle cannot slip in its own keys.
    if out.name != name || !out.proves(&code, &body.sign_key) {
        return Err("the server could not prove it knows the code: not saved. Is the URL right, and is someone in between?".into());
    }
    proto::verifying_key(&out.server_key)?;
    proto::seal(&out.server_age, &())?;
    let cfg = Config {
        v: VERSION,
        name: out.name.clone(),
        server,
        server_key: out.server_key.clone(),
        server_age: out.server_age.clone(),
        sign_seed: B64.encode(sign.to_bytes()),
        age_identity: id.to_string().expose_secret().to_string(),
    };
    let json = Zeroizing::new(serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?);
    private_write(&d.join("runner.json"), &json)?;
    let _ = std::fs::remove_file(d.join("seen.json"));
    let rules = d.join("runner.toml");
    if !rules.exists() {
        let mut t = RULES_TEMPLATE.to_string();
        if cfg!(windows) {
            t.push_str(WINDOWS_RULES_EXAMPLE);
        }
        private_write(&rules, t.as_bytes())?;
    }
    println!(
        "Enrolled as runner \"{}\"; the server proved it knows the code.",
        out.name
    );
    println!("Server key:  {}", proto::fingerprint(&out.server_key));
    println!(
        "Runner key:  {}",
        proto::fingerprint(&proto::public_b64(&sign))
    );
    println!(
        "Rules:       {} (nothing runs until you list programs there)",
        rules.display()
    );
    match fetch_pins(&cfg).await {
        Ok(p) => {
            let n = p.keys.len();
            save_pins(&p)?;
            println!(
                "Passkeys:    {n} pinned for {} (require_passkey in runner.toml uses them)",
                p.rp_id
            );
            for k in &p.keys {
                println!("             {}  {}", proto::fingerprint(&k.key), k.name);
            }
        }
        Err(e) => println!("Passkeys:    none pinned ({e})"),
    }
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
    println!(
        "Passkey:     {} ({} pinned)",
        if i.require_passkey {
            "required"
        } else {
            "not required"
        },
        i.passkeys
    );
    if i.root {
        println!(
            "WARNING: this runner has administrator rights. Run it as its own user (on Windows, not elevated)."
        );
    }
    Ok(())
}

/// The server's list of passkeys, checked against the pinned server key.
async fn fetch_pins(cfg: &Config) -> Result<proto::PinnedPasskeys, String> {
    let sign = cfg.signing_key()?;
    let server_key = proto::verifying_key(&cfg.server_key)?;
    let path = "/v1/runner/passkeys";
    let mut req = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?
        .post(format!("{}{path}", cfg.server))
        .header("content-type", "application/json");
    for (k, v) in proto::sign_request(&sign, &cfg.name, "POST", path, now_unix(), b"{}") {
        req = req.header(k, v);
    }
    let r = req
        .body("{}")
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    let code = r.status().as_u16();
    let v: serde_json::Value = r.json().await.unwrap_or_default();
    if code != 200 {
        return Err(v["error"]
            .as_str()
            .map_or(format!("HTTP {code}"), |m| format!("{m} (HTTP {code})")));
    }
    let signed: Signed = serde_json::from_value(v).map_err(|_| "bad answer")?;
    let p: proto::PinnedPasskeys = signed.open(&server_key)?;
    if p.runner != cfg.name {
        return Err("the list is for another runner".into());
    }
    if p.keys.is_empty() {
        return Err("the server has no passkeys yet".into());
    }
    Ok(p)
}

/// `ucr runner trust-passkeys [--yes]`: pins the passkeys the server lists
/// now, after you check them. Run it on this machine after adding or
/// removing a passkey in the web UI.
pub async fn trust_passkeys(args: &[String]) -> Result<(), String> {
    let cfg = load_config()?;
    let p = fetch_pins(&cfg).await?;
    println!("Passkeys for {} ({}):", p.rp_id, p.origin);
    for k in &p.keys {
        println!("  {}  {}", proto::fingerprint(&k.key), k.name);
    }
    if let Some(old) = load_pins() {
        let same = old.keys.iter().map(|k| &k.id).collect::<Vec<_>>()
            == p.keys.iter().map(|k| &k.id).collect::<Vec<_>>();
        if same && old.rp_id == p.rp_id {
            println!("Already pinned; nothing changed.");
            return Ok(());
        }
    }
    println!("Compare the fingerprints with Settings → Passkey in the web UI.");
    if !args.iter().any(|a| a == "--yes") {
        eprint!("Pin these passkeys on this runner? [y/N] ");
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        if !matches!(line.trim(), "y" | "Y" | "yes") {
            return Err("not pinned".into());
        }
    }
    // Keep the counters already seen, so an old answer cannot come back.
    let mut p = p;
    if let Some(old) = load_pins() {
        for k in p.keys.iter_mut() {
            if let Some(o) = old.keys.iter().find(|o| o.id == k.id) {
                k.sign_count = k.sign_count.max(o.sign_count);
            }
        }
    }
    save_pins(&p)?;
    println!("Pinned {} passkeys.", p.keys.len());
    Ok(())
}

/// `ucr runner forget`: removes the keys. The server still lists the runner
/// until it is removed there.
pub fn forget() -> Result<(), String> {
    let p = dir().join("runner.json");
    let _ = std::fs::remove_file(dir().join("seen.json"));
    let _ = std::fs::remove_file(dir().join("passkeys.json"));
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

/// Jobs already received, kept on disk until they expire, so a copy of a
/// job is refused even after the runner restarts.
pub struct Seen {
    path: Option<PathBuf>,
    map: HashMap<String, i64>,
}

impl Seen {
    pub fn memory() -> Seen {
        Seen {
            path: None,
            map: HashMap::new(),
        }
    }

    fn open() -> Seen {
        let path = dir().join("seen.json");
        let map = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Seen {
            path: Some(path),
            map,
        }
    }

    /// Records a job id; an error if it was seen before or cannot be saved.
    pub fn claim(&mut self, job: &str, till: i64) -> Result<(), String> {
        let now = now_unix();
        self.map.retain(|_, t| *t >= now);
        if self.map.contains_key(job) {
            return Err("the job was already received".into());
        }
        self.map.insert(job.to_string(), till);
        if let Some(p) = &self.path {
            let b = serde_json::to_vec(&self.map).map_err(|e| e.to_string())?;
            // Refuse rather than run something whose replay we cannot stop.
            private_write(p, &b).map_err(|e| format!("cannot record the job: {e}"))?;
        }
        Ok(())
    }
}

/// The routing fields, checked before anything is decrypted.
pub fn check_outer(job: &Job, name: &str, seen: &mut Seen) -> Result<(), String> {
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
    if job.not_after > now + MAX_JOB_LIFE_SECS {
        return Err("the job is valid for too long; check the clocks".into());
    }
    if job.job.len() < 16 || !job.job.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("bad job id".into());
    }
    seen.claim(&job.job, job.not_after)
}

/// The command, checked against this runner's rules once decrypted.
pub fn check_body(job: &Job, body: &JobBody, name: &str, rules: &Rules) -> Result<(), String> {
    // The sealed part names the same job, so it cannot be moved onto
    // another envelope.
    if body.job != job.job || body.runner != name {
        return Err("the sealed job does not match its envelope".into());
    }
    if rules.require_totp && !body.totp {
        return Err("this runner only takes jobs approved with TOTP".into());
    }
    let e = &body.exec;
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
        timeout_sec: body.timeout_sec.clamp(0, 600),
        ..Default::default()
    };
    let public: BTreeSet<&str> = body.public.iter().map(String::as_str).collect();
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

fn failed(output: String) -> policy::RunResult {
    policy::RunResult {
        ok: false,
        exit: -1,
        output,
    }
}

async fn run_body(body: &JobBody) -> policy::RunResult {
    let values = match body.secrets.to_bytes() {
        Ok(v) => v,
        Err(e) => return failed(e),
    };
    let exec = match command_of(&body.exec) {
        Ok(x) => x,
        Err(e) => return failed(e),
    };
    let action = Action {
        exec: Some(exec),
        timeout_sec: if body.timeout_sec > 0 {
            body.timeout_sec.min(600)
        } else {
            30
        },
        ..Default::default()
    };
    let public: BTreeSet<String> = body.public.iter().cloned().collect();
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
    seen: Mutex<Seen>,
    log: Log,
}

impl Ctx {
    /// A POST signed with the runner's key: no token travels.
    async fn post(&self, path: &str, body: Vec<u8>) -> reqwest::Result<reqwest::Response> {
        let mut req = self
            .http
            .post(format!("{}{path}", self.cfg.server))
            .header("content-type", "application/json");
        for (k, v) in
            proto::sign_request(&self.sign, &self.cfg.name, "POST", path, now_unix(), &body)
        {
            req = req.header(k, v);
        }
        req.body(body).send().await
    }
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
    if let Err(e) = check_outer(&job, &ctx.cfg.name, &mut ctx.seen.lock().unwrap()) {
        // A replay or an expired copy: nothing to answer.
        eprintln!("runner: ignored job {}: {e}", job.job);
        ctx.log
            .write(serde_json::json!({"event": "ignored", "job": job.job, "why": e}));
        return;
    }
    let started = std::time::Instant::now();
    let body: Result<JobBody, String> = proto::unseal(&ctx.id, &job.sealed);
    let (res, refused, id, meta) = match body {
        Err(e) => (
            failed(format!("runner {} refused: {e}", ctx.cfg.name)),
            true,
            String::new(),
            serde_json::json!({}),
        ),
        Ok(b) => {
            let meta = serde_json::json!({"hash": b.hash, "approved_by": b.approved_by,
                "argv0": b.exec.argv.first(), "sudo": !b.exec.sudo.is_empty()});
            let verdict = load_rules().and_then(|r| {
                check_body(&job, &b, &ctx.cfg.name, &r)?;
                if r.require_passkey {
                    let pins = check_passkey(&b, load_pins().as_ref())?;
                    save_pins(&pins)?;
                }
                Ok(())
            });
            match verdict {
                Err(why) => (
                    failed(format!("runner {} refused: {why}", ctx.cfg.name)),
                    true,
                    b.id.clone(),
                    meta,
                ),
                Ok(()) => (run_body(&b).await, false, b.id.clone(), meta),
            }
        }
    };
    let mut line = serde_json::json!({
        "event": if refused { "refused" } else { "ran" }, "id": id, "job": job.job,
        "ok": res.ok, "exit": res.exit, "ms": started.elapsed().as_millis() as u64,
        "why": if refused { res.output.clone() } else { String::new() },
    });
    if let (Some(l), Some(m)) = (line.as_object_mut(), meta.as_object()) {
        l.extend(m.clone());
    }
    ctx.log.write(line);
    let sealed = match proto::seal(
        &ctx.cfg.server_age,
        &ResultBody {
            job: job.job.clone(),
            id: id.clone(),
            ok: res.ok,
            exit: res.exit,
            output: res.output,
            refused,
        },
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("runner: cannot seal the result of {id}: {e}");
            return;
        }
    };
    let signed = Signed::new(
        &ctx.sign,
        &JobResult {
            v: VERSION,
            job: job.job.clone(),
            runner: ctx.cfg.name.clone(),
            sealed,
        },
    );
    let body = serde_json::to_vec(&signed).unwrap_or_default();
    for attempt in 0..4u64 {
        match ctx.post("/v1/runner/result", body.clone()).await {
            Ok(r) if r.status().is_success() => return,
            // The server no longer waits for it; retrying will not help.
            Ok(r) if matches!(r.status().as_u16(), 403 | 404 | 410) => return,
            _ => tokio::time::sleep(Duration::from_secs(2 << attempt)).await,
        }
    }
    eprintln!("runner: could not deliver the result of {id}");
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
        seen: Mutex::new(Seen::open()),
        log: Log::open(),
    });
    let mut backoff = 2u64;
    let mut said_locked = false;
    loop {
        let sealed = proto::seal(&ctx.cfg.server_age, &info()).unwrap_or_default();
        let body = serde_json::to_vec(&PollIn { info: sealed }).unwrap_or_default();
        match ctx.post("/v1/runner/poll", body).await {
            Ok(r) if r.status().is_success() => {
                backoff = 2;
                said_locked = false;
                let out: PollOut = r.json().await.unwrap_or_default();
                for env in out.jobs {
                    tokio::spawn(handle(ctx.clone(), env));
                }
            }
            Ok(r) if r.status().as_u16() == 401 => {
                eprintln!(
                    "runner: the server did not accept the signature; check this machine's clock"
                );
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
            }
            Ok(r) if r.status().as_u16() == 403 => {
                return Err("the server does not know this runner: it was removed. Enroll again with a new code.".into());
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

#[cfg(test)]
mod unit {
    use super::*;

    fn outer() -> Job {
        Job {
            v: VERSION,
            job: format!("{:032x}", rand::random::<u128>()),
            runner: "box".into(),
            not_after: now_unix() + 60,
            ..Default::default()
        }
    }

    fn body_of(j: &Job, argv: &[&str]) -> JobBody {
        JobBody {
            job: j.job.clone(),
            runner: j.runner.clone(),
            id: "r1".into(),
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
            require_passkey: false,
        }
    }

    #[test]
    fn outer_checks_identity_time_and_replay() {
        let mut seen = Seen::memory();
        let j = outer();
        assert!(check_outer(&j, "box", &mut seen).is_ok());
        let e = check_outer(&j, "box", &mut seen).unwrap_err();
        assert!(e.contains("already"), "{e}");
        assert!(check_outer(&outer(), "other", &mut seen).is_err());
        let mut old = outer();
        old.not_after = now_unix() - 1;
        assert!(
            check_outer(&old, "box", &mut seen)
                .unwrap_err()
                .contains("expired")
        );
        let mut far = outer();
        far.not_after = now_unix() + 86400;
        assert!(
            check_outer(&far, "box", &mut seen)
                .unwrap_err()
                .contains("too long")
        );
        let mut v1 = outer();
        v1.v = 1;
        assert!(check_outer(&v1, "box", &mut seen).is_err());
    }

    #[test]
    fn replays_are_refused_after_a_restart() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("seen.json");
        let mut a = Seen {
            path: Some(path.clone()),
            map: HashMap::new(),
        };
        a.claim("aaaabbbbccccdddd", now_unix() + 60).unwrap();
        let mut b = Seen {
            path: Some(path.clone()),
            map: serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap(),
        };
        assert!(b.claim("aaaabbbbccccdddd", now_unix() + 60).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn body_checks_rules() {
        let r = rules(&["/usr/bin/id"]);
        let j = outer();
        assert!(check_body(&j, &body_of(&j, &["/usr/bin/id"]), "box", &r).is_ok());
        let e = check_body(&j, &body_of(&j, &["/usr/bin/rm", "-rf", "/"]), "box", &r).unwrap_err();
        assert!(e.contains("allow list"), "{e}");
        // Even with "*", the shared rules still stop a shell.
        let e = check_body(
            &j,
            &body_of(&j, &["/bin/sh", "-c", "id"]),
            "box",
            &rules(&["*"]),
        )
        .unwrap_err();
        assert!(e.contains("interpreters"), "{e}");
        let mut b = body_of(&j, &["/usr/bin/id"]);
        b.totp = false;
        assert!(check_body(&j, &b, "box", &r).unwrap_err().contains("TOTP"));
        let mut b = body_of(&j, &["/usr/bin/id"]);
        b.exec.sudo = "{{secret:pw}}".into();
        let mut off = r.clone();
        off.sudo = false;
        assert!(
            check_body(&j, &b, "box", &off)
                .unwrap_err()
                .contains("sudo is off")
        );
        // A body taken from another envelope.
        let other = outer();
        assert!(
            check_body(&j, &body_of(&other, &["/usr/bin/id"]), "box", &r)
                .unwrap_err()
                .contains("envelope")
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
    async fn runs_with_its_secrets_and_redacts() {
        let cat = ["/bin/cat", "/usr/bin/cat"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
            .unwrap();
        let j = outer();
        let mut b = body_of(&j, &[cat]);
        b.exec.stdin = "{{secret:k}}".into();
        let mut m = std::collections::BTreeMap::new();
        m.insert("k".to_string(), Zeroizing::new(b"s3cr3t-value".to_vec()));
        b.secrets = proto::Values::from_bytes(&m);
        let r = run_body(&b).await;
        assert!(r.ok, "{r:?}");
        assert!(!r.output.contains("s3cr3t-value"), "{}", r.output);
        assert!(r.output.contains("[REDACTED]"));
    }

    #[test]
    fn passkey_approval_is_checked_against_the_job() {
        use crate::webauthn::{self, testkit};
        let rp = testkit::rp();
        let mut key = testkit::Fake::new();
        let ch = webauthn::new_challenge();
        let made: webauthn::Credential = serde_json::from_value(
            key.create(&rp, &webauthn::creation_options(&rp, b"u", &ch, &[])),
        )
        .unwrap();
        let pk = webauthn::finish_register(&rp, &ch, &made).unwrap();
        let pins = proto::PinnedPasskeys {
            runner: "box".into(),
            rp_id: rp.id.clone(),
            origin: rp.origin.clone(),
            keys: vec![pk],
        };
        let j = outer();
        let mut b = body_of(&j, &["/usr/bin/systemctl", "restart", "nginx"]);
        b.hash = "h123".into();
        b.timeout_sec = 30;
        // What the server does when the owner approves.
        let sign = |b: &JobBody, key: &mut testkit::Fake| {
            let action = Action {
                exec: Some(b.exec.clone()),
                timeout_sec: b.timeout_sec,
                runner: b.runner.clone(),
                ..Default::default()
            };
            let nonce = "00ff".to_string();
            let ch = proto::approval_challenge(&proto::action_digest(&action), &b.hash, &nonce);
            let got = key.get(&rp, &webauthn::request_options(&rp, &ch, &pins.keys));
            proto::Approval {
                credential: serde_json::from_value(got).unwrap(),
                nonce,
            }
        };
        assert!(
            check_passkey(&b, Some(&pins))
                .unwrap_err()
                .contains("only takes jobs approved")
        );
        b.approval = Some(sign(&b, &mut key));
        assert!(
            check_passkey(&b, None)
                .unwrap_err()
                .contains("trust-passkeys")
        );
        let after = check_passkey(&b, Some(&pins)).unwrap();
        assert_eq!(after.keys[0].sign_count, 1);
        // The server changes the command after the approval: refused.
        let mut changed = b.clone_for_test();
        changed.exec.argv = vec!["/usr/bin/systemctl".into(), "stop".into(), "nginx".into()];
        assert!(
            check_passkey(&changed, Some(&after))
                .unwrap_err()
                .contains("rejected")
        );
        // A passkey nobody pinned: refused.
        let mut other = testkit::Fake::new();
        let mut b2 = b.clone_for_test();
        b2.approval = Some(sign(&b2, &mut other));
        assert!(check_passkey(&b2, Some(&after)).is_err());
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
