//! Ties the vault, policy, approval channels and audit log together (port of
//! `internal/core`). Error strings match the Go version because the web UI
//! translates them by their text.
//!
//! `setup`, `login`, `unlock_at_start` and `totp_reset` run scrypt and block
//! for about a second; call them from `spawn_blocking` in async code.

mod fields;
mod health;
mod lang;
#[cfg(test)]
mod tests;

pub use crate::state::{TelegramCfg, Token};
pub use fields::{FieldInfo, SecretInfo};
pub use health::HealthItem;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::Rng;
use serde::{Serialize, Serializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use tokio::runtime::Handle;
use tokio::sync::watch;

use crate::policy::{self, Action, Call, Connection, Profile, RunResult, SecretMeta, gourl};
use crate::state::{self, CURRENT_STATE_VERSION, State};
use crate::telegram::{self, Bot, Handler};
use crate::{audit, totp, vault};

const SECRET_TELEGRAM: &str = "_telegram_token";
const SECRET_TOTP: &str = "_totp_secret";
pub const MIN_PASSPHRASE: usize = 12;
const MAX_PENDING: usize = 5;
const RATE_WINDOW: Duration = Duration::from_secs(10 * 60);
const RATE_MAX: usize = 30;
pub(crate) const MAX_DISPLAY: usize = 3000;
const MAX_PAIR_FAILS: u32 = 3;
const PAIR_TTL: Duration = Duration::from_secs(3 * 60);
const PAIR_LETTERS: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
const PAIR_SYMBOLS: &[u8] = b"#$%&+=?!";
const MAX_HISTORY: usize = 200;
/// Commands longer than this are cut in the run log; the hash still binds them.
const MAX_LOG_COMMAND: usize = 2000;
const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

#[derive(Debug)]
pub enum Error {
    Locked,
    NotFound,
    Forbidden,
    Busy,
    LoginBusy,
    ExecOff,
    BadTotp,
    NeedTotp,
    Decided,
    HashChange,
    Tampered,
    StateTooNew,
    Vault(vault::Error),
    Policy(policy::Error),
    Msg(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Locked => "vault locked",
            Error::NotFound => "not found",
            Error::Forbidden => "forbidden",
            Error::Busy => "too many pending requests",
            Error::LoginBusy => "login in progress",
            Error::ExecOff => "chạy lệnh đang tắt, đặt UCANRUN_ENABLE_EXEC=1 và dùng image exec",
            Error::BadTotp => "sai mã TOTP",
            Error::NeedTotp => "cần mã TOTP",
            Error::Decided => "yêu cầu đã được xử lý hoặc hết hạn",
            Error::HashChange => "yêu cầu không khớp",
            Error::Tampered => "state file failed authentication",
            Error::StateTooNew => "state file version is newer than this binary",
            Error::Vault(e) => return e.fmt(f),
            Error::Policy(e) => return e.fmt(f),
            Error::Msg(m) => m,
        })
    }
}

impl std::error::Error for Error {}

impl Error {
    /// The HTTP status the Go web layer gives this error.
    pub fn status(&self) -> u16 {
        match self {
            Error::Locked => 423,
            Error::Forbidden => 403,
            Error::NotFound | Error::Vault(vault::Error::NotFound) => 404,
            Error::Busy | Error::LoginBusy => 429,
            _ => 400,
        }
    }
}

impl From<vault::Error> for Error {
    fn from(e: vault::Error) -> Self {
        match e {
            vault::Error::Locked => Error::Locked,
            e => Error::Vault(e),
        }
    }
}

impl From<policy::Error> for Error {
    fn from(e: policy::Error) -> Self {
        Error::Policy(e)
    }
}

impl From<state::Error> for Error {
    fn from(e: state::Error) -> Self {
        match e {
            state::Error::Tampered => Error::Tampered,
            state::Error::TooNew => Error::StateTooNew,
            e => Error::Msg(e.to_string()),
        }
    }
}

impl From<audit::Error> for Error {
    fn from(e: audit::Error) -> Self {
        Error::Msg(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReqState {
    Pending,
    Denied,
    Expired,
    Running,
    Done,
    Failed,
}

impl ReqState {
    pub fn as_str(self) -> &'static str {
        match self {
            ReqState::Pending => "pending",
            ReqState::Denied => "denied",
            ReqState::Expired => "expired",
            ReqState::Running => "running",
            ReqState::Done => "done",
            ReqState::Failed => "failed",
        }
    }

    pub fn is_final(self) -> bool {
        !matches!(self, ReqState::Pending | ReqState::Running)
    }
}

/// A request as the web and agents see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Request {
    pub id: String,
    pub profile: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    pub caller: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    pub risk: String,
    /// Approval asks for a TOTP code.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub totp: bool,
    pub hash: String,
    pub display: String,
    pub state: ReqState,
    /// Host name the agent's machine reported. Self-declared, not verified.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub device: String,
    /// Agent software from the MCP handshake, such as `claude-code 2.1`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub app: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(serialize_with = "ser_time")]
    pub created: SystemTime,
    #[serde(serialize_with = "ser_time")]
    pub expires: SystemTime,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub decided_by: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub secret: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<RunResult>,
}

/// What the agent's side says about itself. Both values are self-declared:
/// the token is what identifies the agent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientInfo {
    pub device: String,
    pub app: String,
}

impl ClientInfo {
    pub fn new(device: &str, app: &str) -> ClientInfo {
        ClientInfo {
            device: clean_label(device),
            app: clean_label(app),
        }
    }
}

/// Keeps a short, printable label; anything else could mislead the approver.
fn clean_label(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || " ._-/()+:@".contains(*c))
        .take(64)
        .collect::<String>()
        .trim()
        .to_string()
}

/// The run log fields of a finished request: who asked, from where, with which
/// secrets, and the command as the approver saw it (secrets never appear in it).
fn run_fields(r: &Request, refs: &[String]) -> Value {
    let mut secrets: Vec<String> = refs.to_vec();
    if !r.secret.is_empty() && !secrets.contains(&r.secret) {
        secrets.push(r.secret.clone());
    }
    secrets.sort();
    secrets.dedup();
    let mut f = json!({"profile": r.profile, "agent": r.caller,
        "command": r.display.chars().take(MAX_LOG_COMMAND).collect::<String>()});
    if !secrets.is_empty() {
        f["secrets"] = json!(secrets);
    }
    if !r.device.is_empty() {
        f["device"] = json!(r.device);
    }
    if !r.app.is_empty() {
        f["app"] = json!(r.app);
    }
    f
}

fn ser_time<S: Serializer>(t: &SystemTime, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&rfc3339_nano(*t))
}

/// Go's RFC3339Nano in UTC.
pub(crate) fn rfc3339_nano(t: SystemTime) -> String {
    let t = OffsetDateTime::from(t).to_offset(time::UtcOffset::UTC);
    let mut s = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    let frac = format!("{:09}", t.nanosecond());
    let frac = frac.trim_end_matches('0');
    if !frac.is_empty() {
        s.push('.');
        s.push_str(frac);
    }
    s.push('Z');
    s
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct TelegramStatus {
    pub configured: bool,
    pub paired: bool,
    #[serde(skip_serializing_if = "is_zero")]
    pub user_id: i64,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// A draft profile rendered with sample values. Nothing runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Preview {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub display: String,
    pub warnings: Vec<String>,
}

pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

#[derive(Clone, Default)]
pub struct Options {
    pub data_dir: PathBuf,
    /// Zero means two minutes.
    pub approval_ttl: Duration,
    /// Override for tests.
    pub telegram_api: String,
    pub work_factor: u8,
    /// Permits profiles that run programs. Off by default: the default image
    /// only calls APIs.
    pub allow_exec: bool,
    /// "vi" or "en" for Telegram messages. Empty means English.
    pub lang: String,
    pub now: Option<Clock>,
}

struct Entry {
    req: Request,
    action: Action,
    done: watch::Sender<bool>,
}

struct Inner {
    st: Option<State>, // None while locked
    audit_cut: bool,
    reqs: HashMap<String, Entry>,
    order: VecDeque<String>,
    bot: Option<Arc<Bot>>,
    bot_stop: Option<watch::Sender<bool>>,
    pair_code: String,
    pair_till: SystemTime,
    pair_fails: u32,
    recent: HashMap<String, Vec<SystemTime>>,
}

pub struct Core {
    opt: Options,
    pub vault: vault::Vault,
    pub audit: audit::Log,
    inner: Mutex<Inner>,
    login_mu: Mutex<()>,
    rt: Handle,
    me: Weak<Core>,
    shutdown: watch::Sender<bool>,
}

/// Lets the bot reach the core without keeping it alive.
struct Relay(Weak<Core>);

impl Handler for Relay {
    fn decide(
        &self,
        id: &str,
        short: &str,
        approve: bool,
        actor: &str,
        totp: &str,
        secret: &str,
    ) -> std::result::Result<String, String> {
        match self.0.upgrade() {
            Some(c) => Handler::decide(&*c, id, short, approve, actor, totp, secret),
            None => Err(Error::Decided.to_string()),
        }
    }
    fn needs_totp(&self, id: &str) -> bool {
        self.0.upgrade().is_some_and(|c| c.needs_totp(id))
    }
    fn secret_at(&self, id: &str, index: usize) -> Option<String> {
        self.0.upgrade().and_then(|c| c.secret_at(id, index))
    }
    fn pair(&self, code: &str, user_id: i64, chat_id: i64) -> bool {
        self.0
            .upgrade()
            .is_some_and(|c| c.pair(code, user_id, chat_id))
    }
}

impl Handler for Core {
    fn decide(
        &self,
        id: &str,
        short: &str,
        approve: bool,
        actor: &str,
        totp: &str,
        secret: &str,
    ) -> std::result::Result<String, String> {
        Core::decide(self, id, short, approve, actor, totp, secret).map_err(|e| e.to_string())
    }
    fn needs_totp(&self, id: &str) -> bool {
        Core::needs_totp(self, id)
    }
    fn secret_at(&self, id: &str, index: usize) -> Option<String> {
        Core::secret_at(self, id, index)
    }
    fn pair(&self, code: &str, user_id: i64, chat_id: i64) -> bool {
        Core::pair(self, code, user_id, chat_id)
    }
}

fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill(&mut b[..]);
    hex::encode(b)
}

fn pick(set: &[u8]) -> u8 {
    set[rand::rngs::OsRng.gen_range(0..set.len())]
}

fn unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn obj(v: Value) -> serde_json::Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => serde_json::Map::new(),
    }
}

fn normalize_recovery(s: &str) -> String {
    s.replace(['-', ' '], "").to_uppercase()
}

fn hash_recovery(s: &str) -> String {
    hex::encode(Sha256::digest(
        format!("ucanrun recovery v1:{}", normalize_recovery(s)).as_bytes(),
    ))
}

/// Eight codes shown once, and their hashes.
fn new_recovery_codes() -> (Vec<String>, Vec<String>) {
    let mut plain = vec![];
    let mut hashes = vec![];
    for _ in 0..8 {
        let b: Vec<u8> = (0..10).map(|_| pick(RECOVERY_ALPHABET)).collect();
        let code = format!(
            "{}-{}",
            String::from_utf8_lossy(&b[..5]),
            String::from_utf8_lossy(&b[5..])
        );
        hashes.push(hash_recovery(&code));
        plain.push(code);
    }
    (plain, hashes)
}

/// Six characters with one symbol at a random position. The alphabet skips
/// lookalikes and characters Telegram treats as formatting.
fn new_pair_code() -> String {
    let all: Vec<u8> = [PAIR_LETTERS, PAIR_SYMBOLS].concat();
    let mut code: Vec<u8> = (0..6).map(|_| pick(&all)).collect();
    code[rand::rngs::OsRng.gen_range(0..6)] = pick(PAIR_SYMBOLS);
    String::from_utf8(code).expect("ascii")
}

fn clean_reason(s: &str) -> String {
    let s: String = s
        .chars()
        .filter_map(|r| {
            if r == '\n' || r == ' ' {
                Some(' ')
            } else if gourl::is_control_or_format(r) {
                None
            } else {
                Some(r)
            }
        })
        .collect();
    if s.chars().count() > 200 {
        return s.chars().take(200).collect::<String>() + "…";
    }
    s
}

fn allowed(t: &Token, profile: &str) -> bool {
    t.profiles.is_empty() || t.profiles.iter().any(|p| p == profile)
}

/// Whether a token limited to workspaces may use this secret reference.
/// Unknown secrets fall in the default workspace.
pub(crate) fn in_scope(t: &Token, r: &str, meta: &BTreeMap<String, SecretMeta>) -> bool {
    if t.workspaces.is_empty() {
        return true;
    }
    let ws = meta
        .get(policy::secret_of(r, meta))
        .map_or("", |m| m.workspace.as_str());
    t.workspaces.iter().any(|w| w == ws)
}

/// Every secret a profile may touch, including the ones chosen on approval.
fn profile_secrets(p: &Profile) -> Vec<String> {
    let mut v: Vec<String> = action_of(p)
        .secrets()
        .into_iter()
        .filter(|n| n != policy::CHOICE_REF)
        .collect();
    v.extend(p.secret_choices.iter().cloned());
    v
}

fn action_of(p: &Profile) -> Action {
    Action {
        http: p.http.clone(),
        exec: p.exec.clone(),
        timeout_sec: 0,
    }
}

impl Core {
    /// Opens the data directory. Must be called inside a tokio runtime, which
    /// runs the bot, executions and the expiry loop.
    pub fn new(mut opt: Options) -> Result<Arc<Core>> {
        let rt = Handle::try_current()
            .map_err(|_| Error::Msg("ucanrun core needs a tokio runtime".into()))?;
        if opt.approval_ttl.is_zero() {
            opt.approval_ttl = Duration::from_secs(120);
        }
        let mut v = vault::Vault::new(opt.data_dir.join("vault"));
        v.work_factor = opt.work_factor;
        vault::atomic_write(&opt.data_dir.join(".keep"), &[])?;
        let l = audit::Log::open(opt.data_dir.join("audit.jsonl"))?;
        let (shutdown, _) = watch::channel(false);
        let c = Arc::new_cyclic(|me| Core {
            opt,
            vault: v,
            audit: l,
            inner: Mutex::new(Inner {
                st: None,
                audit_cut: false,
                reqs: HashMap::new(),
                order: VecDeque::new(),
                bot: None,
                bot_stop: None,
                pair_code: String::new(),
                pair_till: UNIX_EPOCH,
                pair_fails: 0,
                recent: HashMap::new(),
            }),
            login_mu: Mutex::new(()),
            rt,
            me: me.clone(),
            shutdown,
        });
        let weak = Arc::downgrade(&c);
        let mut stop = c.shutdown.subscribe();
        c.rt.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = stop.wait_for(|v| *v) => return,
                }
                match weak.upgrade() {
                    Some(c) => c.expire_now(),
                    None => return,
                }
            }
        });
        Ok(c)
    }

    /// Stops background work and locks.
    pub fn close(&self) {
        self.shutdown.send_replace(true);
        self.lock("shutdown");
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn login_guard(&self) -> Result<MutexGuard<'_, ()>> {
        match self.login_mu.try_lock() {
            Ok(g) => Ok(g),
            Err(TryLockError::Poisoned(p)) => Ok(p.into_inner()),
            Err(TryLockError::WouldBlock) => Err(Error::LoginBusy),
        }
    }

    fn now(&self) -> SystemTime {
        match &self.opt.now {
            Some(f) => f(),
            None => SystemTime::now(),
        }
    }

    fn vi(&self) -> bool {
        self.opt.lang == "vi"
    }

    fn state_path(&self) -> PathBuf {
        self.opt.data_dir.join("state.json")
    }

    fn audit_path(&self) -> PathBuf {
        self.opt.data_dir.join("audit.jsonl")
    }

    pub fn audit_truncated(&self) -> bool {
        self.inner().audit_cut
    }

    fn log(&self, event: &str, actor: &str, f: Value) {
        if let Err(e) = self.audit.append(event, actor, obj(f)) {
            eprintln!("ERROR audit append: {e}");
        }
    }

    /// Anchors the current audit head in state; entries written after the
    /// last save are not covered until the next save or lock.
    fn save_locked(&self, g: &mut Inner) -> Result<()> {
        let k = self.vault.mac_key().map_err(|_| Error::Locked)?;
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        let (n, h) = self.audit.head();
        st.audit_count = n as i64;
        st.audit_hash = h;
        state::save(&self.state_path(), st, &k)?;
        Ok(())
    }

    pub fn initialized(&self) -> bool {
        self.vault.initialized()
    }

    /// Creates the vault and first state.
    pub fn setup(&self, pass: &[u8]) -> Result<()> {
        if pass.len() < MIN_PASSPHRASE {
            return Err(Error::Msg(format!(
                "mật khẩu chính cần ít nhất {MIN_PASSPHRASE} ký tự"
            )));
        }
        let _l = self.login_guard()?;
        self.vault.init(pass)?;
        let mut g = self.inner();
        g.st = Some(State {
            version: CURRENT_STATE_VERSION,
            ..Default::default()
        });
        self.save_locked(&mut g)?;
        self.log("setup", "web", Value::Null);
        Ok(())
    }

    pub fn locked(&self) -> bool {
        self.inner().st.is_none()
    }

    /// Opens the adopted vault's state, or locks again on failure.
    fn load_locked(&self, g: &mut Inner) -> Result<()> {
        let r = self
            .vault
            .mac_key()
            .map_err(Error::from)
            .and_then(|k| state::load(&self.state_path(), &k).map_err(Error::from));
        match r {
            Ok(st) => {
                g.st = Some(st);
                Ok(())
            }
            Err(e) => {
                g.st = None;
                self.vault.lock();
                Err(e)
            }
        }
    }

    /// Verifies the passphrase and, once enrolled, TOTP. If the vault was
    /// locked it unlocks, and stays locked again when TOTP fails.
    pub fn login(&self, pass: &[u8], code: &str) -> Result<()> {
        // scrypt takes a second and lots of memory. One at a time, and outside
        // the main lock, so anonymous logins can neither exhaust memory nor
        // stall approvals.
        let _l = self.login_guard()?;
        let id = self.vault.open(pass)?;
        let mut g = self.inner();
        let was_locked = g.st.is_none();
        let (mut count, mut hash) = (0, String::new());
        if was_locked {
            self.vault.adopt(id);
            if let Err(e) = self.load_locked(&mut g) {
                self.log("state_tamper", "web", Value::Null);
                return Err(e);
            }
            let st = g.st.as_ref().expect("loaded");
            (count, hash) = (st.audit_count, st.audit_hash.clone());
        }
        if g.st.as_ref().is_some_and(|s| s.totp_enabled)
            && let Err(e) = self.check_second_factor_locked(&mut g, code)
        {
            if was_locked {
                g.st = None;
                self.vault.lock();
            }
            self.log("login_failed", "web", json!({"why": "totp"}));
            return Err(e);
        }
        if was_locked {
            let ok =
                audit::contains(&self.audit_path(), count.max(0) as usize, &hash).unwrap_or(false);
            if !ok {
                g.audit_cut = true;
                self.log("audit_truncated", "web", json!({"count": count}));
            }
            self.start_bot_locked(&mut g);
        }
        self.log("login", "web", Value::Null);
        Ok(())
    }

    /// Accepts a TOTP code or a single-use recovery code.
    fn check_second_factor_locked(&self, g: &mut Inner, code: &str) -> Result<()> {
        if code.len() == 6 {
            return self.check_totp_locked(g, code);
        }
        if self.use_recovery_locked(g, code) {
            let left = g.st.as_ref().map_or(0, |s| s.recovery_hashes.len());
            self.log("recovery_code_used", "web", json!({"left": left}));
            return self.save_locked(g);
        }
        if code.is_empty() {
            return Err(Error::NeedTotp);
        }
        Err(Error::BadTotp)
    }

    fn use_recovery_locked(&self, g: &mut Inner, code: &str) -> bool {
        if normalize_recovery(code).len() != 10 {
            return false;
        }
        let h = hash_recovery(code);
        let Some(st) = g.st.as_mut() else {
            return false;
        };
        let Some(i) = st
            .recovery_hashes
            .iter()
            .position(|v| bool::from(v.as_bytes().ct_eq(h.as_bytes())))
        else {
            return false;
        };
        st.recovery_hashes.remove(i);
        true
    }

    fn check_totp_locked(&self, g: &mut Inner, code: &str) -> Result<()> {
        if code.is_empty() {
            return Err(Error::NeedTotp);
        }
        let sec = self.vault.get(SECRET_TOTP)?;
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        let step = totp::verify(
            &String::from_utf8_lossy(&sec),
            code,
            unix(self.now()),
            st.last_totp_step.max(0) as u64,
        );
        if step == 0 {
            return Err(Error::BadTotp);
        }
        st.last_totp_step = step as i64;
        self.save_locked(g)
    }

    /// How many unused recovery codes remain.
    pub fn recovery_left(&self) -> usize {
        self.inner()
            .st
            .as_ref()
            .map_or(0, |s| s.recovery_hashes.len())
    }

    /// Replaces all recovery codes. A TOTP code proves the phone is in hand.
    pub fn new_recovery_codes(&self, code: &str) -> Result<Vec<String>> {
        let mut g = self.inner();
        let st = g.st.as_ref().ok_or(Error::Locked)?;
        if !st.totp_enabled {
            return Err(Error::Msg("chưa bật TOTP".into()));
        }
        self.check_totp_locked(&mut g, code)?;
        let (plain, hashes) = new_recovery_codes();
        g.st.as_mut().ok_or(Error::Locked)?.recovery_hashes = hashes;
        self.log("recovery_codes_created", "web", Value::Null);
        self.save_locked(&mut g)?;
        Ok(plain)
    }

    /// Turns TOTP off so a new phone can enroll. It needs the passphrase and a
    /// current TOTP or recovery code, so a stolen session alone cannot do it.
    pub fn totp_reset(&self, pass: &[u8], code: &str) -> Result<()> {
        let _l = self.login_guard()?;
        self.vault.verify(pass)?;
        let mut g = self.inner();
        if g.st.is_none() {
            return Err(Error::Locked);
        }
        self.check_second_factor_locked(&mut g, code)?;
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        st.totp_enabled = false;
        st.recovery_hashes.clear();
        st.last_totp_step = 0;
        self.log("totp_reset", "web", Value::Null);
        self.save_locked(&mut g)
    }

    /// Opens the vault from a file at startup, so a restart does not leave
    /// agents locked out. It skips TOTP by design: whoever can read that file
    /// on the host already controls the server.
    pub fn unlock_at_start(&self, pass: &[u8]) -> Result<()> {
        let id = self.vault.open(pass)?;
        let mut g = self.inner();
        if g.st.is_some() {
            return Ok(());
        }
        self.vault.adopt(id);
        self.load_locked(&mut g)?;
        self.start_bot_locked(&mut g);
        self.log("auto_unlock", "file", Value::Null);
        Ok(())
    }

    /// Wipes the key from memory and denies everything in flight.
    pub fn lock(&self, actor: &str) {
        let mut g = self.inner();
        if g.st.is_none() {
            return;
        }
        let pending: Vec<String> = g
            .reqs
            .iter()
            .filter(|(_, e)| e.req.state == ReqState::Pending)
            .map(|(id, _)| id.clone())
            .collect();
        for id in pending {
            self.finish_locked(&mut g, &id, ReqState::Denied, "lock");
        }
        self.stop_bot_locked(&mut g);
        self.log("lock", actor, Value::Null);
        if let Err(e) = self.save_locked(&mut g) {
            eprintln!("ERROR state save: {e}");
        }
        g.st = None;
        self.vault.lock();
    }

    fn stop_bot_locked(&self, g: &mut Inner) {
        if let Some(s) = g.bot_stop.take() {
            s.send_replace(true);
        }
        g.bot = None;
    }

    fn translator(&self) -> telegram::Translate {
        let vi = self.vi();
        Arc::new(move |s: &str| lang::translate(vi, s))
    }

    fn start_bot_locked(&self, g: &mut Inner) {
        self.stop_bot_locked(g);
        let Ok(tok) = self.vault.get(SECRET_TELEGRAM) else {
            return;
        };
        let Some(st) = g.st.as_ref() else { return };
        let bot = Bot::new(
            telegram::Config {
                base_url: self.opt.telegram_api.clone(),
                token: String::from_utf8_lossy(&tok).into_owned(),
                user_id: st.telegram.user_id,
                chat_id: st.telegram.chat_id,
                translate: Some(self.translator()),
            },
            Some(Arc::new(Relay(self.me.clone()))),
        );
        let (tx, rx) = watch::channel(false);
        self.rt.spawn(bot.clone().run(rx));
        g.bot = Some(bot);
        g.bot_stop = Some(tx);
    }

    // --- Telegram configuration ---

    pub fn telegram_status(&self) -> TelegramStatus {
        let g = self.inner();
        let Some(st) = g.st.as_ref() else {
            return TelegramStatus::default();
        };
        TelegramStatus {
            configured: g.bot.is_some(),
            paired: st.telegram.user_id != 0,
            user_id: st.telegram.user_id,
        }
    }

    /// Checks the token, stores it encrypted, and returns the bot name and a
    /// pairing code. Changing the bot clears the pairing.
    pub async fn set_telegram_token(&self, token: &str) -> Result<(String, String)> {
        let probe = Bot::new(
            telegram::Config {
                base_url: self.opt.telegram_api.clone(),
                token: token.to_string(),
                ..Default::default()
            },
            None,
        );
        let u = probe.check().await.map_err(|_| {
            Error::Msg("token Telegram không hợp lệ hoặc không kết nối được".into())
        })?;
        let mut g = self.inner();
        if g.st.is_none() {
            return Err(Error::Locked);
        }
        self.vault.put(SECRET_TELEGRAM, token.as_bytes())?;
        g.st.as_mut().ok_or(Error::Locked)?.telegram = TelegramCfg::default();
        self.save_locked(&mut g)?;
        g.pair_code = new_pair_code();
        g.pair_till = self.now() + PAIR_TTL;
        g.pair_fails = 0;
        self.start_bot_locked(&mut g);
        self.log("telegram_set", "web", json!({"bot": u}));
        Ok((u, g.pair_code.clone()))
    }

    pub fn new_pair_code(&self) -> Result<String> {
        let mut g = self.inner();
        if g.bot.is_none() {
            return Err(Error::Msg("chưa cấu hình bot".into()));
        }
        g.pair_code = new_pair_code();
        g.pair_till = self.now() + PAIR_TTL;
        g.pair_fails = 0;
        Ok(g.pair_code.clone())
    }

    /// The pairing code is single use.
    pub fn pair(&self, code: &str, user_id: i64, chat_id: i64) -> bool {
        let mut g = self.inner();
        if g.st.is_none() || g.pair_code.is_empty() || self.now() > g.pair_till {
            return false;
        }
        if !bool::from(code.as_bytes().ct_eq(g.pair_code.as_bytes())) {
            // Six characters are only safe with very few guesses, and anyone
            // on Telegram can message the bot.
            g.pair_fails += 1;
            if g.pair_fails >= MAX_PAIR_FAILS {
                g.pair_code.clear();
                self.log("pair_code_burned", "telegram", Value::Null);
            }
            return false;
        }
        g.pair_code.clear();
        if let Some(st) = g.st.as_mut() {
            st.telegram = TelegramCfg { user_id, chat_id };
        }
        if self.save_locked(&mut g).is_err() {
            return false;
        }
        self.log("telegram_paired", "telegram", json!({"user": user_id}));
        true
    }

    // --- TOTP enrollment ---

    /// Returns the new TOTP secret and its otpauth URI.
    pub fn totp_start(&self) -> Result<(String, String)> {
        let g = self.inner();
        let st = g.st.as_ref().ok_or(Error::Locked)?;
        if st.totp_enabled {
            return Err(Error::Msg("TOTP đã bật".into()));
        }
        let secret = totp::generate();
        self.vault.put(SECRET_TOTP, secret.as_bytes())?;
        let uri = totp::uri(&secret, "owner");
        Ok((secret, uri))
    }

    /// Finishes enrollment and returns recovery codes, shown once.
    pub fn totp_confirm(&self, code: &str) -> Result<Vec<String>> {
        let mut g = self.inner();
        if g.st.is_none() {
            return Err(Error::Locked);
        }
        self.check_totp_locked(&mut g, code)?;
        let (plain, hashes) = new_recovery_codes();
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        st.totp_enabled = true;
        st.recovery_hashes = hashes;
        self.log("totp_enabled", "web", Value::Null);
        self.save_locked(&mut g)?;
        Ok(plain)
    }

    pub fn totp_enabled(&self) -> bool {
        self.inner().st.as_ref().is_some_and(|s| s.totp_enabled)
    }

    /// Checks a change of a secret's TOTP setting before anything is written.
    /// Waiving TOTP needs a current code, so an open session alone cannot
    /// weaken approvals. Recovery codes do not count here.
    pub fn authorize_secret_totp(&self, name: &str, mode: &str, code: &str) -> Result<()> {
        let mut g = self.inner();
        let st = g.st.as_ref().ok_or(Error::Locked)?;
        let old = st.secrets.get(name).map_or("", |m| m.totp.as_str());
        if mode == policy::TOTP_NEVER && old != policy::TOTP_NEVER && st.totp_enabled {
            self.check_totp_locked(&mut g, code)?;
        }
        Ok(())
    }

    // --- Profiles and tokens ---

    pub fn profiles(&self) -> Result<Vec<Profile>> {
        let g = self.inner();
        let st = g.st.as_ref().ok_or(Error::Locked)?;
        let mut out: Vec<Profile> = st.profiles.values().cloned().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Whether profiles may run programs.
    pub fn exec_enabled(&self) -> bool {
        self.opt.allow_exec
    }

    pub fn put_profile(&self, p: Profile) -> Result<()> {
        let mut g = self.inner();
        let meta = g.st.as_ref().map(|s| s.secrets.clone()).unwrap_or_default();
        p.validate_with(&policy::public_fn(&meta))?;
        if p.exec.is_some() && !self.opt.allow_exec {
            return Err(Error::ExecOff);
        }
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        let r = policy::resolve(&p, &st.connections)?;
        r.validate_with(&policy::public_fn(&meta))?;
        fields::check_refs(&action_of(&r).secrets(), &meta)?;
        self.log(
            "profile_put",
            "web",
            json!({"name": p.name, "risk": p.risk}),
        );
        st.profiles.insert(p.name.clone(), p);
        self.save_locked(&mut g)
    }

    pub fn delete_profile(&self, name: &str) -> Result<()> {
        let mut g = self.inner();
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        st.profiles.remove(name);
        self.log("profile_delete", "web", json!({"name": name}));
        self.save_locked(&mut g)
    }

    /// The owner's notes for every secret.
    pub fn secret_metas(&self) -> Result<BTreeMap<String, SecretMeta>> {
        let g = self.inner();
        Ok(g.st.as_ref().ok_or(Error::Locked)?.secrets.clone())
    }

    /// Sets the notes of a secret. An empty field list keeps the stored one;
    /// the field names themselves change only with the value
    /// (`put_secret_fields`), so only `public` can be toggled here.
    pub fn set_secret_meta(&self, name: &str, mut m: SecretMeta) -> Result<()> {
        m.validate()?;
        let mut g = self.inner();
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        let old = st
            .secrets
            .get(name)
            .map(|x| x.fields.clone())
            .unwrap_or_default();
        if m.fields.is_empty() {
            m.fields = old;
        } else {
            let mut a: Vec<&str> = m.fields.iter().map(|f| f.name.as_str()).collect();
            let mut b: Vec<&str> = old.iter().map(|f| f.name.as_str()).collect();
            a.sort_unstable();
            b.sort_unstable();
            if a != b {
                return Err(Error::Msg(
                    "the field list changes only together with the values".into(),
                ));
            }
        }
        let hosts = if m.hosts.is_empty() {
            Value::Null
        } else {
            json!(m.hosts)
        };
        self.log(
            "secret_meta",
            "web",
            json!({"name": name, "hosts": hosts, "commands": m.allow_commands,
                "totp": if m.totp.is_empty() { Value::Null } else { json!(m.totp) },
                "workspace": if m.workspace.is_empty() { Value::Null } else { json!(m.workspace) }}),
        );
        st.secrets.insert(name.to_string(), m);
        self.save_locked(&mut g)
    }

    pub fn delete_secret_meta(&self, name: &str) -> Result<()> {
        let mut g = self.inner();
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        st.secrets.remove(name);
        self.save_locked(&mut g)
    }

    pub fn connections(&self) -> Result<Vec<Connection>> {
        let g = self.inner();
        let st = g.st.as_ref().ok_or(Error::Locked)?;
        let mut out: Vec<Connection> = st.connections.values().cloned().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Saves a connection. Every profile that uses it must still be valid
    /// afterwards, or nothing changes.
    pub fn put_connection(&self, x: Connection) -> Result<()> {
        x.validate()?;
        let mut g = self.inner();
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        let mut next = st.connections.clone();
        next.insert(x.name.clone(), x.clone());
        for p in st.profiles.values() {
            if p.connection != x.name {
                continue;
            }
            let r = policy::resolve(p, &next)
                .and_then(|r| r.validate_with(&policy::public_fn(&st.secrets)));
            if let Err(e) = r {
                return Err(Error::Msg(format!(
                    "profile {} would break: {e}",
                    gourl::quote(&p.name)
                )));
            }
        }
        st.connections = next;
        self.log(
            "connection_put",
            "web",
            json!({"name": x.name, "base_url": x.base_url, "auth": x.auth.kind}),
        );
        self.save_locked(&mut g)
    }

    pub fn delete_connection(&self, name: &str) -> Result<()> {
        let mut g = self.inner();
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        let mut users: Vec<&str> = st
            .profiles
            .values()
            .filter(|p| p.connection == name)
            .map(|p| p.name.as_str())
            .collect();
        if !users.is_empty() {
            users.sort_unstable();
            return Err(Error::Msg(format!(
                "connection is used by: {}",
                users.join(", ")
            )));
        }
        st.connections.remove(name);
        self.log("connection_delete", "web", json!({"name": name}));
        self.save_locked(&mut g)
    }

    /// Tokens without their hashes, newest first.
    pub fn tokens(&self) -> Result<Vec<Token>> {
        let g = self.inner();
        let st = g.st.as_ref().ok_or(Error::Locked)?;
        let created = |t: &Token| {
            OffsetDateTime::parse(&t.created, &time::format_description::well_known::Rfc3339).ok()
        };
        let mut out: Vec<Token> = st
            .tokens
            .values()
            .map(|t| Token {
                hash: String::new(),
                ..t.clone()
            })
            .collect();
        out.sort_by_key(|t| std::cmp::Reverse(created(t)));
        Ok(out)
    }

    /// Returns the value once; only its hash is kept.
    pub fn create_token(&self, name: &str, profiles: Vec<String>) -> Result<String> {
        self.create_token_in(name, profiles, vec![])
    }

    /// Like `create_token`, limited to the secrets of some workspaces.
    pub fn create_token_in(
        &self,
        name: &str,
        profiles: Vec<String>,
        mut workspaces: Vec<String>,
    ) -> Result<String> {
        for w in &workspaces {
            policy::valid_workspace(w)?;
        }
        workspaces.sort();
        workspaces.dedup();
        let name = name.trim();
        if name.is_empty() || name.len() > 64 {
            return Err(Error::Msg("tên token không hợp lệ".into()));
        }
        let mut g = self.inner();
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        if st.tokens.values().any(|t| t.name == name) {
            // the name is the caller identity
            return Err(Error::Msg("tên token đã tồn tại".into()));
        }
        let val = format!("ucr_{}", rand_hex(32));
        let id = rand_hex(4);
        st.tokens.insert(
            id.clone(),
            Token {
                id: id.clone(),
                name: name.to_string(),
                hash: hex::encode(Sha256::digest(val.as_bytes())),
                profiles,
                workspaces: workspaces.clone(),
                created: rfc3339_nano(self.now()),
            },
        );
        let mut f = json!({"id": id, "name": name});
        if !workspaces.is_empty() {
            f["workspaces"] = json!(workspaces);
        }
        self.log("token_create", "web", f);
        self.save_locked(&mut g)?;
        Ok(val)
    }

    pub fn revoke_token(&self, id: &str) -> Result<()> {
        let mut g = self.inner();
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        st.tokens.remove(id);
        self.log("token_revoke", "web", json!({"id": id}));
        self.save_locked(&mut g)
    }

    /// Resolves a bearer token to its record.
    pub fn authenticate(&self, val: &str) -> Result<Token> {
        let h = hex::encode(Sha256::digest(val.as_bytes()));
        let g = self.inner();
        let st = g.st.as_ref().ok_or(Error::Locked)?;
        st.tokens
            .values()
            .find(|t| bool::from(t.hash.as_bytes().ct_eq(h.as_bytes())))
            .cloned()
            .ok_or(Error::Forbidden)
    }

    /// What a token may see, without templates or hosts.
    pub fn profiles_for(&self, t: &Token) -> Result<Vec<Profile>> {
        let (meta, conns) = {
            let g = self.inner();
            let st = g.st.as_ref().ok_or(Error::Locked)?;
            (st.secrets.clone(), st.connections.clone())
        };
        Ok(self
            .profiles()?
            .into_iter()
            .filter(|p| allowed(t, &p.name))
            .filter(|p| {
                let full = policy::resolve(p, &conns).unwrap_or_else(|_| p.clone());
                profile_secrets(&full).iter().all(|n| in_scope(t, n, &meta))
            })
            .map(|p| Profile {
                name: p.name,
                description: p.description,
                risk: p.risk,
                params: p.params,
                auto_approve: p.auto_approve,
                ..Default::default()
            })
            .collect())
    }

    // --- Requests ---

    /// Validates a request and either starts it or queues it for approval.
    pub fn submit(
        &self,
        t: &Token,
        profile: &str,
        params: BTreeMap<String, String>,
        reason: &str,
    ) -> Result<Request> {
        self.submit_from(t, &ClientInfo::default(), profile, params, reason)
    }

    /// Like `submit`, recording the device and agent software for the run log.
    pub fn submit_from(
        &self,
        t: &Token,
        client: &ClientInfo,
        profile: &str,
        params: BTreeMap<String, String>,
        reason: &str,
    ) -> Result<Request> {
        let mut g = self.inner();
        self.submit_locked(&mut g, t, client, profile, params, reason, true)
    }

    /// Lets the signed-in owner run a profile at once. The owner is the
    /// approver, so there is no Telegram message; high risk still needs TOTP.
    /// Waits for the result.
    pub async fn test_run(
        &self,
        profile: &str,
        params: BTreeMap<String, String>,
        code: &str,
        secret: &str,
    ) -> Result<Request> {
        let web = Token {
            name: "web".into(),
            ..Default::default()
        };
        let r = {
            let mut g = self.inner();
            let client = ClientInfo::new("", "web");
            self.submit_locked(
                &mut g,
                &web,
                &client,
                profile,
                params,
                "chạy thử từ web",
                false,
            )?
        };
        if r.state == ReqState::Pending
            && let Err(e) = self.decide(&r.id, &r.hash, true, "web", code, secret)
        {
            let mut g = self.inner();
            if g.reqs.get(&r.id).map(|e| e.req.state) == Some(ReqState::Pending) {
                self.finish_locked(&mut g, &r.id, ReqState::Denied, "web");
            }
            return Err(e);
        }
        Ok(self.wait(&r.id, None).await.unwrap_or(r))
    }

    #[allow(clippy::too_many_arguments)]
    fn submit_locked(
        &self,
        g: &mut Inner,
        t: &Token,
        client: &ClientInfo,
        profile: &str,
        params: BTreeMap<String, String>,
        reason: &str,
        notify: bool,
    ) -> Result<Request> {
        let st = g.st.as_ref().ok_or(Error::Locked)?;
        if !allowed(t, profile) {
            self.log("request_forbidden", &t.name, json!({"profile": profile}));
            return Err(Error::Forbidden);
        }
        let stored = st.profiles.get(profile).ok_or(Error::NotFound)?;
        if stored.exec.is_some() && !self.opt.allow_exec {
            return Err(Error::ExecOff);
        }
        let p = policy::resolve(stored, &st.connections)?;
        if !profile_secrets(&p)
            .iter()
            .all(|n| in_scope(t, n, &st.secrets))
        {
            self.log(
                "request_forbidden",
                &t.name,
                json!({"profile": profile, "why": "workspace"}),
            );
            return Err(Error::Forbidden);
        }
        let a = p.render(&params)?;
        fields::check_refs(&a.secrets(), &st.secrets)?;
        self.enqueue_locked(g, t, client, profile, params, p, a, reason, notify)
    }

    /// Queues a request the agent wrote itself. Only tokens without a profile
    /// limit may do this, because a limited token was meant to be narrow.
    pub fn submit_call(&self, t: &Token, call: &Call, reason: &str) -> Result<Request> {
        self.submit_call_from(t, &ClientInfo::default(), call, reason)
    }

    /// Like `submit_call`, recording the device and agent software.
    pub fn submit_call_from(
        &self,
        t: &Token,
        client: &ClientInfo,
        call: &Call,
        reason: &str,
    ) -> Result<Request> {
        let mut g = self.inner();
        let st = g.st.as_ref().ok_or(Error::Locked)?;
        if !t.profiles.is_empty() {
            self.log(
                "request_forbidden",
                &t.name,
                json!({"profile": policy::ADHOC_PROFILE}),
            );
            return Err(Error::Forbidden);
        }
        if call.exec.is_some() && !self.opt.allow_exec {
            return Err(Error::ExecOff);
        }
        // Secrets outside the token's workspaces do not exist for it.
        let mut meta = BTreeMap::new();
        if let Ok(l) = self.vault.list() {
            for m in l {
                if let Some(x) = st.secrets.get(&m.name)
                    && (t.workspaces.is_empty() || t.workspaces.contains(&x.workspace))
                {
                    meta.insert(m.name, x.clone());
                }
            }
        }
        let p = policy::from_call(call, &meta)?;
        let a = p.render(&BTreeMap::new())?;
        self.enqueue_locked(
            &mut g,
            t,
            client,
            policy::ADHOC_PROFILE,
            BTreeMap::new(),
            p,
            a,
            reason,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn enqueue_locked(
        &self,
        g: &mut Inner,
        t: &Token,
        client: &ClientInfo,
        profile: &str,
        params: BTreeMap<String, String>,
        p: Profile,
        a: Action,
        reason: &str,
        notify: bool,
    ) -> Result<Request> {
        let pending = g
            .reqs
            .values()
            .filter(|e| e.req.state == ReqState::Pending && e.req.caller == t.name)
            .count();
        if pending >= MAX_PENDING {
            return Err(Error::Busy);
        }
        let now = self.now();
        let mut kept: Vec<SystemTime> = g
            .recent
            .get(&t.name)
            .map(|v| {
                v.iter()
                    .copied()
                    .filter(|at| now.duration_since(*at).map_or(true, |d| d < RATE_WINDOW))
                    .collect()
            })
            .unwrap_or_default();
        if kept.len() >= RATE_MAX {
            g.recent.insert(t.name.clone(), kept);
            return Err(Error::Busy); // floods train a human to approve without reading
        }
        kept.push(now);
        g.recent.insert(t.name.clone(), kept);
        let req = Request {
            id: rand_hex(6),
            profile: profile.to_string(),
            params,
            caller: t.name.clone(),
            reason: clean_reason(reason),
            risk: p.risk.clone(),
            totp: {
                let mut names = a.secrets();
                names.extend(p.secret_choices.iter().cloned());
                let meta = g.st.as_ref().map(|s| &s.secrets);
                meta.is_some_and(|m| policy::needs_totp(&p.risk, &names, m))
            },
            hash: policy::hash(&p, &a, &t.name),
            display: a.display(),
            state: ReqState::Pending,
            device: client.device.clone(),
            app: client.app.clone(),
            duration_ms: None,
            created: now,
            expires: now + self.opt.approval_ttl,
            decided_by: String::new(),
            choices: p.secret_choices.clone(),
            secret: String::new(),
            result: None,
        };
        let id = req.id.clone();
        let (done, _) = watch::channel(false);
        g.reqs.insert(
            id.clone(),
            Entry {
                req: req.clone(),
                action: a,
                done,
            },
        );
        g.order.push_back(id.clone());
        self.trim_locked(g);
        // Nothing runs unless it was recorded first.
        let params = if req.params.is_empty() {
            Value::Null
        } else {
            json!(req.params)
        };
        let mut f = json!({"id": id, "profile": profile, "params": params, "hash": req.hash, "reason": req.reason});
        if !req.device.is_empty() {
            f["device"] = json!(req.device);
        }
        if !req.app.is_empty() {
            f["app"] = json!(req.app);
        }
        if let Err(e) = self.audit.append("request", &t.name, obj(f)) {
            eprintln!("ERROR audit append: {e}");
            self.finish_locked(g, &id, ReqState::Failed, "audit");
            return Err(Error::Msg("cannot record the request".into()));
        }
        // A secret that always needs TOTP also stops auto approval.
        if p.auto_approve && !req.totp {
            self.start_locked(g, &id, "auto");
            return Ok(g.reqs[&id].req.clone());
        }
        let paired = g.st.as_ref().is_some_and(|s| s.telegram.user_id != 0);
        if let (true, true, Some(bot)) = (notify, paired, g.bot.clone()) {
            let text = lang::approval_text(&req, self.vi());
            let (short, choices) = (req.hash[..16].to_string(), req.choices.clone());
            let me = self.me.clone();
            let id = id.clone();
            self.rt.spawn(async move {
                if let Err(e) = bot.notify(&id, &short, &text, &choices).await {
                    eprintln!("WARN telegram notify: {e}");
                    if let Some(c) = me.upgrade() {
                        c.log("notify_failed", "telegram", json!({"id": id}));
                    }
                }
            });
        }
        Ok(req)
    }

    fn trim_locked(&self, g: &mut Inner) {
        while g.order.len() > MAX_HISTORY {
            let id = g.order[0].clone();
            if g.reqs.get(&id).is_some_and(|e| !e.req.state.is_final()) {
                break;
            }
            g.order.pop_front();
            g.reqs.remove(&id);
        }
    }

    fn finish_locked(&self, g: &mut Inner, id: &str, s: ReqState, by: &str) {
        let Some(e) = g.reqs.get_mut(id) else { return };
        e.req.state = s;
        e.req.decided_by = by.to_string();
        e.done.send_replace(true);
        let req = e.req.clone();
        self.log(
            &format!("request_{}", s.as_str()),
            by,
            json!({"id": req.id, "hash": req.hash}),
        );
        if let Some(bot) = g.bot.clone() {
            let text = lang::finish_text(&req, self.vi());
            self.rt
                .spawn(async move { bot.finish(&req.id, &text).await });
        }
    }

    pub fn needs_totp(&self, id: &str) -> bool {
        self.inner().reqs.get(id).is_some_and(|e| e.req.totp)
    }

    /// Maps a Telegram button index to a secret name.
    pub fn secret_at(&self, id: &str, i: usize) -> Option<String> {
        self.inner()
            .reqs
            .get(id)
            .and_then(|e| e.req.choices.get(i).cloned())
    }

    /// Applies one human decision. `hash` may be a prefix of at least 16 hex
    /// characters, because Telegram callback data is limited to 64 bytes.
    pub fn decide(
        &self,
        id: &str,
        hash: &str,
        approve: bool,
        actor: &str,
        code: &str,
        secret: &str,
    ) -> Result<String> {
        let mut g = self.inner();
        let Some(e) = g.reqs.get(id) else {
            return Err(Error::Decided);
        };
        if hash.len() < 16 || !e.req.hash.starts_with(hash) {
            self.log("decide_hash_mismatch", actor, json!({"id": id}));
            return Err(Error::HashChange);
        }
        if e.req.state != ReqState::Pending || self.now() >= e.req.expires {
            return Err(Error::Decided);
        }
        if !approve {
            self.finish_locked(&mut g, id, ReqState::Denied, actor);
            return Ok("Đã từ chối".into());
        }
        let (choices, need_totp) = (e.req.choices.clone(), e.req.totp);
        if !choices.is_empty() {
            if !choices.iter().any(|n| n == secret) {
                return Err(Error::Msg("hãy chọn một secret trong danh sách".into()));
            }
            match self.vault.get(secret) {
                Err(_) => {
                    return Err(Error::Msg(format!(
                        "kho chưa có secret {}",
                        gourl::quote(secret)
                    )));
                }
                Ok(v) if fields::parse(&v).is_some() => {
                    return Err(Error::Msg(format!(
                        "secret {} has fields, use {{{{secret:{secret}.FIELD}}}}",
                        gourl::quote(secret)
                    )));
                }
                Ok(_) => {}
            }
        }
        if need_totp {
            if !g.st.as_ref().is_some_and(|s| s.totp_enabled) {
                return Err(Error::Msg(
                    "chưa bật TOTP nên chưa duyệt được yêu cầu rủi ro cao".into(),
                ));
            }
            if let Err(err) = self.check_totp_locked(&mut g, code) {
                self.log("decide_totp_failed", actor, json!({"id": id}));
                return Err(err);
            }
        }
        if !choices.is_empty() {
            if let Some(e) = g.reqs.get_mut(id) {
                e.action = e.action.with_choice(secret);
                e.req.secret = secret.to_string();
            }
            self.log("secret_chosen", actor, json!({"id": id, "secret": secret}));
        }
        self.start_locked(&mut g, id, actor);
        Ok("Đã duyệt".into())
    }

    fn start_locked(&self, g: &mut Inner, id: &str, by: &str) {
        let Some(e) = g.reqs.get_mut(id) else { return };
        e.req.state = ReqState::Running;
        e.req.decided_by = by.to_string();
        let (hash, action) = (e.req.hash.clone(), e.action.clone());
        self.log("request_approved", by, json!({"id": id, "hash": hash}));
        if let Some(c) = self.me.upgrade() {
            let id = id.to_string();
            self.rt.spawn(async move { c.execute(id, action).await });
        }
    }

    async fn execute(&self, id: String, action: Action) {
        let meta = self
            .inner()
            .st
            .as_ref()
            .map(|s| s.secrets.clone())
            .unwrap_or_default();
        let refs = action.secrets();
        let is_public = policy::public_fn(&meta);
        let public = refs.iter().filter(|r| is_public(r)).cloned().collect();
        let vault = &self.vault;
        let get = |n: &str| fields::resolve(vault, n);
        let mut stop = self.shutdown.subscribe();
        let started = Instant::now();
        let mut res = tokio::select! {
            r = policy::run_with(&action, get, &public) => r,
            _ = stop.wait_for(|v| *v) => RunResult { ok: false, exit: -1, output: "context canceled".into() },
        };
        let extra = fields::private_values(vault, &refs, &meta);
        if !extra.is_empty() {
            let list: Vec<&[u8]> = extra.iter().map(|v| v.as_bytes()).collect();
            res.output = policy::redact(&res.output, &list);
        }
        let ms = started.elapsed().as_millis() as u64;
        let mut g = self.inner();
        let Some(e) = g.reqs.get_mut(&id) else { return };
        e.req.result = Some(res.clone());
        e.req.duration_ms = Some(ms);
        let by = e.req.decided_by.clone();
        let run = run_fields(&e.req, &refs);
        let s = if res.ok {
            ReqState::Done
        } else {
            ReqState::Failed
        };
        self.finish_locked(&mut g, &id, s, &by);
        let sum = Sha256::digest(res.output.as_bytes());
        let mut f = json!({"id": id, "exit": res.exit, "bytes": res.output.len(),
            "sha256": hex::encode(&sum[..8]), "ok": res.ok, "duration_ms": ms});
        if let (Some(m), Value::Object(r)) = (f.as_object_mut(), run) {
            m.extend(r);
        }
        self.log("result", &by, f);
    }

    /// Denies overdue requests; silence is never approval.
    pub fn expire_now(&self) {
        let mut g = self.inner();
        let now = self.now();
        let due: Vec<String> = g
            .reqs
            .iter()
            .filter(|(_, e)| e.req.state == ReqState::Pending && now >= e.req.expires)
            .map(|(id, _)| id.clone())
            .collect();
        for id in due {
            self.finish_locked(&mut g, &id, ReqState::Expired, "ttl");
        }
    }

    /// A snapshot of one request.
    pub fn get(&self, id: &str) -> Option<Request> {
        self.inner().reqs.get(id).map(|e| e.req.clone())
    }

    /// Waits until the request is final or `timeout` passes (None waits
    /// without limit), then returns a snapshot.
    pub async fn wait(&self, id: &str, timeout: Option<Duration>) -> Option<Request> {
        let mut rx = self.inner().reqs.get(id)?.done.subscribe();
        let done = async move {
            let _ = rx.wait_for(|v| *v).await;
        };
        match timeout {
            Some(d) => {
                let _ = tokio::time::timeout(d, done).await;
            }
            None => done.await,
        }
        self.get(id)
    }

    /// All kept requests, newest first.
    pub fn requests(&self) -> Vec<Request> {
        let g = self.inner();
        g.order
            .iter()
            .rev()
            .filter_map(|id| g.reqs.get(id).map(|e| e.req.clone()))
            .collect()
    }

    /// Validates a draft and renders it with sample values, using the same
    /// code path as a real request. It runs nothing.
    pub fn preview(&self, p: &Profile, sample: &BTreeMap<String, String>) -> Preview {
        let mut out = Preview::default();
        let (meta, conns) = {
            let g = self.inner();
            g.st.as_ref()
                .map(|s| (s.secrets.clone(), s.connections.clone()))
                .unwrap_or_default()
        };
        let public = policy::public_fn(&meta);
        if let Err(e) = p.validate_with(&public) {
            out.error = e.to_string();
            return out;
        }
        let p = match policy::resolve(p, &conns) {
            Ok(r) => r,
            Err(e) => {
                out.error = e.to_string();
                return out;
            }
        };
        if p.exec.is_some() && !self.opt.allow_exec {
            out.error = Error::ExecOff.to_string();
            return out;
        }
        out.warnings.extend(p.lint());
        let a = match p.render(sample) {
            Ok(a) => a,
            Err(e) => {
                out.error = e.to_string();
                return out;
            }
        };
        out.display = a.display();
        if let Err(e) = fields::check_refs(&a.secrets(), &meta) {
            out.error = e.to_string();
            return out;
        }
        let have: Vec<String> = self
            .vault
            .list()
            .map(|l| l.into_iter().map(|m| m.name).collect())
            .unwrap_or_default();
        let known = |n: &str| have.iter().any(|h| h == n);
        for n in a.secrets() {
            let found = known(&n) || n.rsplit_once('.').is_some_and(|(s, _)| known(s));
            if !found {
                out.warnings.push(format!(
                    "Chưa có secret \"{n}\" trong kho, lệnh sẽ không chạy được."
                ));
            }
        }
        out
    }

    /// Returns `s` in the configured language.
    pub fn translate(&self, s: &str) -> String {
        lang::translate(self.vi(), s)
    }
}
