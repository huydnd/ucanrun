//! The human UI and the agent API on separate listeners (port of
//! `internal/web`), so that the UI can be published without exposing the
//! agent port.

mod strict;

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, delete, get, post, put};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rand::RngCore;
use rust_embed::RustEmbed;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::audit;
use crate::core::{self, Core, FieldInfo, HealthItem, Token};
use crate::policy::{Call, Connection, FieldMeta, Profile, SecretMeta};
use crate::vault;

pub const COOKIE_NAME: &str = "ucr_session";
pub const GATE_COOKIE: &str = "ucr_gate";
const SESSION_IDLE: Duration = Duration::from_secs(30 * 60);
const SESSION_MAX: Duration = Duration::from_secs(12 * 3600);
const GATE_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);
const MAX_BODY: usize = 256 << 10;
const MAX_GATE_BODY: usize = 4096;
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(130);

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
/// The UI needs none of these browser features.
const PERMISSIONS: &str = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), \
    serial=(), bluetooth=()";
const GATE_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

#[derive(RustEmbed)]
#[folder = "web/static"]
pub(crate) struct Static;

static GATE_PAGE: &[u8] = include_bytes!("../../web/gate.html");

struct Session {
    created: Instant,
    seen: Instant,
}

#[derive(Default)]
struct Backoff {
    fails: u32,
    blocked: Option<Instant>,
}

impl Backoff {
    fn throttled(&self) -> bool {
        self.blocked.is_some_and(|b| Instant::now() < b)
    }

    fn record(&mut self, ok: bool) {
        if ok {
            *self = Backoff::default();
            return;
        }
        self.fails += 1;
        if self.fails >= 3 {
            let d = Duration::from_secs(1 << (self.fails - 3).min(6));
            self.blocked = Some(Instant::now() + d);
        }
    }
}

#[derive(Default)]
struct Guard {
    sessions: HashMap<String, Session>,
    /// Password and TOTP checks.
    login: Backoff,
    /// The access gate. Kept apart so a stranger guessing the gate code
    /// cannot lock the owner, who already has the gate cookie, out of login.
    gate: Backoff,
}

/// Shared state of both routers. Set the public fields before wrapping it in
/// an `Arc`.
pub struct Server {
    pub core: Arc<Core>,
    pub secure_cookie: bool,
    pub setup_token: String,
    pub audit_path: PathBuf,
    /// Empty turns the access gate off.
    pub gate_token: String,
    mu: Mutex<Guard>,
}

fn hash_tok(t: &str) -> String {
    hex::encode(Sha256::digest(t.as_bytes()))
}

/// Go's json.Encoder output: HTML characters and line separators escaped,
/// newline at the end. These characters only occur inside strings.
fn go_json<T: Serialize>(v: &T) -> String {
    let s = serde_json::to_string(v).unwrap_or_else(|_| "null".into());
    let mut out = String::with_capacity(s.len() + 1);
    for c in s.chars() {
        match c {
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('\n');
    out
}

fn write_json<T: Serialize>(code: u16, v: &T) -> Response {
    let code = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST);
    (
        code,
        [(header::CONTENT_TYPE, "application/json")],
        go_json(v),
    )
        .into_response()
}

fn err_json(code: u16, msg: &str) -> Response {
    write_json(code, &json!({"error": msg}))
}

fn fail(e: core::Error) -> Response {
    err_json(e.status(), &e.to_string())
}

/// Errors for agents carry a stable `code` and, when only the human can fix
/// it, `ask_human`. `error` keeps the message, as before.
fn agent_fail(e: core::Error) -> Response {
    let (code, ask) = e.agent_code();
    let mut v = json!({"error": e.to_string(), "code": code});
    if let Some(a) = ask {
        v["ask_human"] = json!(a);
    }
    write_json(e.status(), &v)
}

macro_rules! trya {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return agent_fail(e.into()),
        }
    };
}

fn ok_json() -> Response {
    write_json(200, &json!({"ok": true}))
}

fn text(code: StatusCode, body: &'static str) -> Response {
    (
        code,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response()
}

fn not_found() -> Response {
    text(StatusCode::NOT_FOUND, "404 page not found\n")
}

fn not_allowed() -> Response {
    text(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed\n")
}

/// Reads a JSON body the way the Go server does: at most 256 KiB, the first
/// value only, and no unknown fields.
async fn read<T: DeserializeOwned>(body: Body) -> Result<T, Box<Response>> {
    let bad = || Box::new(err_json(400, "JSON không hợp lệ"));
    let b = match tokio::time::timeout(READ_TIMEOUT, axum::body::to_bytes(body, MAX_BODY)).await {
        Ok(Ok(b)) => b,
        _ => return Err(bad()),
    };
    let v: Value = match serde_json::Deserializer::from_slice(&b)
        .into_iter::<Value>()
        .next()
    {
        Some(Ok(v)) => v,
        _ => return Err(bad()),
    };
    strict::from_value(&v).map_err(|_| bad())
}

fn header_str<'a>(h: &'a HeaderMap, k: &str) -> &'a str {
    h.get(k).and_then(|v| v.to_str().ok()).unwrap_or("")
}

fn cookie(h: &HeaderMap, name: &str) -> Option<String> {
    for v in h.get_all(header::COOKIE) {
        let Ok(s) = v.to_str() else { continue };
        for part in s.split(';') {
            if let Some((k, v)) = part.trim().split_once('=')
                && k == name
            {
                return Some(v.trim_matches('"').to_string());
            }
        }
    }
    None
}

fn set_cookie(r: &mut Response, c: String) {
    if let Ok(v) = HeaderValue::from_str(&c) {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
}

fn gate_value(tok: &str) -> String {
    hex::encode(Sha256::digest(format!("ucanrun gate v1:{tok}").as_bytes()))
}

/// Returns the access code. An explicit value wins, otherwise a code is
/// created once in the data directory, so that a default install is gated
/// without any configuration. The flag reports a new code.
pub fn load_gate_token(dir: &FsPath, explicit: &str) -> std::io::Result<(String, bool)> {
    if !explicit.is_empty() {
        return Ok((explicit.to_string(), false));
    }
    let path = dir.join("gate.token");
    match std::fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => return Ok((s.trim().to_string(), false)),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut b = [0u8; 18];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let t = URL_SAFE_NO_PAD.encode(b);
    vault::atomic_write(&path, format!("{t}\n").as_bytes()).map_err(|e| match e {
        vault::Error::Io(e) => e,
        e => std::io::Error::other(e.to_string()),
    })?;
    Ok((t, true))
}

fn rfc3339_nano(t: std::time::SystemTime) -> String {
    let t = time::OffsetDateTime::from(t);
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

fn mime_of(path: &str) -> String {
    let ext = path.rsplit_once('.').map_or("", |(_, e)| e);
    match ext {
        "html" => "text/html; charset=utf-8".into(),
        "js" => "text/javascript; charset=utf-8".into(),
        "css" => "text/css; charset=utf-8".into(),
        "json" => "application/json".into(),
        "svg" => "image/svg+xml".into(),
        "png" => "image/png".into(),
        "webmanifest" => "application/manifest+json".into(),
        _ => mime_guess::from_path(path)
            .first_or_octet_stream()
            .to_string(),
    }
}

/// The embedded files, served like Go's http.FileServerFS.
fn serve_static(path: &str) -> Response {
    if path == "/index.html" {
        return (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, "./")]).into_response();
    }
    let name = match path.strip_prefix('/').unwrap_or(path) {
        "" => "index.html",
        p => p,
    };
    match Static::get(name) {
        Some(f) => (
            [(header::CONTENT_TYPE, mime_of(name))],
            Body::from(f.data.into_owned()),
        )
            .into_response(),
        None => not_found(),
    }
}

/// What Go's mux does with a path no pattern serves for this method: every
/// GET falls through to the file server, anything else is not allowed.
async fn unrouted(method: Method, uri: axum::http::Uri) -> Response {
    if method == Method::GET || method == Method::HEAD {
        serve_static(uri.path())
    } else {
        not_allowed()
    }
}

fn ui(m: MethodRouter<Arc<Server>>) -> MethodRouter<Arc<Server>> {
    m.fallback(unrouted)
}

macro_rules! need_auth {
    ($s:expr, $h:expr) => {
        if let Some(r) = $s.deny_anon(&$h) {
            return r;
        }
    };
}

macro_rules! body {
    ($b:expr) => {
        match read($b).await {
            Ok(v) => v,
            Err(r) => return *r,
        }
    };
}

macro_rules! tryf {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return fail(e.into()),
        }
    };
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f)
        .await
        .expect("blocking task panicked")
}

impl Server {
    pub fn new(core: Arc<Core>, setup_token: &str, audit_path: PathBuf, secure: bool) -> Server {
        Server {
            core,
            secure_cookie: secure,
            setup_token: setup_token.to_string(),
            audit_path,
            gate_token: String::new(),
            mu: Mutex::new(Guard::default()),
        }
    }

    fn guard(&self) -> MutexGuard<'_, Guard> {
        self.mu.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn cookie_attrs(&self, max_age: Duration, same_site: &str) -> String {
        let secure = if self.secure_cookie { "; Secure" } else { "" };
        format!(
            "Path=/; Max-Age={}; HttpOnly{secure}; SameSite={same_site}",
            max_age.as_secs()
        )
    }

    fn new_session(&self) -> String {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        let tok = URL_SAFE_NO_PAD.encode(b);
        let now = Instant::now();
        self.guard().sessions.insert(
            hash_tok(&tok),
            Session {
                created: now,
                seen: now,
            },
        );
        format!(
            "{COOKIE_NAME}={tok}; {}",
            self.cookie_attrs(SESSION_MAX, "Strict")
        )
    }

    fn authed(&self, h: &HeaderMap) -> bool {
        let Some(c) = cookie(h, COOKIE_NAME) else {
            return false;
        };
        let k = hash_tok(&c);
        let mut g = self.guard();
        let Some(se) = g.sessions.get_mut(&k) else {
            return false;
        };
        let now = Instant::now();
        if now.duration_since(se.seen) > SESSION_IDLE
            || now.duration_since(se.created) > SESSION_MAX
        {
            g.sessions.remove(&k);
            return false;
        }
        se.seen = now;
        drop(g);
        self.core.touch();
        true
    }

    fn deny_anon(&self, h: &HeaderMap) -> Option<Response> {
        if !self.authed(h) || self.core.locked() {
            return Some(err_json(401, "chưa đăng nhập"));
        }
        None
    }

    fn clear_sessions(&self) {
        self.guard().sessions.clear();
    }

    /// One global backoff per door, because behind a proxy every client
    /// shares an address and the attacker controls forwarded headers.
    fn throttled(&self) -> bool {
        self.guard().login.throttled()
    }

    fn record_login(&self, ok: bool) {
        self.guard().login.record(ok);
    }

    fn gate_throttled(&self) -> bool {
        self.guard().gate.throttled()
    }

    fn record_gate(&self, ok: bool) {
        self.guard().gate.record(ok);
    }

    fn gate_open(&self, h: &HeaderMap) -> bool {
        cookie(h, GATE_COOKIE).is_some_and(|c| {
            bool::from(c.as_bytes().ct_eq(gate_value(&self.gate_token).as_bytes()))
        })
    }

    /// The human UI.
    pub fn handler(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/healthz", ui(get(healthz)))
            .route("/api/status", ui(get(status)))
            .route("/api/setup", ui(post(setup)))
            .route("/api/login", ui(post(login)))
            .route("/api/logout", ui(post(logout)))
            .route("/api/lock", ui(post(lock)))
            .route("/api/passphrase", ui(post(passphrase)))
            .route("/api/secrets", ui(get(list_secrets)))
            .route(
                "/api/secrets/{name}",
                ui(put(put_secret).delete(delete_secret)),
            )
            .route("/api/profiles", ui(get(profiles).put(put_profile)))
            .route("/api/profiles/preview", ui(post(preview)))
            .route("/api/profiles/{name}/test", ui(post(test_run)))
            .route("/api/profiles/{name}", ui(delete(delete_profile)))
            .route("/api/connections", ui(get(connections).put(put_connection)))
            .route("/api/connections/{name}", ui(delete(delete_connection)))
            .route("/api/tokens", ui(get(tokens).post(create_token)))
            .route("/api/tokens/{id}", ui(delete(revoke_token)))
            .route("/api/requests", ui(get(requests)))
            .route("/api/requests/{id}/decide", ui(post(decide)))
            .route("/api/audit", ui(get(audit_log)))
            .route("/api/health", ui(get(health)))
            .route("/api/telegram", ui(put(set_telegram)))
            .route("/api/telegram/pair", ui(post(pair_code)))
            .route("/api/totp/start", ui(post(totp_start)))
            .route("/api/totp/confirm", ui(post(totp_confirm)))
            .route("/api/totp/recovery", ui(post(totp_recovery)))
            .route("/api/totp/reset", ui(post(totp_reset)))
            .route("/api/runs", ui(get(runs)))
            .route("/api/devices", ui(get(devices)))
            .route("/api/runners", ui(get(runners_list)))
            .route("/api/system", ui(get(system_info)))
            .route("/api/runners/code", ui(post(runner_code)))
            .route("/api/runners/{name}", ui(delete(runner_delete)))
            .route("/api/settings", ui(put(put_settings)))
            .route("/api/templates", ui(get(templates).put(put_template)))
            .route("/api/templates/{id}", ui(delete(delete_template)))
            .fallback(unrouted)
            .layer(middleware::from_fn(csrf))
            .layer(middleware::from_fn_with_state(self.clone(), secure_headers))
            .layer(middleware::from_fn_with_state(self.clone(), gate))
            .layer(middleware::from_fn(write_timeout))
            .with_state(self.clone())
    }

    /// The API for agents. It has no way to read a secret.
    pub fn agent_handler(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/healthz", get(healthz).fallback(not_allowed_h))
            .route("/v1/profiles", get(agent_profiles).fallback(not_allowed_h))
            .route("/v1/secrets", get(agent_secrets).fallback(not_allowed_h))
            .route("/v1/requests", post(agent_submit).fallback(not_allowed_h))
            .route("/v1/requests/{id}", get(agent_get).fallback(not_allowed_h))
            .route("/v1/runners", get(agent_runners).fallback(not_allowed_h))
            .route(
                "/v1/runner/enroll",
                post(runner_enroll).fallback(not_allowed_h),
            )
            .route("/v1/runner/poll", post(runner_poll).fallback(not_allowed_h))
            .route(
                "/v1/runner/result",
                post(runner_result).fallback(not_allowed_h),
            )
            .fallback(not_found_h)
            .layer(middleware::from_fn(agent_headers))
            .layer(middleware::from_fn(write_timeout))
            .with_state(self.clone())
    }

    async fn bearer(&self, h: &HeaderMap) -> Result<Token, Box<Response>> {
        let Some(tok) = header_str(h, "authorization").strip_prefix("Bearer ") else {
            return Err(Box::new(write_json(
                401,
                &json!({"error": "missing token", "code": "missing_token",
                    "ask_human": "Create an agent token on the Agent tokens tab and give it to the agent (ucr login, or UCANRUN_TOKEN)."}),
            )));
        };
        self.core.authenticate(tok).map_err(|e| {
            if matches!(e, core::Error::Forbidden) {
                // An unknown token, not a missing permission.
                return Box::new(write_json(
                    403,
                    &json!({"error": "forbidden", "code": "invalid_token",
                        "ask_human": "This agent token is unknown or revoked. Create a new one on the Agent tokens tab."}),
                ));
            }
            Box::new(agent_fail(e))
        })
    }
}

async fn not_allowed_h() -> Response {
    not_allowed()
}

async fn not_found_h() -> Response {
    not_found()
}

// --- middleware ---

async fn write_timeout(req: Request, next: Next) -> Response {
    match tokio::time::timeout(WRITE_TIMEOUT, next.run(req)).await {
        Ok(r) => r,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn secure_headers(State(s): State<Arc<Server>>, req: Request, next: Next) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    if s.secure_cookie {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(PERMISSIONS),
    );
    r
}

/// The agent API returns request results; no cache should keep them.
async fn agent_headers(req: Request, next: Next) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

/// Blocks cross-site writes: a custom header cannot be sent cross-origin
/// without a CORS preflight, and this server never answers one.
async fn csrf(req: Request, next: Next) -> Response {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        let h = req.headers();
        let site = header_str(h, "sec-fetch-site");
        if header_str(h, "x-ucanrun") != "1" || (!site.is_empty() && site != "same-origin") {
            return err_json(403, "csrf");
        }
    }
    next.run(req).await
}

fn gate_deny(code: StatusCode) -> Response {
    (
        code,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, GATE_CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::CACHE_CONTROL, "no-store"),
            (HeaderName::from_static("permissions-policy"), PERMISSIONS),
        ],
        GATE_PAGE,
    )
        .into_response()
}

/// An outer fence for the public UI. Without the access code nothing answers
/// except the health check, so strangers can neither reach the login form nor
/// learn anything about the vault.
async fn gate(State(s): State<Arc<Server>>, req: Request, next: Next) -> Response {
    if s.gate_token.is_empty() || req.uri().path() == "/healthz" || s.gate_open(req.headers()) {
        return next.run(req).await;
    }
    if req.method() != Method::POST || req.uri().path() != "/gate" {
        return gate_deny(StatusCode::UNAUTHORIZED);
    }
    if s.gate_throttled() {
        return gate_deny(StatusCode::TOO_MANY_REQUESTS);
    }
    let site = header_str(req.headers(), "sec-fetch-site").to_string();
    let form = header_str(req.headers(), "content-type")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/x-www-form-urlencoded");
    let body = tokio::time::timeout(
        READ_TIMEOUT,
        axum::body::to_bytes(req.into_body(), MAX_GATE_BODY),
    )
    .await;
    let code = match body {
        Ok(Ok(b)) if form => url::form_urlencoded::parse(&b)
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default(),
        _ => String::new(),
    };
    if !site.is_empty() && site != "same-origin" {
        return gate_deny(StatusCode::FORBIDDEN);
    }
    let want = gate_value(&s.gate_token);
    if !bool::from(gate_value(&code).as_bytes().ct_eq(want.as_bytes())) {
        s.record_gate(false);
        return gate_deny(StatusCode::UNAUTHORIZED);
    }
    s.record_gate(true);
    let mut r = (StatusCode::SEE_OTHER, [(header::LOCATION, "/")]).into_response();
    set_cookie(
        &mut r,
        format!(
            "{GATE_COOKIE}={want}; {}",
            s.cookie_attrs(GATE_MAX_AGE, "Lax")
        ),
    );
    r
}

// --- UI handlers ---

async fn healthz() -> Response {
    ok_json()
}

async fn status(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    let c = &s.core;
    let authed = s.authed(&h) && !c.locked();
    let mut out = json!({"initialized": c.initialized(), "locked": c.locked(), "authed": authed});
    if authed {
        out["telegram"] = json!(c.telegram_status());
        out["totp"] = json!(c.totp_enabled());
        out["exec"] = json!(c.exec_enabled());
        out["auto_lock_min"] = json!(c.auto_lock_min());
        out["recovery_left"] = json!(c.recovery_left());
    }
    write_json(200, &out)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SetupIn {
    setup_token: String,
    passphrase: String,
}

async fn setup(State(s): State<Arc<Server>>, b: Body) -> Response {
    let input: SetupIn = body!(b);
    if s.core.initialized() {
        return err_json(409, "đã khởi tạo");
    }
    if s.setup_token.is_empty()
        || !bool::from(input.setup_token.as_bytes().ct_eq(s.setup_token.as_bytes()))
    {
        return err_json(403, "sai setup token");
    }
    let c = s.core.clone();
    if let Err(e) = blocking(move || c.setup(input.passphrase.as_bytes())).await {
        return fail(e);
    }
    let mut r = ok_json();
    set_cookie(&mut r, s.new_session());
    r
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LoginIn {
    passphrase: String,
    totp: String,
}

async fn login(State(s): State<Arc<Server>>, b: Body) -> Response {
    let input: LoginIn = body!(b);
    if s.throttled() {
        return err_json(429, "thử lại sau ít giây");
    }
    if input.passphrase.len() > 1024 {
        return err_json(401, "sai thông tin đăng nhập");
    }
    let c = s.core.clone();
    let res = blocking(move || c.login(input.passphrase.as_bytes(), &input.totp)).await;
    match res {
        Err(e @ core::Error::LoginBusy) => fail(e),
        Err(e) => {
            s.record_login(false);
            match e {
                core::Error::StateTooNew => {
                    err_json(409, "dữ liệu tạo bởi bản mới hơn, hãy nâng cấp ucanrun")
                }
                core::Error::Tampered => {
                    err_json(409, "file trạng thái không qua được kiểm tra toàn vẹn")
                }
                _ => err_json(401, "sai thông tin đăng nhập"),
            }
        }
        Ok(()) => {
            s.record_login(true);
            let mut r = ok_json();
            set_cookie(&mut r, s.new_session());
            r
        }
    }
}

async fn logout(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    if let Some(c) = cookie(&h, COOKIE_NAME) {
        s.guard().sessions.remove(&hash_tok(&c));
    }
    ok_json()
}

async fn lock(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    s.core.lock("web");
    s.clear_sessions();
    ok_json()
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PassIn {
    old: String,
    new: String,
}

async fn passphrase(State(s): State<Arc<Server>>, h: HeaderMap, b: Body) -> Response {
    need_auth!(s, h);
    let input: PassIn = body!(b);
    if input.new.len() < core::MIN_PASSPHRASE {
        return err_json(400, "mật khẩu mới quá ngắn");
    }
    let c = s.core.clone();
    let res = blocking(move || {
        c.vault
            .change_passphrase(input.old.as_bytes(), input.new.as_bytes())
    })
    .await;
    if res.is_err() {
        return err_json(400, "mật khẩu cũ không đúng");
    }
    if let Err(e) = s
        .core
        .audit
        .append("passphrase_changed", "web", serde_json::Map::new())
    {
        eprintln!("ERROR audit append: {e}");
    }
    ok_json()
}

#[derive(Serialize)]
struct SecretRow {
    name: String,
    updated: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hosts: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    allow_commands: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<FieldInfo>,
    #[serde(skip_serializing_if = "String::is_empty")]
    totp: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    workspace: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    approve: String,
}

async fn list_secrets(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    let c = s.core.clone();
    let rows = blocking(move || -> core::Result<Vec<SecretRow>> {
        let list = c.vault.list()?;
        let meta = c.secret_metas()?;
        let mut out = Vec::with_capacity(list.len());
        for m in list {
            let x = meta.get(&m.name).cloned().unwrap_or_default();
            let public = if x.fields.iter().any(|f| f.public) {
                c.secret_public_values(&m.name).unwrap_or_default()
            } else {
                BTreeMap::new()
            };
            let fields = x
                .fields
                .iter()
                .map(|f| FieldInfo {
                    name: f.name.clone(),
                    public: f.public,
                    value: if f.public {
                        public.get(&f.name).cloned()
                    } else {
                        None
                    },
                })
                .collect();
            out.push(SecretRow {
                updated: rfc3339_nano(m.updated),
                name: m.name,
                description: x.description,
                hosts: x.hosts,
                allow_commands: x.allow_commands,
                fields,
                totp: x.totp,
                workspace: x.workspace,
                approve: x.approve,
            });
        }
        Ok(out)
    })
    .await;
    match rows {
        Ok(r) => write_json(200, &r),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct FieldIn {
    name: String,
    public: bool,
    value: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PutSecretIn {
    value: String,
    description: String,
    hosts: Vec<String>,
    allow_commands: bool,
    fields: Option<Vec<FieldIn>>,
    workspace: String,
    /// "" asks every time, "auto" runs agent calls without asking.
    approve: String,
    /// "", "always" or "never".
    totp: String,
    /// A current TOTP code, needed to set totp to "never".
    code: String,
}

/// Write-only by design: no endpoint ever returns a private value.
async fn put_secret(
    State(s): State<Arc<Server>>,
    h: HeaderMap,
    Path(name): Path<String>,
    b: Body,
) -> Response {
    need_auth!(s, h);
    if name.starts_with('_') {
        return fail(vault::Error::InvalidName.into());
    }
    let input: PutSecretIn = body!(b);
    let mut meta = SecretMeta {
        description: input.description,
        hosts: input.hosts,
        allow_commands: input.allow_commands,
        fields: vec![],
        totp: input.totp,
        workspace: input.workspace.trim().to_string(),
        approve: input.approve,
    };
    tryf!(meta.validate());
    let c = s.core.clone();
    let res = blocking(move || -> core::Result<Option<Response>> {
        // Checked before anything is written, so a refused change leaves the
        // value untouched too.
        c.authorize_secret_change(&name, &meta.totp, &meta.approve, &input.code)?;
        if let Some(fields) = input.fields {
            meta.fields = fields
                .iter()
                .map(|f| FieldMeta {
                    name: f.name.clone(),
                    public: f.public,
                })
                .collect();
            let values: BTreeMap<String, String> =
                fields.into_iter().map(|f| (f.name, f.value)).collect();
            c.put_secret_fields(&name, meta.clone(), &values)?;
        } else if !input.value.is_empty() {
            // An empty value keeps the stored one, so notes can change alone.
            c.put_secret(&name, input.value.as_bytes())?;
        } else if !c.vault.list()?.iter().any(|m| m.name == name) {
            return Ok(Some(err_json(400, "value is required for a new secret")));
        }
        c.set_secret_meta(&name, meta)?;
        Ok(None)
    })
    .await;
    match res {
        Ok(Some(r)) => r,
        Ok(None) => ok_json(),
        Err(e) => fail(e),
    }
}

async fn delete_secret(
    State(s): State<Arc<Server>>,
    h: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    need_auth!(s, h);
    tryf!(s.core.delete_secret(&name));
    ok_json()
}

async fn profiles(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    write_json(200, &tryf!(s.core.profiles()))
}

async fn put_profile(State(s): State<Arc<Server>>, h: HeaderMap, b: Body) -> Response {
    need_auth!(s, h);
    let p: Profile = body!(b);
    tryf!(s.core.put_profile(p.clone()));
    write_json(200, &p)
}

async fn connections(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    write_json(200, &tryf!(s.core.connections()))
}

async fn put_connection(State(s): State<Arc<Server>>, h: HeaderMap, b: Body) -> Response {
    need_auth!(s, h);
    let x: Connection = body!(b);
    tryf!(s.core.put_connection(x.clone()));
    write_json(200, &x)
}

async fn delete_connection(
    State(s): State<Arc<Server>>,
    h: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    need_auth!(s, h);
    tryf!(s.core.delete_connection(&name));
    ok_json()
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PreviewIn {
    profile: Profile,
    sample: BTreeMap<String, String>,
}

async fn preview(State(s): State<Arc<Server>>, h: HeaderMap, b: Body) -> Response {
    need_auth!(s, h);
    let input: PreviewIn = body!(b);
    let c = s.core.clone();
    let out = blocking(move || c.preview(&input.profile, &input.sample)).await;
    write_json(200, &out)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TestIn {
    params: BTreeMap<String, String>,
    totp: String,
    secret: String,
}

async fn test_run(
    State(s): State<Arc<Server>>,
    h: HeaderMap,
    Path(name): Path<String>,
    b: Body,
) -> Response {
    need_auth!(s, h);
    let input: TestIn = body!(b);
    let run = s
        .core
        .test_run(&name, input.params, &input.totp, &input.secret);
    match tokio::time::timeout(Duration::from_secs(90), run).await {
        Ok(Ok(q)) => write_json(200, &q),
        Ok(Err(e)) => fail(e),
        Err(_) => err_json(400, "context deadline exceeded"),
    }
}

async fn delete_profile(
    State(s): State<Arc<Server>>,
    h: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    need_auth!(s, h);
    tryf!(s.core.delete_profile(&name));
    ok_json()
}

async fn tokens(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    write_json(200, &tryf!(s.core.tokens()))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TokenIn {
    name: String,
    profiles: Vec<String>,
    workspaces: Vec<String>,
}

async fn create_token(State(s): State<Arc<Server>>, h: HeaderMap, b: Body) -> Response {
    need_auth!(s, h);
    let input: TokenIn = body!(b);
    let v = tryf!(
        s.core
            .create_token_in(&input.name, input.profiles, input.workspaces)
    );
    write_json(200, &json!({"token": v}))
}

async fn revoke_token(
    State(s): State<Arc<Server>>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    need_auth!(s, h);
    tryf!(s.core.revoke_token(&id));
    ok_json()
}

async fn requests(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    write_json(200, &s.core.requests())
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DecideIn {
    approve: bool,
    hash: String,
    totp: String,
    secret: String,
}

async fn decide(
    State(s): State<Arc<Server>>,
    h: HeaderMap,
    Path(id): Path<String>,
    b: Body,
) -> Response {
    need_auth!(s, h);
    let i: DecideIn = body!(b);
    let msg = tryf!(
        s.core
            .decide(&id, &i.hash, i.approve, "web", &i.totp, &i.secret)
    );
    write_json(200, &json!({"message": msg}))
}

async fn audit_log(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    let c = s.core.clone();
    let path = s.audit_path.clone();
    let res = blocking(move || {
        let es = c.audit.tail(200)?;
        let (n, ok) = match audit::verify(&path) {
            Ok(n) => (n, true),
            Err(audit::Error::ChainBroken(n)) => (n - 1, false),
            Err(_) => (0, false),
        };
        Ok::<_, audit::Error>(json!({"entries": es, "valid_entries": n, "chain_ok": ok,
            "truncated": c.audit_truncated()}))
    })
    .await;
    write_json(200, &tryf!(res))
}

async fn health(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    let c = s.core.clone();
    let mut items = tryf!(blocking(move || c.health()).await);
    let item = |level: &str, key: &str, msg: &str| HealthItem {
        key: key.into(),
        level: level.into(),
        message: msg.into(),
        names: vec![],
    };
    items.push(if s.gate_token.is_empty() {
        item(
            "bad",
            "gate",
            "Cổng mã truy cập đang tắt, ai tới được địa chỉ này cũng thấy trang đăng nhập.",
        )
    } else {
        item("ok", "gate", "Có mã truy cập chặn trước trang đăng nhập.")
    });
    items.push(if s.secure_cookie {
        item("ok", "https", "Cookie phiên chỉ đi qua HTTPS.")
    } else {
        item(
            "warn",
            "https",
            "Cookie phiên chưa đặt Secure. Đặt UCANRUN_PUBLIC_URL với địa chỉ https.",
        )
    });
    write_json(200, &items)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TelegramIn {
    token: String,
}

async fn set_telegram(State(s): State<Arc<Server>>, h: HeaderMap, b: Body) -> Response {
    need_auth!(s, h);
    let input: TelegramIn = body!(b);
    let set = s.core.set_telegram_token(input.token.trim());
    match tokio::time::timeout(Duration::from_secs(15), set).await {
        Ok(Ok((bot, code))) => write_json(200, &json!({"bot": bot, "code": code})),
        Ok(Err(e)) => fail(e),
        Err(_) => err_json(400, "token Telegram không hợp lệ hoặc không kết nối được"),
    }
}

async fn pair_code(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    let code = tryf!(s.core.new_pair_code());
    write_json(200, &json!({"code": code}))
}

/// An SVG QR code as a data URI.
fn qr_data_uri(text: &str) -> Result<String, core::Error> {
    let q = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| core::Error::Msg(e.to_string()))?;
    let svg = q
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(256, 256)
        .build();
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        STANDARD.encode(svg)
    ))
}

async fn totp_start(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    let (secret, uri) = tryf!(s.core.totp_start());
    let qr = tryf!(qr_data_uri(&uri));
    write_json(200, &json!({"secret": secret, "qr": qr}))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CodeIn {
    code: String,
}

async fn totp_confirm(State(s): State<Arc<Server>>, h: HeaderMap, b: Body) -> Response {
    need_auth!(s, h);
    let input: CodeIn = body!(b);
    let codes = tryf!(s.core.totp_confirm(&input.code));
    write_json(200, &json!({"recovery_codes": codes}))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SettingsIn {
    auto_lock_min: i64,
}

async fn put_settings(State(s): State<Arc<Server>>, h: HeaderMap, b: Body) -> Response {
    need_auth!(s, h);
    let input: SettingsIn = body!(b);
    tryf!(s.core.set_auto_lock(input.auto_lock_min));
    write_json(200, &json!({"auto_lock_min": s.core.auto_lock_min()}))
}

async fn templates(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    write_json(200, &tryf!(s.core.templates()))
}

async fn put_template(State(s): State<Arc<Server>>, h: HeaderMap, b: Body) -> Response {
    need_auth!(s, h);
    let input: crate::state::SecretTemplate = body!(b);
    write_json(200, &tryf!(s.core.put_template(input)))
}

async fn delete_template(
    State(s): State<Arc<Server>>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    need_auth!(s, h);
    tryf!(s.core.delete_template(&id));
    ok_json()
}

async fn devices(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    let c = s.core.clone();
    write_json(200, &tryf!(blocking(move || c.devices()).await))
}

/// How far back the run log looks, in audit lines.
const RUN_SCAN: usize = 5000;
const RUN_MAX: usize = 300;

/// Finished runs, newest first, read from the audit log so they survive
/// restarts and cannot be edited without breaking the chain.
async fn runs(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    let c = s.core.clone();
    let res = blocking(move || {
        let es = c.audit.tail(RUN_SCAN)?;
        let rows: Vec<Value> = es
            .into_iter()
            .filter(|e| e.event == "result")
            .take(RUN_MAX)
            .map(|e| {
                let mut v = Value::Object(e.fields);
                v["time"] = json!(e.time);
                v["approved_by"] = json!(e.actor);
                v
            })
            .collect();
        Ok::<_, audit::Error>(json!({"runs": rows}))
    })
    .await;
    write_json(200, &tryf!(res))
}

async fn totp_recovery(State(s): State<Arc<Server>>, h: HeaderMap, b: Body) -> Response {
    need_auth!(s, h);
    let input: CodeIn = body!(b);
    let codes = tryf!(s.core.new_recovery_codes(&input.code));
    write_json(200, &json!({"recovery_codes": codes}))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ResetIn {
    passphrase: String,
    code: String,
}

async fn totp_reset(State(s): State<Arc<Server>>, h: HeaderMap, b: Body) -> Response {
    need_auth!(s, h);
    let input: ResetIn = body!(b);
    if s.throttled() {
        return err_json(429, "thử lại sau ít giây");
    }
    let c = s.core.clone();
    if blocking(move || c.totp_reset(input.passphrase.as_bytes(), &input.code))
        .await
        .is_err()
    {
        s.record_login(false);
        return err_json(401, "sai mật khẩu hoặc mã");
    }
    ok_json()
}

// --- agent handlers ---

async fn agent_profiles(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    let t = match s.bearer(&h).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    write_json(200, &trya!(s.core.profiles_for(&t)))
}

async fn agent_secrets(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    let t = match s.bearer(&h).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    let c = s.core.clone();
    write_json(200, &trya!(blocking(move || c.secrets_for(&t)).await))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SubmitIn {
    profile: String,
    params: BTreeMap<String, String>,
    call: Option<Call>,
    reason: String,
    wait_sec: i64,
}

async fn agent_submit(State(s): State<Arc<Server>>, h: HeaderMap, b: Body) -> Response {
    let t = match s.bearer(&h).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    let input: SubmitIn = body!(b);
    let client = core::ClientInfo::new(
        header_str(&h, "x-ucanrun-device"),
        header_str(&h, "x-ucanrun-app"),
    );
    let q = match &input.call {
        Some(call) => s.core.submit_call_from(&t, &client, call, &input.reason),
        None => s
            .core
            .submit_from(&t, &client, &input.profile, input.params, &input.reason),
    };
    let mut q = trya!(q);
    if input.wait_sec > 0 {
        let d = Duration::from_secs(input.wait_sec.min(110) as u64);
        if let Some(r) = s.core.wait(&q.id, Some(d)).await {
            q = r;
        }
    }
    write_json(200, &q)
}

async fn agent_get(State(s): State<Arc<Server>>, h: HeaderMap, Path(id): Path<String>) -> Response {
    let t = match s.bearer(&h).await {
        Ok(t) => t,
        Err(r) => return *r,
    };
    match s.core.get(&id) {
        Some(q) if q.caller == t.name => write_json(200, &q),
        _ => agent_fail(core::Error::NotFound),
    }
}

async fn agent_runners(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    if let Err(r) = s.bearer(&h).await {
        return *r;
    }
    write_json(200, &trya!(s.core.runners_for_agent()))
}

// --- runner handlers ---

fn runner_name(s: &Server, h: &HeaderMap) -> Result<String, Box<Response>> {
    let tok = header_str(h, "authorization")
        .strip_prefix("Bearer ")
        .unwrap_or("");
    s.core.runner_auth(tok).map_err(|e| {
        Box::new(match e {
            core::Error::Locked => err_json(423, "vault locked"),
            _ => err_json(403, "unknown runner"),
        })
    })
}

async fn runner_enroll(State(s): State<Arc<Server>>, b: Body) -> Response {
    let input: crate::runner::proto::EnrollIn = body!(b);
    match s.core.enroll_runner(input) {
        Ok(out) => write_json(200, &out),
        Err(e) => fail(e),
    }
}

async fn runner_poll(State(s): State<Arc<Server>>, h: HeaderMap, b: Body) -> Response {
    let name = match runner_name(&s, &h) {
        Ok(n) => n,
        Err(r) => return *r,
    };
    let input: crate::runner::proto::PollIn = body!(b);
    match s.core.runner_poll(&name, input.info).await {
        Ok(jobs) => write_json(200, &crate::runner::proto::PollOut { jobs }),
        Err(core::Error::Locked) => err_json(423, "vault locked"),
        Err(e) => fail(e),
    }
}

async fn runner_result(State(s): State<Arc<Server>>, h: HeaderMap, b: Body) -> Response {
    let name = match runner_name(&s, &h) {
        Ok(n) => n,
        Err(r) => return *r,
    };
    let input: crate::runner::proto::Signed = body!(b);
    match s.core.runner_result(&name, input) {
        Ok(()) => ok_json(),
        Err(e) => fail(e),
    }
}

async fn runners_list(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    let list = tryf!(s.core.runners());
    let key = tryf!(s.core.runner_server_key());
    write_json(
        200,
        &json!({"runners": list, "server_key": crate::runner::proto::fingerprint(&key),
            "agent_url": std::env::var("UCANRUN_AGENT_URL").unwrap_or_default()}),
    )
}

async fn system_info(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    let c = s.core.clone();
    let info = blocking(move || c.system()).await;
    let env = |k: &str, d: &str| match std::env::var(k) {
        Ok(v) if !v.is_empty() => v,
        _ => d.to_string(),
    };
    let mut v = serde_json::to_value(&info).unwrap_or_default();
    v["web_addr"] = json!(env("UCANRUN_WEB_ADDR", "127.0.0.1:8780"));
    v["agent_addr"] = json!(env("UCANRUN_AGENT_ADDR", "127.0.0.1:8781"));
    v["public_url"] = json!(env("UCANRUN_PUBLIC_URL", ""));
    v["agent_url"] = json!(env("UCANRUN_AGENT_URL", ""));
    v["gate"] = json!(!s.gate_token.is_empty());
    v["secure_cookie"] = json!(s.secure_cookie);
    write_json(200, &v)
}

async fn runner_code(State(s): State<Arc<Server>>, h: HeaderMap) -> Response {
    need_auth!(s, h);
    let (code, expires) = tryf!(s.core.new_runner_code());
    write_json(200, &json!({"code": code, "expires": expires}))
}

async fn runner_delete(
    State(s): State<Arc<Server>>,
    h: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    need_auth!(s, h);
    tryf!(s.core.delete_runner(&name));
    ok_json()
}

// --- serving ---

/// Serves `app` on `l` with timeouts like the Go server, until `shutdown`
/// resolves; open connections then get three seconds to finish.
pub async fn serve(
    l: tokio::net::TcpListener,
    app: Router,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    use hyper_util::rt::{TokioIo, TokioTimer};
    use hyper_util::service::TowerToHyperService;

    let mut b = hyper::server::conn::http1::Builder::new();
    b.timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_buf_size(20 << 10); // Go: 16 KiB of headers plus 4 KiB slack
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    tokio::pin!(shutdown);
    loop {
        let (stream, _) = tokio::select! {
            r = l.accept() => match r {
                Ok(x) => x,
                // Running out of file descriptors must not stop the server.
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            _ = &mut shutdown => break,
        };
        let _ = stream.set_nodelay(true);
        let conn = b.serve_connection(TokioIo::new(stream), TowerToHyperService::new(app.clone()));
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            let _ = conn.await;
        });
    }
    let _ = tokio::time::timeout(Duration::from_secs(3), graceful.shutdown()).await;
    Ok(())
}
