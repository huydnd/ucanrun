//! The Go tests of internal/web (e2e_test.go, catalog_test.go) against the
//! real axum routers over HTTP, with a fake Telegram Bot API and a fake
//! target service, plus the `ucr` binary itself.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path as AxPath, State};
use axum::http::{HeaderMap, Uri};
use axum::routing::any;
use hmac::{Hmac, Mac};
use reqwest::header::HeaderMap as RHeaders;
use serde_json::{Value, json};
use sha2::Sha256;

use ucanrun::client::Client;
use ucanrun::core::{self, Core, Options, ReqState, Request};
use ucanrun::policy::Profile;
use ucanrun::web::{self, Server};
use ucanrun::{audit, totp};

const PASS: &str = "correct horse battery staple";
const SECRET: &str = "gitea-token-VALUE-0123456789";
const BOT_TOK: &str = "123:BOTTOKEN";
const OWNER: i64 = 1001;
const STRANGER: i64 = 666;
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

// --- fake Telegram ---

#[derive(Default)]
struct Tg {
    next_id: i64,
    updates: Vec<Value>,
    sent: Vec<Value>,
    answers: Vec<String>,
    edits: Vec<String>,
}

#[derive(Default)]
struct FakeTg(Mutex<Tg>);

async fn tg_handler(
    State(f): State<Arc<FakeTg>>,
    AxPath(path): AxPath<String>,
    body: Bytes,
) -> axum::Json<Value> {
    let (bot, method) = path.split_once('/').unwrap_or((&path, ""));
    if bot != format!("bot{BOT_TOK}") {
        return axum::Json(json!({"ok": false, "description": "Unauthorized"}));
    }
    let input: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let reply = |v: Value| axum::Json(json!({"ok": true, "result": v}));
    let text = || input["text"].as_str().unwrap_or("").to_string();
    match method {
        "getMe" => reply(json!({"username": "ucanrun_test_bot"})),
        "sendMessage" => {
            let mut s = f.0.lock().unwrap();
            s.sent.push(input.clone());
            reply(json!({"message_id": s.sent.len()}))
        }
        "answerCallbackQuery" => {
            f.0.lock().unwrap().answers.push(text());
            reply(json!(true))
        }
        "editMessageText" => {
            f.0.lock().unwrap().edits.push(text());
            reply(json!(true))
        }
        "getUpdates" => {
            let off = input["offset"].as_i64().unwrap_or(0);
            if off < 0 {
                return reply(json!([]));
            }
            let deadline = Instant::now() + Duration::from_millis(150);
            while Instant::now() < deadline {
                let out: Vec<Value> = {
                    let s = f.0.lock().unwrap();
                    s.updates
                        .iter()
                        .filter(|u| u["update_id"].as_i64().unwrap() >= off)
                        .cloned()
                        .collect()
                };
                if !out.is_empty() {
                    return reply(Value::Array(out));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            reply(json!([]))
        }
        _ => reply(Value::Null),
    }
}

impl FakeTg {
    fn push(&self, mut u: Value) {
        let mut s = self.0.lock().unwrap();
        s.next_id += 1;
        u["update_id"] = json!(s.next_id);
        s.updates.push(u);
    }

    fn text(&self, user: i64, chat: i64, t: &str) {
        self.push(json!({"message": {"message_id": 1, "text": t,
            "from": {"id": user}, "chat": {"id": chat, "type": "private"}}}));
    }

    fn press(&self, user: i64, chat: i64, data: &str) {
        self.push(
            json!({"callback_query": {"id": "cb", "data": data, "from": {"id": user},
            "message": {"chat": {"id": chat}}}}),
        );
    }

    fn dump(&self) -> String {
        let s = self.0.lock().unwrap();
        serde_json::to_string(&json!([s.sent, s.answers, s.edits])).unwrap()
    }

    /// Callback data of the first button of the newest approval message,
    /// once that message mentions `want`.
    async fn last_button(&self, want: &str) -> String {
        let mut data = String::new();
        wait_for(&format!("approval message {want}"), || {
            let s = self.0.lock().unwrap();
            let Some(m) = s
                .sent
                .iter()
                .rev()
                .find(|m| m.get("reply_markup").is_some())
            else {
                return false;
            };
            if !m["text"].as_str().unwrap().contains(want) {
                return false;
            }
            data = m["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
                .as_str()
                .unwrap()
                .to_string();
            true
        })
        .await;
        data
    }
}

// --- fake target service ---

#[derive(Default)]
struct Target {
    auth: Mutex<String>,
    pass: Mutex<String>,
    path: Mutex<String>,
    hits: AtomicUsize,
}

async fn target_handler(State(t): State<Arc<Target>>, uri: Uri, h: HeaderMap) -> String {
    let get = |k: &str| {
        h.get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let (auth, pass) = (get("authorization"), get("x-pass"));
    *t.auth.lock().unwrap() = auth.clone();
    *t.pass.lock().unwrap() = pass.clone();
    *t.path.lock().unwrap() = uri.path().to_string();
    t.hits.fetch_add(1, Ordering::SeqCst);
    format!("created, debug header was {auth}; pass {pass}")
}

async fn serve(r: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(web::serve(l, r, std::future::pending()));
    format!("http://{addr}")
}

async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while Instant::now() < end {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// --- HTTP with a cookie jar ---

struct Http {
    base: String,
    c: reqwest::Client,
    jar: Mutex<HashMap<String, String>>,
}

struct Resp {
    code: u16,
    headers: RHeaders,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn header(&self, k: &str) -> String {
        self.headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }
    fn cookies(&self) -> Vec<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }
}

impl Http {
    fn new(base: &str) -> Http {
        Http {
            base: base.to_string(),
            c: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            jar: Mutex::new(HashMap::new()),
        }
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        hdr: &[(&str, &str)],
    ) -> Resp {
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let mut r = self.c.request(m, format!("{}{path}", self.base));
        let cookies: Vec<String> = self
            .jar
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        if !cookies.is_empty() {
            r = r.header("cookie", cookies.join("; "));
        }
        for (k, v) in hdr {
            r = r.header(*k, *v);
        }
        if let Some(b) = body {
            r = r.body(b);
        }
        let resp = r.send().await.unwrap();
        let out = Resp {
            code: resp.status().as_u16(),
            headers: resp.headers().clone(),
            body: resp.bytes().await.unwrap().to_vec(),
        };
        let mut jar = self.jar.lock().unwrap();
        for c in out.cookies() {
            let first = c.split(';').next().unwrap();
            let (k, v) = first.split_once('=').unwrap();
            if c.contains("Max-Age=0") || v.is_empty() {
                jar.remove(k);
            } else {
                jar.insert(k.to_string(), v.to_string());
            }
        }
        out
    }

    /// JSON with the CSRF header, like the web UI.
    async fn req(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let r = self.raw(method, path, body, &[("X-Ucanrun", "1")]).await;
        (r.code, r.json())
    }

    async fn raw(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        hdr: &[(&str, &str)],
    ) -> Resp {
        let mut h = hdr.to_vec();
        if body.is_some() {
            h.push(("content-type", "application/json"));
        }
        self.send(
            method,
            path,
            body.map(|b| serde_json::to_vec(&b).unwrap()),
            &h,
        )
        .await
    }
}

// --- environment ---

struct Env {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    c: Arc<Core>,
    tg: Arc<FakeTg>,
    target: Arc<Target>,
    target_url: String,
    web: String,
    agent: String,
    hc: Http,
}

fn core_opts(dir: &Path, tg: &str, ttl: Duration) -> Options {
    Options {
        data_dir: dir.to_path_buf(),
        approval_ttl: ttl,
        telegram_api: tg.into(),
        work_factor: 10,
        lang: "vi".into(),
        ..Default::default()
    }
}

/// The routers of a server, served on ephemeral ports.
async fn start(s: Server) -> (String, String) {
    let s = Arc::new(s);
    (serve(s.handler()).await, serve(s.agent_handler()).await)
}

async fn bare(ttl: Duration) -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("data");
    let tg = Arc::new(FakeTg::default());
    let tg_url = serve(
        Router::new()
            .route("/{*path}", any(tg_handler))
            .with_state(tg.clone()),
    )
    .await;
    let target = Arc::new(Target::default());
    let target_url = serve(
        Router::new()
            .fallback(target_handler)
            .with_state(target.clone()),
    )
    .await;
    let c = Core::new(core_opts(&dir, &tg_url, ttl)).unwrap();
    let s = Server::new(c.clone(), "setup-tok", dir.join("audit.jsonl"), false);
    let (web, agent) = start(s).await;
    Env {
        _tmp: tmp,
        hc: Http::new(&web),
        dir,
        c,
        tg,
        target,
        target_url,
        web,
        agent,
    }
}

async fn setup(ttl: Duration) -> Env {
    let e = bare(ttl).await;
    let (code, m) = e
        .req(
            "POST",
            "/api/setup",
            json!({"setup_token": "wrong", "passphrase": PASS}),
        )
        .await;
    assert_eq!(code, 403, "setup with bad token: {m}");
    let (code, m) = e
        .req(
            "POST",
            "/api/setup",
            json!({"setup_token": "setup-tok", "passphrase": PASS}),
        )
        .await;
    assert_eq!(code, 200, "setup: {m}");
    let (code, _) = e
        .req(
            "POST",
            "/api/setup",
            json!({"setup_token": "setup-tok", "passphrase": "another long password"}),
        )
        .await;
    assert_eq!(code, 409, "second setup");
    let (code, m) = e
        .req("PUT", "/api/secrets/gitea", json!({"value": SECRET}))
        .await;
    assert_eq!(code, 200, "put secret: {m}");
    e.profile("create", "low", false).await;
    e.profile("danger", "high", false).await;
    e.profile("auto", "low", true).await;
    e
}

fn minute() -> Duration {
    Duration::from_secs(60)
}

impl Env {
    async fn req(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        let body = if body.is_null() { None } else { Some(body) };
        self.hc.req(method, path, body).await
    }

    async fn profile(&self, name: &str, risk: &str, auto: bool) {
        let p = json!({"name": name, "risk": risk, "auto_approve": auto,
            "params": [{"name": "repo", "pattern": "[a-z0-9-]+", "required": true}],
            "http": {"method": "POST", "url": format!("{}/repos/{{{{repo}}}}", self.target_url),
                     "headers": {"Authorization": "token {{secret:gitea}}"}}});
        let (code, m) = self.req("PUT", "/api/profiles", p).await;
        assert_eq!(code, 200, "profile: {m}");
    }

    async fn token(&self, name: &str, profiles: &[&str]) -> Client {
        let (code, m) = self
            .req(
                "POST",
                "/api/tokens",
                json!({"name": name, "profiles": profiles}),
            )
            .await;
        assert_eq!(code, 200, "token: {m}");
        Client::new(&self.agent, m["token"].as_str().unwrap())
    }

    async fn pair(&self) {
        let (code, m) = self
            .req("PUT", "/api/telegram", json!({"token": BOT_TOK}))
            .await;
        assert_eq!(code, 200, "telegram: {m}");
        assert_eq!(m["bot"], "ucanrun_test_bot");
        self.tg.text(STRANGER, STRANGER, "/pair wrong-code");
        self.tg.text(
            OWNER,
            OWNER,
            &format!("/pair {}", m["code"].as_str().unwrap()),
        );
        wait_for("pairing", || self.c.telegram_status().paired).await;
        assert_eq!(self.c.telegram_status().user_id, OWNER, "wrong user paired");
    }

    /// Enrolls TOTP with the previous step, leaving current and next free.
    async fn enable_totp(&self) -> String {
        let (code, m) = self.req("POST", "/api/totp/start", Value::Null).await;
        assert_eq!(code, 200, "totp start: {m}");
        let sec = m["secret"].as_str().unwrap().to_string();
        assert!(
            m["qr"]
                .as_str()
                .unwrap()
                .starts_with("data:image/svg+xml;base64,"),
            "no qr"
        );
        let c = totp::code(&sec, unix_now() - 30).unwrap();
        let (code, m) = self
            .req("POST", "/api/totp/confirm", json!({"code": c}))
            .await;
        assert_eq!(code, 200, "totp confirm: {m}");
        sec
    }

    async fn wait(&self, id: &str, want: ReqState) -> Request {
        let mut r = None;
        wait_for(&format!("state {}", want.as_str()), || {
            r = self.c.get(id);
            r.as_ref().is_some_and(|r| r.state == want)
        })
        .await;
        r.unwrap()
    }

    fn hits(&self) -> usize {
        self.target.hits.load(Ordering::SeqCst)
    }

    fn got_auth(&self) -> String {
        self.target.auth.lock().unwrap().clone()
    }

    fn no_secret_anywhere(&self) {
        assert!(!self.tg.dump().contains(SECRET), "secret reached Telegram");
        fn walk(p: &Path) {
            for e in std::fs::read_dir(p).unwrap() {
                let e = e.unwrap();
                if e.file_type().unwrap().is_dir() {
                    walk(&e.path());
                    continue;
                }
                let b = std::fs::read(e.path()).unwrap();
                let s = String::from_utf8_lossy(&b);
                assert!(
                    !s.contains(SECRET) && !s.contains(BOT_TOK),
                    "plaintext secret in {:?}",
                    e.path()
                );
            }
        }
        walk(&self.dir);
    }

    async fn decide(&self, id: &str, body: Value) -> u16 {
        self.req("POST", &format!("/api/requests/{id}/decide"), body)
            .await
            .0
    }
}

fn sid(r: &Value, k: &str) -> String {
    r[k].as_str().unwrap().to_string()
}

fn params(kv: &[(&str, &str)]) -> Value {
    json!(
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<_, _>>()
    )
}

// --- the Go e2e tests ---

#[tokio::test(flavor = "multi_thread")]
async fn approve_on_telegram_runs_and_hides_secret() {
    let e = setup(minute()).await;
    e.pair().await;
    let cl = e.token("claude", &[]).await;
    let r = cl
        .run("create", params(&[("repo", "foo")]), "cần repo mới", 0)
        .await
        .unwrap();
    assert_eq!(r["state"], "pending", "{r}");
    let id = sid(&r, "id");
    assert_eq!(e.hits(), 0, "ran before approval");
    let btn = e.tg.last_button("/repos/foo").await;
    let d = e.tg.dump();
    assert!(
        d.contains("agent tự khai") && d.contains("‹secret:gitea›"),
        "approval text: {d}"
    );
    // A stranger, and the owner in another chat, must both fail.
    e.tg.press(STRANGER, OWNER, &btn);
    e.tg.press(OWNER, STRANGER, &btn);
    wait_for("strangers refused", || {
        e.tg.dump().matches("Không có quyền").count() == 2
    })
    .await;
    assert_eq!(
        e.c.get(&id).unwrap().state,
        ReqState::Pending,
        "stranger changed state"
    );
    e.tg.press(OWNER, OWNER, &btn);
    let q = e.wait(&id, ReqState::Done).await;
    assert_eq!(e.got_auth(), format!("token {SECRET}"));
    let out = q.result.unwrap().output;
    assert!(
        !out.contains(SECRET) && out.contains("[REDACTED]"),
        "output: {out}"
    );
    // A second press and a replayed press must not run it again.
    e.tg.press(OWNER, OWNER, &btn);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(e.hits(), 1);
    wait_for("buttons removed", || e.tg.dump().contains("Kết thúc: done")).await;
    let got = cl.request(&id).await.unwrap();
    assert!(
        !got.to_string().contains(SECRET),
        "secret in agent response"
    );
    e.no_secret_anywhere();
    let n = audit::verify(&e.dir.join("audit.jsonl")).unwrap();
    assert!(n > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn deny_expire_and_wrong_hash() {
    let e = setup(Duration::from_millis(400)).await;
    e.pair().await;
    let cl = e.token("claude", &[]).await;
    let r = cl
        .run("create", params(&[("repo", "a")]), "", 0)
        .await
        .unwrap();
    let id = sid(&r, "id");
    assert_ne!(
        e.decide(&id, json!({"approve": true, "hash": "0".repeat(64)}))
            .await,
        200
    );
    assert_ne!(
        e.decide(&id, json!({"approve": true, "hash": ""})).await,
        200
    );
    e.wait(&id, ReqState::Expired).await; // silence is not approval
    assert_ne!(
        e.decide(&id, json!({"approve": true, "hash": r["hash"]}))
            .await,
        200
    );
    let r = cl
        .run("create", params(&[("repo", "b")]), "", 0)
        .await
        .unwrap();
    let btn = e.tg.last_button("/repos/b").await.replacen("a:", "d:", 1);
    e.tg.press(OWNER, OWNER, &btn);
    e.wait(&sid(&r, "id"), ReqState::Denied).await;
    assert_eq!(e.hits(), 0, "denied request ran");
}

#[tokio::test(flavor = "multi_thread")]
async fn high_risk_needs_totp_and_code_is_single_use() {
    let e = setup(minute()).await;
    e.pair().await;
    let cl = e.token("claude", &[]).await;
    let r = cl
        .run("danger", params(&[("repo", "a")]), "", 0)
        .await
        .unwrap();
    let (id, hash) = (sid(&r, "id"), sid(&r, "hash"));
    assert_ne!(
        e.decide(&id, json!({"approve": true, "hash": hash})).await,
        200
    );
    let sec = e.enable_totp().await;
    let btn = e.tg.last_button("RỦI RO CAO").await;
    e.tg.press(OWNER, OWNER, &btn);
    wait_for("totp prompt", || e.tg.dump().contains("Gửi mã TOTP")).await;
    assert_eq!(
        e.c.get(&id).unwrap().state,
        ReqState::Pending,
        "button alone approved"
    );
    e.tg.text(STRANGER, STRANGER, "123456");
    e.tg.text(OWNER, OWNER, "000000");
    wait_for("bad code refused", || e.tg.dump().contains("sai mã TOTP")).await;
    assert_eq!(
        e.c.get(&id).unwrap().state,
        ReqState::Pending,
        "bad code approved"
    );
    e.tg.press(OWNER, OWNER, &btn);
    wait_for("second prompt", || {
        e.tg.dump().matches("Gửi mã TOTP").count() == 2
    })
    .await;
    let good = totp::code(&sec, unix_now()).unwrap();
    e.tg.text(OWNER, OWNER, &good);
    e.wait(&id, ReqState::Done).await;

    let r2 = cl
        .run("danger", params(&[("repo", "b")]), "", 0)
        .await
        .unwrap();
    let code = e
        .decide(
            &sid(&r2, "id"),
            json!({"approve": true, "hash": r2["hash"], "totp": good}),
        )
        .await;
    assert_ne!(code, 200, "TOTP code reused");
    e.no_secret_anywhere();
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_boundaries() {
    let e = setup(minute()).await;
    let limited = e.token("limited", &["create"]).await;
    assert!(
        limited
            .run("danger", params(&[("repo", "a")]), "", 0)
            .await
            .is_err(),
        "scope"
    );
    assert!(
        limited
            .run("create", params(&[("repo", "../x")]), "", 0)
            .await
            .is_err()
    );
    let extra = params(&[("repo", "a"), ("extra", "b")]);
    assert!(
        limited.run("create", extra, "", 0).await.is_err(),
        "unknown param"
    );
    let bad = Client::new(&e.agent, "ucr_nope");
    assert!(bad.profiles().await.is_err(), "bad token accepted");
    // The agent cannot reach any human endpoint on its port.
    let http = reqwest::Client::new();
    for p in [
        "/api/secrets",
        "/api/profiles",
        "/api/tokens",
        "/",
        "/app.js",
    ] {
        let r = http
            .get(format!("{}{p}", e.agent))
            .bearer_auth(&limited.token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 404, "{p} on agent port");
    }
    // A token cannot read another caller's result.
    let other = e.token("other", &[]).await;
    let r = limited
        .run("create", params(&[("repo", "a")]), "", 0)
        .await
        .unwrap();
    let err = other.request(&sid(&r, "id")).await.unwrap_err();
    assert!(err.contains("not found") && err.contains("404"), "{err}");
    assert!(limited.request(&sid(&r, "id")).await.is_ok());
    // Approval spam is capped.
    let mut last = Ok(Value::Null);
    for _ in 0..8 {
        last = other.run("create", params(&[("repo", "a")]), "", 0).await;
    }
    assert!(
        last.unwrap_err().contains("429"),
        "pending cap not enforced"
    );
    // Revocation applies immediately.
    for t in e.c.tokens().unwrap() {
        e.req("DELETE", &format!("/api/tokens/{}", t.id), Value::Null)
            .await;
    }
    assert!(
        limited.profiles().await.unwrap_err().contains("403"),
        "revoked token works"
    );
    // Profile listing hides templates, hosts and secret names.
    let cl = e.token("c", &[]).await;
    let v = cl.profiles().await.unwrap().to_string();
    assert!(
        !v.contains("gitea") && !v.contains("127.0.0.1"),
        "listing leaks: {v}"
    );
    // No token at all.
    let r = http
        .get(format!("{}/v1/profiles", e.agent))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    assert_eq!(r.json::<Value>().await.unwrap()["error"], "missing token");
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_approve() {
    let e = setup(minute()).await;
    let cl = e.token("c", &[]).await;
    let r = cl
        .run("auto", params(&[("repo", "a")]), "", 5)
        .await
        .unwrap();
    assert_eq!(r["state"], "done", "{r}");
}

#[tokio::test(flavor = "multi_thread")]
async fn lock_denies_pending_and_blocks_agents() {
    let e = setup(minute()).await;
    let cl = e.token("c", &[]).await;
    let r = cl
        .run("create", params(&[("repo", "a")]), "", 0)
        .await
        .unwrap();
    let hash = r["hash"].clone();
    assert_eq!(e.req("POST", "/api/lock", Value::Null).await.0, 200);
    let err = cl
        .run("create", params(&[("repo", "b")]), "", 0)
        .await
        .unwrap_err();
    assert!(err.contains("423"), "locked: {err}");
    assert_eq!(
        e.req("GET", "/api/secrets", Value::Null).await.0,
        401,
        "session survived lock"
    );
    let (code, _) = e
        .req(
            "POST",
            "/api/login",
            json!({"passphrase": "wrong wrong wrong"}),
        )
        .await;
    assert_eq!(code, 401, "bad login accepted");
    assert_eq!(
        e.req("POST", "/api/login", json!({"passphrase": PASS}))
            .await
            .0,
        200
    );
    let code = e
        .decide(&sid(&r, "id"), json!({"approve": true, "hash": hash}))
        .await;
    assert_ne!(code, 200, "pending request survived lock");
    assert_eq!(e.hits(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_state_refused() {
    let e = setup(minute()).await;
    e.token("c", &[]).await;
    e.req("POST", "/api/lock", Value::Null).await;
    let p = e.dir.join("state.json");
    let b = std::fs::read_to_string(&p).unwrap();
    assert!(b.contains(r#""risk":"high""#), "fixture");
    std::fs::write(&p, b.replacen(r#""risk":"high""#, r#""risk":"low""#, 1)).unwrap();
    let (code, m) = e
        .req("POST", "/api/login", json!({"passphrase": PASS}))
        .await;
    assert_eq!(code, 409, "tampered state accepted: {m}");
    assert_eq!(
        m["error"],
        "file trạng thái không qua được kiểm tra toàn vẹn"
    );
    assert!(e.c.locked(), "unlocked after tamper");
}

#[tokio::test(flavor = "multi_thread")]
async fn web_hardening() {
    let e = setup(minute()).await;
    let v = Some(json!({"value": "v"}));
    let r = e.hc.raw("PUT", "/api/secrets/x", v.clone(), &[]).await;
    assert_eq!(
        (r.code, r.json()["error"].clone()),
        (403, json!("csrf")),
        "no csrf header"
    );
    for site in ["cross-site", "same-site", "none"] {
        let h = [("X-Ucanrun", "1"), ("Sec-Fetch-Site", site)];
        let r = e.hc.raw("PUT", "/api/secrets/x", v.clone(), &h).await;
        assert_eq!(r.code, 403, "{site} write");
    }
    let h = [("X-Ucanrun", "2")];
    assert_eq!(
        e.hc.raw("PUT", "/api/secrets/x", v.clone(), &h).await.code,
        403
    );
    let h = [("X-Ucanrun", "1"), ("Sec-Fetch-Site", "same-origin")];
    assert_eq!(
        e.hc.raw("PUT", "/api/secrets/x", v.clone(), &h).await.code,
        200
    );
    let (code, m) = e
        .req("PUT", "/api/secrets/_telegram_token", json!({"value": "v"}))
        .await;
    assert_eq!(
        (code, m["error"].clone()),
        (400, json!("invalid secret name"))
    );
    assert_ne!(
        e.req("DELETE", "/api/secrets/_totp_secret", Value::Null)
            .await
            .0,
        200
    );
    let r = e.hc.raw("GET", "/api/secrets", None, &[]).await;
    let t = r.text();
    assert!(
        r.code == 200 && !t.contains(SECRET) && !t.contains("value"),
        "secret list: {t}"
    );
    let r = reqwest::get(format!("{}/", e.web)).await.unwrap();
    let h = r.headers();
    assert_eq!(h["content-security-policy"], CSP);
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert_eq!(h["cache-control"], "no-store");
    assert!(h.get("strict-transport-security").is_none());
    // Anonymous clients get nothing, and repeated failures slow down.
    let r = reqwest::get(format!("{}/api/secrets", e.web))
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    let mut saw429 = false;
    for _ in 0..5 {
        let (c, _) = e
            .req(
                "POST",
                "/api/login",
                json!({"passphrase": "bad guess number x"}),
            )
            .await;
        saw429 |= c == 429;
    }
    assert!(saw429, "login not throttled");
}

#[tokio::test(flavor = "multi_thread")]
async fn login_does_not_reveal_passphrase_or_stall_approvals() {
    let e = setup(minute()).await;
    e.enable_totp().await;
    // A correct passphrase with no code must look the same as a wrong one.
    let h = [("X-Ucanrun", "1")];
    let r =
        e.hc.raw("POST", "/api/login", Some(json!({"passphrase": PASS})), &h)
            .await;
    let t = r.text();
    assert!(
        r.code == 401 && !t.contains("need_totp") && t.contains("sai thông tin"),
        "oracle: {t}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn token_names_unique_and_rate_limited() {
    let e = setup(minute()).await;
    e.token("dup", &[]).await;
    assert_ne!(
        e.req("POST", "/api/tokens", json!({"name": "dup"})).await.0,
        200
    );
    let cl = e.token("flood", &[]).await;
    let mut last = Ok(Value::Null);
    for _ in 0..40 {
        last = cl.run("auto", params(&[("repo", "a")]), "", 0).await;
    }
    assert!(last.unwrap_err().contains("429"), "no rate limit");
}

#[tokio::test(flavor = "multi_thread")]
async fn long_display_still_reaches_telegram() {
    let e = setup(minute()).await;
    e.pair().await;
    let p = json!({"name": "big", "risk": "low", "params": [{"name": "b", "pattern": "[a-z]+", "required": true}],
        "http": {"method": "POST", "url": format!("{}/x", e.target_url), "body": "{{b}}"}});
    let (code, m) = e.req("PUT", "/api/profiles", p).await;
    assert_eq!(code, 200, "{m}");
    let cl = e.token("c", &[]).await;
    let big = "a".repeat(4000);
    cl.run("big", params(&[("b", &big)]), "", 0).await.unwrap();
    e.tg.last_button("ĐÃ CẮT BỚT").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn preview() {
    let e = setup(minute()).await;
    let bad = json!({"profile": {"name": "Bad Name"}, "sample": {}});
    let (_, m) = e.req("POST", "/api/profiles/preview", bad).await;
    assert!(m["error"].is_string(), "no error: {m}");
    let p = json!({"name": "del", "risk": "low", "params": [{"name": "r", "pattern": ".+", "required": true}],
        "http": {"method": "DELETE", "url": "http://api.example.com/{{r}}",
                 "headers": {"Authorization": "Bearer {{secret:missing}}"}}});
    let (_, m) = e
        .req(
            "POST",
            "/api/profiles/preview",
            json!({"profile": p, "sample": {"r": "x"}}),
        )
        .await;
    let w = m["warnings"].to_string();
    for want in [
        "HTTP không mã hoá",
        "TOTP",
        "nhận mọi thứ",
        "Chưa có secret",
    ] {
        assert!(w.contains(want), "missing {want:?} in {w}");
    }
    assert!(
        m["display"].as_str().unwrap().contains("‹secret:missing›"),
        "{m}"
    );
    assert_eq!(e.hits(), 0, "preview ran the action");
}

#[tokio::test(flavor = "multi_thread")]
async fn pair_code_is_short_and_burns_after_guesses() {
    let e = setup(minute()).await;
    let (code, m) = e
        .req("PUT", "/api/telegram", json!({"token": BOT_TOK}))
        .await;
    assert_eq!(code, 200, "{m}");
    let pair = sid(&m, "code");
    assert!(
        pair.chars().count() == 6
            && pair.chars().any(|c| "#$%&+=?!".contains(c))
            && !pair.chars().any(|c| "0O1lI_*`~ ".contains(c)),
        "code {pair:?}"
    );
    for i in 0..3 {
        e.tg.text(STRANGER, STRANGER, &format!("/pair guess{i}"));
    }
    e.tg.text(OWNER, OWNER, &format!("/pair {pair}")); // correct, but too late
    wait_for("code burned", || {
        e.c.audit
            .tail(5)
            .unwrap()
            .iter()
            .any(|x| x.event == "pair_code_burned")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!e.c.telegram_status().paired, "paired with a burned code");
    // Generating a new code from the web works again.
    let (code, m) = e.req("POST", "/api/telegram/pair", Value::Null).await;
    assert_eq!(code, 200, "{m}");
    e.tg.text(OWNER, OWNER, &format!("/pair {}", sid(&m, "code")));
    wait_for("pairing", || e.c.telegram_status().paired).await;
    // A bad bot token is refused with the Go message.
    let (code, m) = e
        .req("PUT", "/api/telegram", json!({"token": "1:WRONG"}))
        .await;
    assert_eq!(code, 400);
    assert_eq!(
        m["error"],
        "token Telegram không hợp lệ hoặc không kết nối được"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn approver_chooses_secret_on_telegram() {
    let e = setup(minute()).await;
    e.pair().await;
    let (code, _) = e
        .req(
            "PUT",
            "/api/secrets/other",
            json!({"value": "second-secret-value-42"}),
        )
        .await;
    assert_eq!(code, 200);
    let p = json!({"name": "pick", "risk": "low", "secret_choices": ["gitea", "other", "absent"],
        "http": {"method": "GET", "url": format!("{}/x", e.target_url),
                 "headers": {"Authorization": "token {{secret:choice}}"}}});
    let (code, m) = e.req("PUT", "/api/profiles", p).await;
    assert_eq!(code, 200, "{m}");
    let cl = e.token("c", &[]).await;
    let r = cl.run("pick", Value::Null, "", 0).await.unwrap();
    let (id, hash) = (sid(&r, "id"), sid(&r, "hash"));
    assert!(
        r["display"]
            .as_str()
            .unwrap()
            .contains("‹secret bạn chọn khi duyệt›"),
        "{r}"
    );
    e.tg.last_button("Bấm tên secret").await;
    let short = &hash[..16];
    // Plain approve, an out of range button, a secret off the list, and a
    // listed secret missing from the vault must all fail.
    e.tg.press(STRANGER, OWNER, &format!("a:{id}:{short}:1"));
    e.tg.press(OWNER, OWNER, &format!("a:{id}:{short}"));
    e.tg.press(OWNER, OWNER, &format!("a:{id}:{short}:9"));
    wait_for("invalid choice", || {
        e.tg.dump().contains("Lựa chọn không hợp lệ")
    })
    .await;
    let body = json!({"approve": true, "hash": hash, "secret": "_totp_secret"});
    assert_ne!(e.decide(&id, body).await, 200, "off-list secret accepted");
    let body = json!({"approve": true, "hash": hash, "secret": "absent"});
    assert_ne!(e.decide(&id, body).await, 200, "missing secret accepted");
    assert_eq!(e.hits(), 0, "ran before a valid choice");
    e.tg.press(OWNER, OWNER, &format!("a:{id}:{short}:1"));
    let q = e.wait(&id, ReqState::Done).await;
    assert_eq!(e.got_auth(), "token second-secret-value-42");
    assert_eq!(q.secret, "other");
    assert!(
        !q.result.unwrap().output.contains("second-secret-value-42"),
        "leak"
    );
    wait_for("secret named", || {
        e.tg.dump().contains("Secret đã dùng: other")
    })
    .await;
    assert!(
        !e.tg.dump().contains("second-secret-value-42"),
        "secret on Telegram"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn gate_blocks_everything_without_code() {
    let e = setup(minute()).await;
    let mut s = Server::new(e.c.clone(), "setup-tok", e.dir.join("audit.jsonl"), false);
    s.gate_token = "open sesame gate code".into();
    let (url, _) = start(s).await;
    let anon = Http::new(&url);
    for p in [
        "/",
        "/app.js",
        "/api/status",
        "/api/secrets",
        "/api/profiles",
        "/catalog.json",
        "/gate",
    ] {
        let r = anon.send("GET", p, None, &[]).await;
        let t = r.text();
        assert!(
            r.code == 401 && !t.contains("initialized") && !t.contains("ucanrun"),
            "{p}: {} {t}",
            r.code
        );
        assert!(
            r.header("content-security-policy")
                .contains("form-action 'self'")
        );
        assert_eq!(r.header("content-type"), "text/html; charset=utf-8");
    }
    let form = [("content-type", "application/x-www-form-urlencoded")];
    let login = serde_json::to_vec(&json!({"passphrase": PASS})).unwrap();
    let h = [("X-Ucanrun", "1"), ("content-type", "application/json")];
    let r = anon.send("POST", "/api/login", Some(login), &h).await;
    assert_eq!(r.code, 401, "login reachable through the gate");
    let r = anon
        .send("POST", "/gate", Some(b"code=wrong".to_vec()), &form)
        .await;
    assert!(
        r.code == 401 && r.cookies().is_empty(),
        "wrong code: {}",
        r.code
    );
    let mut h = form.to_vec();
    h.push(("Sec-Fetch-Site", "cross-site"));
    let r = anon
        .send(
            "POST",
            "/gate",
            Some(b"code=open+sesame+gate+code".to_vec()),
            &h,
        )
        .await;
    assert_eq!(r.code, 403, "cross-site gate accepted");
    let r = reqwest::get(format!("{url}/healthz")).await.unwrap();
    assert_eq!(r.status().as_u16(), 200, "healthz");
    let r = anon
        .send(
            "POST",
            "/gate",
            Some(b"code=open+sesame+gate+code".to_vec()),
            &form,
        )
        .await;
    let ck = r.cookies();
    assert!(
        r.code == 303 && ck.len() == 1 && ck[0].contains("; HttpOnly"),
        "right code: {} {ck:?}",
        r.code
    );
    assert_eq!(r.header("location"), "/");
    assert!(
        ck[0].contains("SameSite=Lax")
            && ck[0].contains("Max-Age=2592000")
            && !ck[0].contains("Secure")
    );
    assert!(!ck[0].contains("sesame"), "token stored in cookie");
    let want = hex::encode(<Sha256 as sha2::Digest>::digest(
        b"ucanrun gate v1:open sesame gate code",
    ));
    assert!(ck[0].starts_with(&format!("ucr_gate={want};")), "{}", ck[0]);
    let r = anon.send("GET", "/api/status", None, &[]).await;
    assert_eq!(r.code, 200, "status after gate");
    assert_eq!(r.header("content-security-policy"), CSP);
    // The cookie opens only the gate: data still needs a login.
    assert_eq!(anon.send("GET", "/api/secrets", None, &[]).await.code, 401);
    assert_eq!(anon.send("GET", "/app.js", None, &[]).await.code, 200);
    // The agent API stays on its own port and does not use the gate.
    let cl = e.token("c", &[]).await;
    cl.profiles().await.unwrap();
    // A wrong cookie is no better than none.
    let other = Http::new(&url);
    other
        .jar
        .lock()
        .unwrap()
        .insert("ucr_gate".into(), "0".repeat(64));
    assert_eq!(other.send("GET", "/", None, &[]).await.code, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn gate_failures_share_the_login_backoff() {
    let e = bare(minute()).await;
    let mut s = Server::new(e.c.clone(), "", e.dir.join("audit.jsonl"), false);
    s.gate_token = "the right code".into();
    let (url, _) = start(s).await;
    let anon = Http::new(&url);
    let form = [("content-type", "application/x-www-form-urlencoded")];
    let mut codes = vec![];
    for _ in 0..4 {
        codes.push(
            anon.send("POST", "/gate", Some(b"code=nope".to_vec()), &form)
                .await
                .code,
        );
    }
    assert_eq!(codes, [401, 401, 401, 429]);
    let r = anon
        .send(
            "POST",
            "/gate",
            Some(b"code=the+right+code".to_vec()),
            &form,
        )
        .await;
    assert_eq!(r.code, 429, "right code during the backoff");
}

#[tokio::test(flavor = "multi_thread")]
async fn load_gate_token() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (a, created) = web::load_gate_token(dir.path(), "").unwrap();
    assert!(created && a.len() >= 20, "{a:?}");
    let mode = std::fs::metadata(dir.path().join("gate.token"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("gate.token")).unwrap(),
        format!("{a}\n")
    );
    let (b, created) = web::load_gate_token(dir.path(), "").unwrap();
    assert!(b == a && !created, "code changed on restart");
    let (c, _) = web::load_gate_token(dir.path(), "explicit").unwrap();
    assert_eq!(c, "explicit", "explicit value ignored");
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_off_by_default() {
    let e = setup(minute()).await;
    let p = json!({"name": "e", "risk": "low", "exec": {"argv": ["/usr/bin/git", "--version"]}});
    let (code, m) = e.req("PUT", "/api/profiles", p.clone()).await;
    assert_ne!(code, 200, "exec profile saved while exec is off");
    assert_eq!(m["error"], core::Error::ExecOff.to_string());
    let (_, m) = e
        .req("POST", "/api/profiles/preview", json!({"profile": p}))
        .await;
    assert!(m["error"].is_string(), "preview allowed exec");
    // A stored exec profile, as after turning the option off, must not run.
    let tmp = tempfile::tempdir().unwrap();
    let mut opt = core_opts(tmp.path(), "", minute());
    opt.allow_exec = true;
    let on = Core::new(opt.clone()).unwrap();
    on.setup(PASS.as_bytes()).unwrap();
    on.put_profile(serde_json::from_value::<Profile>(p).unwrap())
        .unwrap();
    let val = on.create_token("t", vec![]).unwrap();
    let tk = on.authenticate(&val).unwrap();
    on.lock("test");
    on.close();
    opt.allow_exec = false;
    let off = Core::new(opt).unwrap();
    off.login(PASS.as_bytes(), "").unwrap();
    assert!(
        off.submit(&tk, "e", Default::default(), "").is_err(),
        "stored exec profile ran"
    );
    off.close();
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_codes() {
    let e = setup(minute()).await;
    let (code, m) = e.req("POST", "/api/totp/start", Value::Null).await;
    assert_eq!(code, 200, "{m}");
    let sec = sid(&m, "secret");
    let c = totp::code(&sec, unix_now() - 30).unwrap();
    let (code, m) = e.req("POST", "/api/totp/confirm", json!({"code": c})).await;
    assert_eq!(code, 200, "{m}");
    let list: Vec<String> = serde_json::from_value(m["recovery_codes"].clone()).unwrap();
    assert!(list.len() == 8 && list[0].len() == 11, "{list:?}");
    let first = list[0].clone();
    let raw = std::fs::read_to_string(e.dir.join("state.json")).unwrap();
    assert!(!raw.contains(&first), "recovery code stored in plain text");
    e.req("POST", "/api/lock", Value::Null).await;
    let (code, _) = e
        .req(
            "POST",
            "/api/login",
            json!({"passphrase": PASS, "totp": "AAAAA-AAAAA"}),
        )
        .await;
    assert_eq!(code, 401, "made-up code accepted");
    // Lowercase and without a dash, as typed on a phone.
    let typed = first.replace('-', "").to_lowercase();
    let (code, m) = e
        .req(
            "POST",
            "/api/login",
            json!({"passphrase": PASS, "totp": typed}),
        )
        .await;
    assert_eq!(code, 200, "recovery login: {m}");
    assert_eq!(e.c.recovery_left(), 7);
    let (_, st) = e.req("GET", "/api/status", Value::Null).await;
    assert_eq!(st["recovery_left"], 7);
    e.req("POST", "/api/lock", Value::Null).await;
    tokio::time::sleep(Duration::from_millis(1100)).await; // past the backoff
    let (code, _) = e
        .req(
            "POST",
            "/api/login",
            json!({"passphrase": PASS, "totp": first}),
        )
        .await;
    assert_ne!(code, 200, "recovery code reused");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (code, m) = e
        .req(
            "POST",
            "/api/login",
            json!({"passphrase": PASS, "totp": list[1]}),
        )
        .await;
    assert_eq!(code, 200, "second code: {m}");
    // A recovery code must not approve high risk work.
    let cl = e.token("c", &[]).await;
    let r = cl
        .run("danger", params(&[("repo", "a")]), "", 0)
        .await
        .unwrap();
    let body = json!({"approve": true, "hash": r["hash"], "totp": list[2]});
    assert_ne!(
        e.decide(&sid(&r, "id"), body).await,
        200,
        "recovery code approved high risk"
    );
    // A new phone: passphrase plus a recovery code resets TOTP.
    let (code, m) = e
        .req(
            "POST",
            "/api/totp/reset",
            json!({"passphrase": "wrong wrong wrong", "code": list[2]}),
        )
        .await;
    assert_eq!(
        (code, m["error"].clone()),
        (401, json!("sai mật khẩu hoặc mã"))
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (code, m) = e
        .req(
            "POST",
            "/api/totp/reset",
            json!({"passphrase": PASS, "code": list[2]}),
        )
        .await;
    assert_eq!(code, 200, "reset: {m}");
    assert!(
        !e.c.totp_enabled() && e.c.recovery_left() == 0,
        "reset left TOTP on"
    );
    let sec2 = e.enable_totp().await;
    let now = totp::code(&sec2, unix_now()).unwrap();
    let (code, m) = e
        .req("POST", "/api/totp/recovery", json!({"code": now}))
        .await;
    assert!(
        code == 200 && m["recovery_codes"].as_array().unwrap().len() == 8,
        "{code} {m}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn telegram_speaks_english_by_default() {
    let tmp = tempfile::tempdir().unwrap();
    let mut opt = core_opts(tmp.path(), "", minute());
    opt.lang = String::new();
    let c = Core::new(opt.clone()).unwrap();
    assert_eq!(c.translate("sai mã TOTP"), "Wrong TOTP code");
    c.close();
    let tmp = tempfile::tempdir().unwrap();
    let vi = Core::new(core_opts(tmp.path(), "", minute())).unwrap();
    assert_eq!(vi.translate("sai mã TOTP"), "sai mã TOTP");
    vi.close();
}

#[tokio::test(flavor = "multi_thread")]
async fn newer_state_is_explained() {
    let e = setup(minute()).await;
    e.req("POST", "/api/lock", Value::Null).await;
    let p = e.dir.join("state.json");
    let f: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    let mut data = f["data"].clone();
    data["version"] = json!(99);
    let d = serde_json::to_vec(&data).unwrap();
    e.c.vault.unlock(PASS.as_bytes()).unwrap();
    let k = e.c.vault.mac_key().unwrap();
    e.c.vault.lock();
    let mut m = Hmac::<Sha256>::new_from_slice(&k).unwrap();
    m.update(&d);
    let mac = hex::encode(m.finalize().into_bytes());
    let out = format!(
        "{{\"mac\":\"{mac}\",\"data\":{}}}",
        String::from_utf8(d).unwrap()
    );
    std::fs::write(&p, out).unwrap();
    let (code, r) = e
        .req("POST", "/api/login", json!({"passphrase": PASS}))
        .await;
    assert!(
        code == 409 && r["error"].as_str().unwrap().contains("bản mới hơn"),
        "{code} {r}"
    );
    assert!(e.c.locked(), "unlocked with a newer state");
}

#[tokio::test(flavor = "multi_thread")]
async fn owner_test_run() {
    let e = setup(minute()).await;
    e.pair().await;
    let before = e.tg.dump().matches("reply_markup").count();
    let (code, m) = e
        .req(
            "POST",
            "/api/profiles/create/test",
            json!({"params": {"repo": "x"}}),
        )
        .await;
    assert!(code == 200 && m["state"] == "done", "{code} {m}");
    assert_eq!(e.got_auth(), format!("token {SECRET}"));
    assert!(!m.to_string().contains(SECRET), "secret in test run result");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        e.tg.dump().matches("reply_markup").count(),
        before,
        "test run sent an approval"
    );
    let (code, _) = e
        .req(
            "POST",
            "/api/profiles/create/test",
            json!({"params": {"repo": "../x"}}),
        )
        .await;
    assert_ne!(code, 200, "bad param accepted");
    // High risk still needs TOTP.
    let (code, _) = e
        .req(
            "POST",
            "/api/profiles/danger/test",
            json!({"params": {"repo": "x"}}),
        )
        .await;
    assert_ne!(code, 200, "high risk ran without TOTP");
    let n = e.hits();
    let sec = e.enable_totp().await;
    let c = totp::code(&sec, unix_now()).unwrap();
    let (code, m) = e
        .req(
            "POST",
            "/api/profiles/danger/test",
            json!({"params": {"repo": "x"}, "totp": c}),
        )
        .await;
    assert!(code == 200 && m["state"] == "done", "{code} {m}");
    assert_eq!(e.hits(), n + 1, "high risk did not run once");
    // Anonymous callers cannot use it.
    let anon = Http::new(&e.web);
    let r = anon
        .send(
            "POST",
            "/api/profiles/create/test",
            Some(b"{}".to_vec()),
            &[("content-type", "application/json")],
        )
        .await;
    assert!(r.code == 403 || r.code == 401, "anonymous: {}", r.code);
    let r = anon
        .send(
            "POST",
            "/api/profiles/create/test",
            Some(b"{}".to_vec()),
            &[("X-Ucanrun", "1")],
        )
        .await;
    assert_eq!(r.code, 401, "anonymous with the csrf header");
}

#[tokio::test(flavor = "multi_thread")]
async fn unlock_at_start() {
    let e = setup(minute()).await;
    e.pair().await;
    e.req("POST", "/api/lock", Value::Null).await;
    let c = e.c.clone();
    let r = tokio::task::spawn_blocking(move || c.unlock_at_start(b"wrong passphrase here"))
        .await
        .unwrap();
    assert!(r.is_err() && e.c.locked(), "wrong passphrase unlocked");
    let c = e.c.clone();
    tokio::task::spawn_blocking(move || c.unlock_at_start(PASS.as_bytes()))
        .await
        .unwrap()
        .unwrap();
    assert!(!e.c.locked());
    // The web still needs a full sign-in.
    assert_eq!(
        e.req("GET", "/api/secrets", Value::Null).await.0,
        401,
        "session after auto unlock"
    );
    let val = e.c.create_token("c", vec![]).unwrap();
    let cl = Client::new(&e.agent, &val);
    cl.profiles().await.expect("agents work after auto unlock");
}

#[tokio::test(flavor = "multi_thread")]
async fn connections() {
    let e = setup(minute()).await;
    let mut conn = json!({"name": "svc", "base_url": format!("{}/api", e.target_url),
        "auth": {"type": "bearer", "secret": "gitea"}, "headers": {"Accept": "application/json"}});
    let (code, m) = e.req("PUT", "/api/connections", conn.clone()).await;
    assert_eq!(code, 200, "{m}");
    assert_eq!(m["auth"]["type"], "bearer");
    let p = json!({"name": "svc-get", "risk": "low", "auto_approve": true, "connection": "svc",
        "params": [{"name": "id", "pattern": "[a-z0-9]{1,8}", "required": true}],
        "http": {"method": "GET", "url": "/items/{{id}}"}});
    let (code, m) = e.req("PUT", "/api/profiles", p).await;
    assert_eq!(code, 200, "{m}");
    let (_, l) = e.req("GET", "/api/connections", Value::Null).await;
    assert_eq!(l[0]["name"], "svc");
    let cl = e.token("c", &[]).await;
    let r = cl
        .run("svc-get", params(&[("id", "abc")]), "", 5)
        .await
        .unwrap();
    assert!(
        r["state"] == "done" && e.got_auth() == format!("Bearer {SECRET}"),
        "{r} {}",
        e.got_auth()
    );
    let d = r["display"].as_str().unwrap();
    assert!(
        d.contains("/api/items/abc") && !r.to_string().contains(SECRET),
        "{d}"
    );
    // A profile cannot take over the auth header or leave the host.
    let mut bad = json!({"name": "svc-bad", "risk": "low", "connection": "svc",
        "http": {"method": "GET", "url": "//evil.example/x"}});
    assert_ne!(
        e.req("PUT", "/api/profiles", bad.clone()).await.0,
        200,
        "protocol-relative"
    );
    bad["http"] = json!({"method": "GET", "url": "/x", "headers": {"Authorization": "Bearer {{secret:other}}"}});
    assert_ne!(
        e.req("PUT", "/api/profiles", bad).await.0,
        200,
        "auth header override"
    );
    let ghost = json!({"name": "svc-x", "risk": "low", "connection": "ghost",
        "http": {"method": "GET", "url": "/x"}});
    assert_ne!(
        e.req("PUT", "/api/profiles", ghost).await.0,
        200,
        "unknown connection"
    );
    // Moving the connection moves every profile on it.
    conn["base_url"] = json!(format!("{}/v2", e.target_url));
    let (code, m) = e.req("PUT", "/api/connections", conn).await;
    assert_eq!(code, 200, "{m}");
    let r = cl
        .run("svc-get", params(&[("id", "abc")]), "", 5)
        .await
        .unwrap();
    assert!(
        r["display"].as_str().unwrap().contains("/v2/items/abc"),
        "{r}"
    );
    // A change that would break a profile is refused as a whole.
    let broken =
        json!({"name": "svc", "base_url": "https://{{x}}.example", "auth": {"type": "none"}});
    assert_ne!(
        e.req("PUT", "/api/connections", broken).await.0,
        200,
        "broken connection"
    );
    let (code, m) = e.req("DELETE", "/api/connections/svc", Value::Null).await;
    assert!(
        code != 200 && m["error"] == "connection is used by: svc-get",
        "{code} {m}"
    );
    e.req("DELETE", "/api/profiles/svc-get", Value::Null).await;
    assert_eq!(
        e.req("DELETE", "/api/connections/svc", Value::Null).await.0,
        200
    );
    // Choosing the secret moves to the connection.
    e.pair().await;
    e.req(
        "PUT",
        "/api/secrets/other",
        json!({"value": "second-secret-value-42"}),
    )
    .await;
    let pick = json!({"name": "pick", "base_url": e.target_url,
        "auth": {"type": "token", "choices": ["gitea", "other"]}});
    assert_eq!(e.req("PUT", "/api/connections", pick).await.0, 200);
    let pm = json!({"name": "pick-me", "risk": "low", "connection": "pick", "http": {"method": "GET", "url": "/me"}});
    assert_eq!(e.req("PUT", "/api/profiles", pm).await.0, 200);
    let r = cl.run("pick-me", Value::Null, "", 0).await.unwrap();
    e.tg.last_button("Bấm tên secret").await;
    let h = sid(&r, "hash");
    e.tg.press(OWNER, OWNER, &format!("a:{}:{}:1", sid(&r, "id"), &h[..16]));
    e.wait(&sid(&r, "id"), ReqState::Done).await;
    assert_eq!(e.got_auth(), "token second-secret-value-42");
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_call_with_secret_notes() {
    let e = setup(minute()).await;
    e.pair().await;
    let host = e.target_url.trim_start_matches("http://").to_string();
    // A secret without allowed hosts is invisible to agents.
    let cl = e.token("c", &[]).await;
    assert_eq!(
        cl.secrets().await.unwrap(),
        json!([]),
        "listed a secret with no hosts"
    );
    let notes = json!({"description": "Token cho dịch vụ thử", "hosts": [host]});
    let (code, m) = e.req("PUT", "/api/secrets/gitea", notes).await;
    assert_eq!(code, 200, "{m}");
    let v = cl.secrets().await.unwrap().to_string();
    assert!(
        v.contains("Token cho dịch vụ thử") && !v.contains(SECRET),
        "{v}"
    );
    let call = json!({"http": {"method": "GET", "url": format!("{}/user", e.target_url),
        "headers": {"Authorization": "Bearer {{secret:gitea}}"}}});
    let r = cl.call(call.clone(), "xem tài khoản", 0).await.unwrap();
    e.tg.last_button("Agent tự soạn lệnh").await;
    assert_eq!(e.hits(), 0, "ran before approval");
    let h = sid(&r, "hash");
    e.tg.press(OWNER, OWNER, &format!("a:{}:{}", sid(&r, "id"), &h[..16]));
    let q = e.wait(&sid(&r, "id"), ReqState::Done).await;
    assert_eq!(e.got_auth(), format!("Bearer {SECRET}"));
    assert!(!q.result.unwrap().output.contains(SECRET));
    // Another host, the body, and a profile-limited token are refused.
    let refused = [
        (
            "other host",
            json!({"http": {"method": "GET", "url": "https://evil.example/x",
            "headers": {"Authorization": "Bearer {{secret:gitea}}"}}}),
        ),
        (
            "in body",
            json!({"http": {"method": "POST", "url": format!("{}/x", e.target_url),
            "body": "{{secret:gitea}}"}}),
        ),
        (
            "exec off",
            json!({"exec": {"argv": ["/usr/bin/env"], "env": {"T": "{{secret:gitea}}"}}}),
        ),
        (
            "unknown field",
            json!({"http": {"method": "GET", "url": format!("{}/x", e.target_url),
            "header": {"Authorization": "Bearer {{secret:gitea}}"}}}),
        ),
    ];
    for (name, c) in refused {
        assert!(cl.call(c, "", 0).await.is_err(), "{name} accepted");
    }
    let limited = e.token("narrow", &["create"]).await;
    assert!(
        limited.call(call, "", 0).await.is_err(),
        "profile-limited token made a call"
    );
    // Notes change without resending the value; a new secret needs one.
    let (code, _) = e
        .req(
            "PUT",
            "/api/secrets/gitea",
            json!({"description": "đổi mô tả"}),
        )
        .await;
    assert_eq!(code, 200, "notes-only update failed");
    let (code, m) = e
        .req("PUT", "/api/secrets/brand-new", json!({"description": "x"}))
        .await;
    assert_eq!(
        (code, m["error"].clone()),
        (400, json!("value is required for a new secret"))
    );
    let (code, _) = e
        .req(
            "PUT",
            "/api/secrets/gitea",
            json!({"hosts": ["https://bad"]}),
        )
        .await;
    assert_ne!(code, 200, "bad host accepted");
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_disabled_without_token() {
    let tmp = tempfile::tempdir().unwrap();
    let c = Core::new(core_opts(tmp.path(), "", minute())).unwrap();
    let (url, _) = start(Server::new(c.clone(), "", tmp.path().join("a"), false)).await;
    let h = Http::new(&url);
    let body = br#"{"setup_token":"","passphrase":"a long passphrase"}"#.to_vec();
    let r = h
        .send("POST", "/api/setup", Some(body), &[("X-Ucanrun", "1")])
        .await;
    assert_eq!(r.code, 403, "empty token setup");
    assert_eq!(r.json()["error"], "sai setup token");
    c.close();
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_over_stdio() {
    let e = setup(minute()).await;
    let cl = e.token("c", &[]).await;
    let input = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_profiles","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run","arguments":{"profile":"auto","params":{"repo":"m"}}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"nope"}"#,
    ]
    .join("\n")
        + "\n";
    let out = ucr(
        &[("UCANRUN_URL", &e.agent), ("UCANRUN_TOKEN", &cl.token)],
        &["mcp"],
        Some(&input),
    )
    .await;
    assert!(out.ok, "{}", out.stderr);
    let s = out.stdout;
    assert_eq!(s.matches('\n').count(), 5, "responses: {s}");
    for want in [
        r#""protocolVersion":"2025-06-18""#,
        r#""instructions":"ucanrun holds the user's secrets"#,
        "call list_secrets first",
        "get_request",
        "auto",
        r#"\"state\": \"done\""#,
        "-32601",
    ] {
        assert!(s.contains(want), "missing {want:?} in {s}");
    }
    assert!(
        !s.contains(SECRET) && !s.contains("get_secret"),
        "mcp leaks"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn health_endpoint() {
    let e = setup(minute()).await;
    e.c.vault.put("stray", b"stray-secret-value-123").unwrap();
    e.profile("ghost", "low", false).await;
    e.req(
        "PUT",
        "/api/secrets/stray2",
        json!({"value": "another-hidden-value"}),
    )
    .await;
    let r =
        e.hc.raw("GET", "/api/health", None, &[("X-Ucanrun", "1")])
            .await;
    assert_eq!(r.code, 200, "health: {}", r.text());
    for v in [SECRET, "stray-secret-value-123", "another-hidden-value"] {
        assert!(
            !r.text().contains(v),
            "health leaks a secret value: {}",
            r.text()
        );
    }
    let items: Vec<Value> = serde_json::from_slice(&r.body).unwrap();
    let by: HashMap<String, Value> = items.iter().map(|i| (sid(i, "key"), i.clone())).collect();
    assert_eq!(by["totp"]["level"], "bad");
    assert_eq!(by["gate"]["level"], "bad");
    assert_eq!(by["https"]["level"], "warn");
    assert_eq!(by["auto_write"]["level"], "warn");
    assert!(
        by["auto_write"]["names"]
            .as_array()
            .unwrap()
            .contains(&json!("auto"))
    );
    assert!(
        by["unused_secrets"]["names"]
            .as_array()
            .unwrap()
            .contains(&json!("stray"))
    );
    e.enable_totp().await;
    let r = e.hc.raw("GET", "/api/health", None, &[]).await;
    let items: Vec<Value> = serde_json::from_slice(&r.body).unwrap();
    for i in items {
        if i["key"] == "totp" {
            assert_eq!(i["level"], "ok", "totp after enable: {i}");
        }
    }
    // With the gate on and HTTPS, both items turn ok.
    let mut s = Server::new(e.c.clone(), "", e.dir.join("audit.jsonl"), true);
    s.gate_token = "g".into();
    let (url, _) = start(s).await;
    let h = Http::new(&url);
    h.jar.lock().unwrap().insert(
        "ucr_gate".into(),
        hex::encode(<Sha256 as sha2::Digest>::digest(b"ucanrun gate v1:g")),
    );
    let r = h.send("GET", "/", None, &[]).await;
    assert_eq!(r.header("strict-transport-security"), "max-age=31536000");
    h.jar.lock().unwrap().clear();
    let r = h.send("POST", "/api/login", None, &[]).await;
    assert_eq!(
        r.header("strict-transport-security"),
        "",
        "the gate page sets no HSTS"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn health_needs_session() {
    let e = setup(minute()).await;
    let anon = Http::new(&e.web);
    let r = anon
        .send("GET", "/api/health", None, &[("X-Ucanrun", "1")])
        .await;
    assert_eq!(r.code, 401, "health without session");
    assert_eq!(r.json()["error"], "chưa đăng nhập");
}

#[tokio::test(flavor = "multi_thread")]
async fn choice_on_connection_explains_auto_approve() {
    let e = setup(minute()).await;
    let g = json!({"name": "g", "base_url": e.target_url, "auth": {"type": "bearer", "secret": "gitea"}});
    e.req("PUT", "/api/connections", g).await;
    let p = json!({"name": "who", "risk": "low", "auto_approve": true, "connection": "g",
        "http": {"method": "GET", "url": "/user"}});
    e.req("PUT", "/api/profiles", p).await;
    let g2 = json!({"name": "g", "base_url": e.target_url, "auth": {"type": "bearer", "choices": ["gitea"]}});
    let (code, m) = e.req("PUT", "/api/connections", g2).await;
    let err = m["error"].as_str().unwrap_or("");
    assert!(
        code != 200 && err.contains(r#""who" would break: a secret choice needs a human"#),
        "{code} {m}"
    );
}

// --- catalog_test.go ---

#[test]
fn catalog_embedded_is_valid() {
    let cat = web::read_catalog(None);
    assert!(cat.len() >= 6, "only {} entries", cat.len());
    for e in &cat {
        if let Err(err) = web::valid_entry(e) {
            panic!("{:?}: {err}", e.service.as_ref().map(|s| &s.name));
        }
    }
}

#[test]
fn catalog_extra_dir() {
    let base = web::read_catalog(None).len();
    let dir = tempfile::tempdir().unwrap();
    let w = |name: &str, body: &str| std::fs::write(dir.path().join(name), body).unwrap();
    w(
        "a-good.json",
        r#"[{"service":{"name":"acme","base_url":"https://api.acme.example","auth":{"type":"bearer","secret":"acme_token"}},
      "hint":"x","actions":[{"title":"Ping","profile":{"name":"acme-ping","risk":"low","http":{"method":"GET","url":"/ping"}}}]}]"#,
    );
    w("b-broken.json", "[{");
    w(
        "c-badhost.json",
        r#"[{"service":{"name":"evil","base_url":"https://{{x}}.example","auth":{"type":"none"}},"actions":[{"title":"x","profile":{"name":"evil-x","risk":"low","http":{"method":"GET","url":"/"}}}]}]"#,
    );
    w(
        "d-escape.json",
        r#"[{"service":{"name":"esc","base_url":"https://a.example","auth":{"type":"none"}},"actions":[{"title":"x","profile":{"name":"esc-x","risk":"low","http":{"method":"GET","url":"//evil.example/"}}}]}]"#,
    );
    w(
        "e-dup.json",
        r#"[{"service":{"name":"github","base_url":"https://a.example","auth":{"type":"none"}},"actions":[{"title":"x","profile":{"name":"dup-x","risk":"low","http":{"method":"GET","url":"/"}}}]}]"#,
    );
    w(
        "f-dupaction.json",
        r#"[{"service":{"name":"other","base_url":"https://a.example","auth":{"type":"none"}},"actions":[{"title":"x","profile":{"name":"github-whoami","risk":"low","http":{"method":"GET","url":"/"}}}]}]"#,
    );
    std::os::unix::fs::symlink(
        dir.path().join("a-good.json"),
        dir.path().join("g-link.json"),
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("h-dir.json")).unwrap();
    w(
        "i-notjson.txt",
        &std::fs::read_to_string(dir.path().join("a-good.json"))
            .unwrap()
            .replace("acme", "txt"),
    );
    w("j-big.json", &format!("[{}]", " ".repeat(1 << 20)));
    let got = web::read_catalog(Some(dir.path()));
    assert_eq!(got.len(), base + 1, "want base plus acme");
    assert_eq!(got[base].service.as_ref().unwrap().name, "acme");
    assert_eq!(
        web::read_catalog(Some(&dir.path().join("missing"))).len(),
        base
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn catalog_over_http() {
    let e = setup(minute()).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("x.json"), r#"[{"title":"Mine","hint":"h","custom":true,"actions":[{"title":"t","profile":{"name":"mine-x","risk":"low","http":{"method":"GET","url":"https://a.example/"}}}]}]"#).unwrap();
    let mut s = Server::new(e.c.clone(), "", e.dir.join("audit.jsonl"), false);
    s.catalog_dir = Some(dir.path().to_path_buf());
    let (url, _) = start(s).await;
    let r = Http::new(&url)
        .send("GET", "/catalog.json", None, &[])
        .await;
    assert_eq!(r.code, 200);
    assert_eq!(r.header("content-type"), "application/json");
    let v = r.json();
    let last = v.as_array().unwrap().last().unwrap().clone();
    assert_eq!(last["title"], "Mine");
    assert_eq!(last["custom"], true);
    assert!(
        last.get("service").is_none() && last.get("title_en").is_none(),
        "{last}"
    );
    let r = e.hc.send("GET", "/catalog.json", None, &[]).await;
    assert_eq!(
        r.json().as_array().unwrap().len(),
        v.as_array().unwrap().len() - 1
    );
}

// --- secrets with several fields over HTTP ---

#[tokio::test(flavor = "multi_thread")]
async fn multi_field_secrets_over_http() {
    let e = setup(minute()).await;
    let host = e.target_url.trim_start_matches("http://").to_string();
    let db = |pass: &str, user: &str| {
        json!({"description": "Database", "hosts": [host],
            "fields": [{"name": "user", "public": true, "value": user},
                       {"name": "db", "public": true, "value": "shop"},
                       {"name": "password", "public": false, "value": pass}]})
    };
    let (code, m) = e.req("PUT", "/api/secrets/db", db("", "alice")).await;
    assert_eq!(
        (code, m["error"].clone()),
        (400, json!("field \"password\" needs a value"))
    );
    let (code, m) = e
        .req("PUT", "/api/secrets/db", db("pw-PRIVATE-998877", "alice"))
        .await;
    assert_eq!(code, 200, "{m}");
    let (code, m) = e.req("PUT", "/api/secrets/_db", db("x", "y")).await;
    assert_eq!(
        (code, m["error"].clone()),
        (400, json!("invalid secret name"))
    );
    let bad = json!({"fields": [{"name": "Bad Name", "public": true, "value": "x"}]});
    assert_eq!(e.req("PUT", "/api/secrets/db2", bad).await.0, 400);
    let shaped = json!({"value": r#"{"ucanrun_fields":{"a":"b"}}"#});
    assert_eq!(
        e.req("PUT", "/api/secrets/db3", shaped).await.0,
        400,
        "fields smuggled as a value"
    );

    // The owner sees public values, never the private one.
    let r = e.hc.raw("GET", "/api/secrets", None, &[]).await;
    assert!(!r.text().contains("pw-PRIVATE"), "{}", r.text());
    let list = r.json();
    let row = list
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "db")
        .unwrap()
        .clone();
    assert_eq!(row["description"], "Database");
    assert_eq!(
        row["fields"],
        json!([{"name": "user", "public": true, "value": "alice"},
               {"name": "db", "public": true, "value": "shop"},
               {"name": "password", "public": false}])
    );
    assert!(row["updated"].as_str().unwrap().ends_with('Z'));
    let gitea = list
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "gitea")
        .unwrap();
    assert!(gitea.get("fields").is_none(), "{gitea}");

    // An empty value keeps the stored one; a notes-only save keeps the fields.
    let (code, m) = e.req("PUT", "/api/secrets/db", db("", "bob")).await;
    assert_eq!(code, 200, "{m}");
    let (code, m) = e
        .req(
            "PUT",
            "/api/secrets/db",
            json!({"description": "DB", "hosts": [host]}),
        )
        .await;
    assert_eq!(code, 200, "{m}");
    let (_, list) = e.req("GET", "/api/secrets", Value::Null).await;
    let row = list
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "db")
        .unwrap()
        .clone();
    assert_eq!(
        (
            row["description"].clone(),
            row["fields"][0]["value"].clone()
        ),
        (json!("DB"), json!("bob"))
    );
    // Renaming fields needs the values again.
    let renamed = json!({"fields": [{"name": "login", "public": true, "value": ""}]});
    assert_eq!(e.req("PUT", "/api/secrets/db", renamed).await.0, 400);

    // Agents see the public values too.
    let cl = e.token("c", &[]).await;
    let v = cl.secrets().await.unwrap();
    assert!(!v.to_string().contains("pw-PRIVATE"), "{v}");
    let s = v
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "db")
        .unwrap();
    assert_eq!(
        s["fields"][0],
        json!({"name": "user", "public": true, "value": "bob"})
    );
    assert_eq!(s["fields"][2], json!({"name": "password", "public": false}));

    // A public field in the URL works, a private one goes in a header and is
    // redacted from the output.
    let call = json!({"http": {"method": "GET",
        "url": format!("{}/u/{{{{secret:db.user}}}}/{{{{secret:db.db}}}}", e.target_url),
        "headers": {"X-Pass": "{{secret:db.password}}"}}});
    let r = cl.call(call, "query", 0).await.unwrap();
    assert!(
        r["display"]
            .as_str()
            .unwrap()
            .contains("/u/‹secret:db.user›"),
        "{r}"
    );
    assert_eq!(
        e.decide(&sid(&r, "id"), json!({"approve": true, "hash": r["hash"]}))
            .await,
        200
    );
    let q = e.wait(&sid(&r, "id"), ReqState::Done).await;
    assert_eq!(*e.target.path.lock().unwrap(), "/u/bob/shop");
    assert_eq!(*e.target.pass.lock().unwrap(), "pw-PRIVATE-998877");
    let out = q.result.unwrap().output;
    assert!(
        !out.contains("pw-PRIVATE") && out.contains("[REDACTED]"),
        "{out}"
    );
    let got = cl.request(&sid(&r, "id")).await.unwrap();
    assert!(!got.to_string().contains("pw-PRIVATE"));

    // A private field may not go in the URL, and a bare name is ambiguous.
    for c in [
        json!({"http": {"method": "GET", "url": format!("{}/p/{{{{secret:db.password}}}}", e.target_url)}}),
        json!({"http": {"method": "GET", "url": format!("{}/x", e.target_url),
            "headers": {"X-Pass": "{{secret:db}}"}}}),
    ] {
        assert!(cl.call(c.clone(), "", 0).await.is_err(), "{c}");
    }
    let (code, m) = e.req("DELETE", "/api/secrets/db", Value::Null).await;
    assert_eq!(code, 200, "{m}");
    assert_eq!(e.req("DELETE", "/api/secrets/db", Value::Null).await.0, 404);
}

// --- web details ---

#[tokio::test(flavor = "multi_thread")]
async fn static_files_and_routing() {
    let e = bare(minute()).await;
    let h = Http::new(&e.web);
    for (p, ct) in [
        ("/", "text/html; charset=utf-8"),
        ("/app.js", "text/javascript; charset=utf-8"),
        ("/i18n.js", "text/javascript; charset=utf-8"),
        ("/style.css", "text/css; charset=utf-8"),
        ("/manifest.webmanifest", "application/manifest+json"),
        ("/logo.svg", "image/svg+xml"),
        ("/icon-192.png", "image/png"),
    ] {
        let r = h.send("GET", p, None, &[]).await;
        assert_eq!(
            (r.code, r.header("content-type").as_str()),
            (200, ct),
            "{p}"
        );
        assert_eq!(r.header("content-security-policy"), CSP, "{p}");
    }
    let r = h.send("GET", "/", None, &[]).await;
    assert!(r.text().contains("<script src=\"app.js\"></script>"));
    let r = h.send("GET", "/index.html", None, &[]).await;
    assert_eq!((r.code, r.header("location")), (301, "./".to_string()));
    let r = h.send("GET", "/nope.js", None, &[]).await;
    assert_eq!(
        (r.code, r.text()),
        (404, "404 page not found\n".to_string())
    );
    assert_eq!(r.header("x-frame-options"), "DENY");
    // As with Go's mux, a GET of a write-only path reaches the file server,
    // and other methods are not allowed.
    assert_eq!(h.send("GET", "/api/lock", None, &[]).await.code, 404);
    assert_eq!(
        h.send("DELETE", "/api/lock", None, &[("X-Ucanrun", "1")])
            .await
            .code,
        405
    );
    assert_eq!(
        h.send("PUT", "/nope", None, &[("X-Ucanrun", "1")])
            .await
            .code,
        405
    );
    assert_eq!(h.send("HEAD", "/app.js", None, &[]).await.code, 200);
    let r = h.send("GET", "/healthz", None, &[]).await;
    assert_eq!((r.code, r.json()), (200, json!({"ok": true})));
    let r = reqwest::get(format!("{}/healthz", e.agent)).await.unwrap();
    assert!(r.headers().get("content-security-policy").is_none());
    let r = reqwest::Client::new()
        .post(format!("{}/v1/profiles", e.agent))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 405);
    let (code, m) = h.req("GET", "/api/status", None).await;
    assert_eq!(
        (code, m),
        (
            200,
            json!({"initialized": false, "locked": true, "authed": false})
        )
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn json_decoding_is_strict() {
    let e = setup(minute()).await;
    let bad_json = |code: u16, m: &Value| code == 400 && m["error"] == "JSON không hợp lệ";
    for body in [
        json!({"name": "x", "nope": 1}),
        json!({"name": "x", "risk": "low", "http": {"method": "GET", "url": "https://a.example/", "evil": 1}}),
        json!({"name": "x", "risk": "low", "params": [{"name": "a", "pattern": ".", "kind": "x"}]}),
        json!({"name": 5}),
        json!([1]),
    ] {
        let (code, m) = e.req("PUT", "/api/profiles", body.clone()).await;
        assert!(bad_json(code, &m), "{body}: {code} {m}");
    }
    let raw = |b: &[u8]| Some(b.to_vec());
    let h = [("X-Ucanrun", "1")];
    for b in [&b""[..], b"{", b"not json"] {
        let r = e.hc.send("POST", "/api/tokens", raw(b), &h).await;
        assert!(
            bad_json(r.code, &r.json()),
            "{:?}",
            String::from_utf8_lossy(b)
        );
    }
    // Like Go's Decoder: only the first value counts, and null is empty.
    let r =
        e.hc.send(
            "POST",
            "/api/tokens",
            raw(br#"{"name":"first"} trailing"#),
            &h,
        )
        .await;
    assert_eq!(r.code, 200, "{}", r.text());
    let r = e.hc.send("POST", "/api/login", raw(b"null"), &h).await;
    assert_eq!(r.code, 401);
    let r =
        e.hc.send(
            "POST",
            "/api/tokens",
            raw(br#"{"name":"n","profiles":null}"#),
            &h,
        )
        .await;
    assert_eq!(r.code, 200, "{}", r.text());
    // The body limit is 256 KiB.
    let big = format!(r#"{{"name":"big","x":"{}"}}"#, "a".repeat(256 << 10));
    let r =
        e.hc.send("POST", "/api/tokens", raw(big.as_bytes()), &h)
            .await;
    assert!(bad_json(r.code, &r.json()));
    let fits = format!(
        r#"{{"sample":{{"a":"{}"}},"profile":{{"name":"p"}}}}"#,
        "a".repeat(200 << 10)
    );
    let r =
        e.hc.send("POST", "/api/profiles/preview", raw(fits.as_bytes()), &h)
            .await;
    assert_eq!(r.code, 200);
    // The agent API decodes the same way.
    let cl = e.token("c", &[]).await;
    let http = reqwest::Client::new();
    let post = |b: Value| {
        http.post(format!("{}/v1/requests", e.agent))
            .bearer_auth(&cl.token)
            .json(&b)
            .send()
    };
    let r = post(json!({"profile": "auto", "params": {"repo": "a"}, "wat": 1}))
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    let r = post(json!({"profile": "auto", "params": {"repo": "a"}, "wait_sec": 5}))
        .await
        .unwrap();
    assert_eq!(r.json::<Value>().await.unwrap()["state"], "done");
    let r = post(json!({"profile": "nope"})).await.unwrap();
    assert_eq!(
        (r.status().as_u16(), r.json::<Value>().await.unwrap()),
        (404, json!({"error": "not found"}))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions() {
    let e = setup(minute()).await;
    e.req("POST", "/api/lock", Value::Null).await;
    let h = [("X-Ucanrun", "1")];
    let r =
        e.hc.raw("POST", "/api/login", Some(json!({"passphrase": PASS})), &h)
            .await;
    assert_eq!(r.code, 200);
    let ck = r.cookies();
    assert_eq!(ck.len(), 1);
    let c = &ck[0];
    let tok = c
        .strip_prefix("ucr_session=")
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    assert_eq!(tok.len(), 43, "32 bytes base64url: {c}");
    assert!(
        c.ends_with("; Path=/; Max-Age=43200; HttpOnly; SameSite=Strict"),
        "{c}"
    );
    let (_, st) = e.req("GET", "/api/status", Value::Null).await;
    assert_eq!(st["authed"], true);
    assert_eq!(
        st["telegram"],
        json!({"configured": false, "paired": false})
    );
    assert_eq!(
        (st["totp"].clone(), st["exec"].clone()),
        (json!(false), json!(false))
    );
    // Another browser with a made-up cookie gets nothing.
    let other = Http::new(&e.web);
    other
        .jar
        .lock()
        .unwrap()
        .insert("ucr_session".into(), "x".repeat(43));
    assert_eq!(
        other.send("GET", "/api/profiles", None, &[]).await.code,
        401
    );
    // Logging out ends the session.
    assert_eq!(e.req("POST", "/api/logout", Value::Null).await.0, 200);
    assert_eq!(e.req("GET", "/api/profiles", Value::Null).await.0, 401);
    let (_, st) = e.req("GET", "/api/status", Value::Null).await;
    assert_eq!(
        st,
        json!({"initialized": true, "locked": false, "authed": false})
    );
    // A secure server marks cookies Secure.
    let s = Server::new(e.c.clone(), "", e.dir.join("audit.jsonl"), true);
    let (url, _) = start(s).await;
    let r = Http::new(&url)
        .raw("POST", "/api/login", Some(json!({"passphrase": PASS})), &h)
        .await;
    assert!(
        r.cookies()[0].contains("; HttpOnly; Secure; SameSite=Strict"),
        "{:?}",
        r.cookies()
    );
    assert_eq!(r.header("strict-transport-security"), "max-age=31536000");
}

#[tokio::test(flavor = "multi_thread")]
async fn passphrase_change_and_audit() {
    let e = setup(minute()).await;
    let (code, m) = e
        .req(
            "POST",
            "/api/passphrase",
            json!({"old": PASS, "new": "short"}),
        )
        .await;
    assert_eq!(
        (code, m["error"].clone()),
        (400, json!("mật khẩu mới quá ngắn"))
    );
    let (code, m) = e
        .req(
            "POST",
            "/api/passphrase",
            json!({"old": "wrong wrong wrong", "new": "a brand new passphrase"}),
        )
        .await;
    assert_eq!(
        (code, m["error"].clone()),
        (400, json!("mật khẩu cũ không đúng"))
    );
    let (code, _) = e
        .req(
            "POST",
            "/api/passphrase",
            json!({"old": PASS, "new": "a brand new passphrase"}),
        )
        .await;
    assert_eq!(code, 200);
    let (code, a) = e.req("GET", "/api/audit", Value::Null).await;
    assert_eq!(code, 200);
    assert_eq!(a["chain_ok"], true);
    assert_eq!(a["truncated"], false);
    let entries = a["entries"].as_array().unwrap();
    assert_eq!(entries[0]["event"], "passphrase_changed");
    assert_eq!(
        a["valid_entries"].as_u64().unwrap() as usize,
        audit::verify(&e.dir.join("audit.jsonl")).unwrap()
    );
    e.req("POST", "/api/lock", Value::Null).await;
    assert_eq!(
        e.req("POST", "/api/login", json!({"passphrase": PASS}))
            .await
            .0,
        401
    );
    let (code, _) = e
        .req(
            "POST",
            "/api/login",
            json!({"passphrase": "a brand new passphrase"}),
        )
        .await;
    assert_eq!(code, 200);
    let (code, l) = e.req("GET", "/api/requests", Value::Null).await;
    assert_eq!((code, l), (200, json!([])));
    let (code, t) = e.req("GET", "/api/tokens", Value::Null).await;
    assert_eq!((code, t), (200, json!([])));
}

// --- the ucr binary ---

struct Out {
    ok: bool,
    code: i32,
    stdout: String,
    stderr: String,
}

async fn ucr(env: &[(&str, &str)], args: &[&str], stdin: Option<&str>) -> Out {
    use tokio::io::AsyncWriteExt;
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_ucr"));
    cmd.args(args)
        .env_remove("UCANRUN_URL")
        .env_remove("UCANRUN_TOKEN")
        .env_remove("UCANRUN_DATA")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let mut sin = child.stdin.take().unwrap();
    if let Some(s) = stdin {
        // The child may exit without reading stdin; a closed pipe is fine.
        if let Err(e) = sin.write_all(s.as_bytes()).await {
            assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
        }
    }
    drop(sin);
    let o = child.wait_with_output().await.unwrap();
    Out {
        ok: o.status.success(),
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_agent_commands() {
    // Short, because `ucr run` waits for a pending request until it expires.
    let e = setup(Duration::from_secs(2)).await;
    let cl = e.token("c", &[]).await;
    let env = [
        ("UCANRUN_URL", e.agent.as_str()),
        ("UCANRUN_TOKEN", cl.token.as_str()),
    ];
    let o = ucr(&env, &["profiles"], None).await;
    assert!(
        o.ok && o.stdout.contains("\"name\": \"auto\""),
        "{} {}",
        o.stdout,
        o.stderr
    );
    let o = ucr(
        &env,
        &["run", "auto", "repo=a", "--reason", "cli test"],
        None,
    )
    .await;
    assert!(
        o.ok && o.stdout.contains("\"state\": \"done\""),
        "{} {}",
        o.stdout,
        o.stderr
    );
    let o = ucr(&env, &["run", "create", "repo=../x"], None).await;
    assert!(
        !o.ok && o.stderr.starts_with("ucr: ucanrun: "),
        "{}",
        o.stderr
    );
    let o = ucr(&env, &["run", "create", "oops"], None).await;
    assert_eq!(o.stderr, "ucr: param \"oops\" must be k=v\n");
    let o = ucr(&env, &["run", "create", "repo=b"], None).await;
    assert_eq!(o.code, 1, "pending is not done");
    let o = ucr(&env, &["doctor"], None).await;
    assert!(
        o.ok && o.stdout.starts_with("OK  token: token found\n"),
        "{}",
        o.stdout
    );
    let o = ucr(
        &[
            ("UCANRUN_URL", "http://127.0.0.1:1"),
            ("HOME", "/nonexistent"),
        ],
        &["doctor"],
        None,
    )
    .await;
    assert!(
        !o.ok && o.stdout.contains("FAIL token: missing"),
        "{}",
        o.stdout
    );
    let o = ucr(&[("HOME", "/nonexistent")], &["profiles"], None).await;
    assert_eq!(
        o.stderr,
        "ucr: no agent token: set UCANRUN_TOKEN or ~/.config/ucanrun/token\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_data_commands() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let d = data.to_str().unwrap();
    let env = [("UCANRUN_DATA", d)];
    let o = ucr(&[], &["version"], None).await;
    assert_eq!(o.stdout, format!("ucr {}\n", env!("CARGO_PKG_VERSION")));
    let o = ucr(&[], &[], None).await;
    assert!(o.code == 2 && o.stdout.starts_with("ucr: credential broker"));
    let o = ucr(&[], &["bogus"], None).await;
    assert_eq!(o.code, 2);
    assert!(ucr(&[], &["help"], None).await.stdout.contains("ucr mcp"));
    // A vault must exist before secrets can be added.
    let c = Core::new(core_opts(&data, "", minute())).unwrap();
    let cc = c.clone();
    tokio::task::spawn_blocking(move || cc.setup(PASS.as_bytes()))
        .await
        .unwrap()
        .unwrap();
    c.lock("test");
    c.close();
    let o = ucr(&env, &["add", "api_key"], Some("the-value-123\n")).await;
    assert!(o.ok, "{}", o.stderr);
    let o = ucr(&env, &["add", "_internal"], Some("x\n")).await;
    assert_eq!(o.stderr, "ucr: invalid secret name\n");
    assert_eq!(
        ucr(&env, &["add"], None).await.stderr,
        "ucr: usage: ucr add NAME\n"
    );
    let o = ucr(&env, &["list"], None).await;
    assert!(
        o.stdout.starts_with("api_key\t") && o.stdout.trim_end().ends_with('Z'),
        "{}",
        o.stdout
    );
    let o = ucr(&env, &["gate"], None).await;
    let code = o.stdout.trim().to_string();
    assert_eq!(code.len(), 24);
    assert_eq!(ucr(&env, &["gate"], None).await.stdout.trim(), code);
    let o = ucr(
        &[("UCANRUN_DATA", d), ("UCANRUN_GATE_TOKEN", "mine")],
        &["gate"],
        None,
    )
    .await;
    assert_eq!(o.stdout, "mine\n");
    let o = ucr(&env, &["audit-verify"], None).await;
    assert!(
        o.ok && o.stdout.starts_with("OK: ") && o.stdout.ends_with(" entries\n"),
        "{}",
        o.stdout
    );
    let file = tmp.path().join("b.tar.gz");
    let f = file.to_str().unwrap();
    let o = ucr(&env, &["backup", f], None).await;
    assert!(o.ok, "{}", o.stderr);
    let o = ucr(&env, &["backup-check", f], None).await;
    assert!(
        o.ok && o.stdout.starts_with("OK: "),
        "{} {}",
        o.stdout,
        o.stderr
    );
    let o = ucr(&env, &["backup-check", "-"], Some("not a backup")).await;
    assert!(!o.ok && o.stderr.starts_with("ucr: "));
    let restored = tmp.path().join("restored");
    let r = [("UCANRUN_DATA", restored.to_str().unwrap())];
    let o = ucr(&r, &["restore", f], None).await;
    assert!(o.ok, "{}", o.stderr);
    assert!(
        ucr(&r, &["list"], None)
            .await
            .stdout
            .starts_with("api_key\t")
    );
    let o = ucr(&env, &["rm", "api_key"], None).await;
    assert!(o.ok, "{}", o.stderr);
    assert_eq!(ucr(&env, &["list"], None).await.stdout, "");
    assert_eq!(
        ucr(&env, &["rm"], None).await.stderr,
        "ucr: usage: ucr rm NAME\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_serve_and_health() {
    use tokio::io::AsyncBufReadExt;
    let tmp = tempfile::tempdir().unwrap();
    let free = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string()
    };
    let (web_addr, agent_addr) = (free(), free());
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_ucr"))
        .arg("serve")
        .env("UCANRUN_DATA", tmp.path().join("data"))
        .env("UCANRUN_WEB_ADDR", &web_addr)
        .env("UCANRUN_AGENT_ADDR", &agent_addr)
        .env_remove("UCANRUN_PUBLIC_URL")
        .env_remove("UCANRUN_GATE")
        .env_remove("UCANRUN_GATE_TOKEN")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
    let mut got = vec![];
    for _ in 0..3 {
        got.push(lines.next_line().await.unwrap().unwrap());
    }
    assert!(
        got[0].starts_with("ucanrun is not set up yet. Setup token: "),
        "{got:?}"
    );
    assert!(got[1].starts_with("Access code: "), "{got:?}");
    let port = web_addr.rsplit_once(':').unwrap().1;
    assert_eq!(
        got[2],
        format!(
            "Open http://127.0.0.1:{port} to finish setup. Show the access code again with: ucr gate"
        )
    );
    let env = [("UCANRUN_WEB_ADDR", web_addr.as_str())];
    let mut ok = false;
    for _ in 0..100 {
        if ucr(&env, &["health"], None).await.ok {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ok, "ucr health never passed");
    let gate = got[1].trim_start_matches("Access code: ");
    let r = reqwest::get(format!("http://{web_addr}/api/status"))
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401, "gated by default");
    assert_eq!(gate.len(), 24);
    let id = child.id().unwrap() as i32;
    // SAFETY: signals our own child process.
    unsafe { libc::kill(id, libc::SIGTERM) };
    let st = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(st.success(), "{st:?}");
    let o = ucr(&env, &["health"], None).await;
    assert!(!o.ok && o.stderr.starts_with("ucr: "));
}
