//! Approval channel on Telegram: long polling, inline buttons, a TOTP reply for
//! high risk requests. Messages are plain text so agent-influenced text cannot
//! add formatting or links.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};

/// Implemented by the core. Identity is checked here before it is called.
pub trait Handler: Send + Sync {
    fn decide(
        &self,
        id: &str,
        short: &str,
        approve: bool,
        actor: &str,
        totp: &str,
        secret: &str,
    ) -> Result<String, String>;
    fn needs_totp(&self, id: &str) -> bool;
    fn secret_at(&self, id: &str, index: usize) -> Option<String>;
    fn pair(&self, code: &str, user_id: i64, chat_id: i64) -> bool;
}

pub type Translate = Arc<dyn Fn(&str) -> String + Send + Sync>;

#[derive(Clone, Default)]
pub struct Config {
    pub base_url: String,
    pub token: String,
    pub user_id: i64,
    pub chat_id: i64,
    pub translate: Option<Translate>,
}

struct Pending {
    id: String,
    short: String,
    secret: String,
    until: Instant,
}

pub struct Bot {
    cfg: RwLock<Config>,
    handler: Option<Arc<dyn Handler>>,
    http: reqwest::Client,
    waiting: Mutex<HashMap<i64, Pending>>,
    msgs: Mutex<HashMap<String, i64>>,
    /// When a poll last succeeded, and the last poll error, for the overview.
    link: Mutex<(Option<std::time::SystemTime>, String)>,
}

#[derive(Deserialize)]
struct Envelope {
    ok: bool,
    #[serde(default)]
    result: Value,
    #[serde(default)]
    description: String,
}

impl Bot {
    pub fn new(mut cfg: Config, handler: Option<Arc<dyn Handler>>) -> Arc<Bot> {
        if cfg.base_url.is_empty() {
            cfg.base_url = "https://api.telegram.org".into();
        }
        // A reused connection that died silently hangs until the timeout, which
        // would delay an approval. Requests are rare, so open one each time.
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(40))
            .pool_max_idle_per_host(0)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("http client");
        Arc::new(Bot {
            cfg: RwLock::new(cfg),
            handler,
            http,
            waiting: Mutex::new(HashMap::new()),
            msgs: Mutex::new(HashMap::new()),
            link: Mutex::new((None, String::new())),
        })
    }

    fn t(&self, s: &str) -> String {
        match &self.cfg.read().unwrap().translate {
            Some(f) => f(s),
            None => s.to_string(),
        }
    }

    fn owner(&self) -> (i64, i64) {
        let c = self.cfg.read().unwrap();
        (c.user_id, c.chat_id)
    }

    fn authorized(&self, user: i64, chat: i64) -> bool {
        let (u, c) = self.owner();
        u != 0 && user == u && chat == c
    }

    /// Never lets the token reach an error: reqwest errors embed the URL, and
    /// the URL holds the token.
    async fn call(
        &self,
        method: &str,
        body: Value,
        timeout: Option<Duration>,
    ) -> Result<Value, String> {
        let (base, token) = {
            let c = self.cfg.read().unwrap();
            (c.base_url.clone(), c.token.clone())
        };
        let mut req = self
            .http
            .post(format!("{base}/bot{token}/{method}"))
            .json(&body);
        if let Some(t) = timeout {
            req = req.timeout(t);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("telegram {method}: {}", e.without_url()))?;
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("telegram {method}: {}", e.without_url()))?;
        let env: Envelope = serde_json::from_slice(&bytes[..bytes.len().min(1 << 20)])
            .map_err(|_| format!("telegram {method}: bad response"))?;
        if !env.ok {
            return Err(format!("telegram {method}: {}", env.description));
        }
        Ok(env.result)
    }

    pub async fn check(&self) -> Result<String, String> {
        let me = self
            .call("getMe", json!({}), Some(Duration::from_secs(15)))
            .await?;
        Ok(me
            .get("username")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string())
    }

    fn keyboard(&self, id: &str, short: &str, choices: &[String]) -> Value {
        let deny = json!({"text": format!("❌ {}", self.t("Từ chối")), "callback_data": format!("d:{id}:{short}")});
        if choices.is_empty() {
            return json!({"inline_keyboard": [[{"text": format!("✅ {}", self.t("Duyệt")), "callback_data": format!("a:{id}:{short}")}, deny]]});
        }
        let mut rows: Vec<Value> = choices
            .iter()
            .enumerate()
            .map(|(i, n)| json!([{"text": format!("✅ {} {n}", self.t("Dùng")), "callback_data": format!("a:{id}:{short}:{i}")}]))
            .collect();
        rows.push(json!([deny]));
        json!({"inline_keyboard": rows})
    }

    /// Sends an approval request. A second copy is harmless because each
    /// decision applies once; a lost message leaves the agent waiting.
    pub async fn notify(
        &self,
        id: &str,
        short: &str,
        text: &str,
        choices: &[String],
    ) -> Result<(), String> {
        let (_, chat) = self.owner();
        let body = json!({"chat_id": chat, "text": text, "reply_markup": self.keyboard(id, short, choices), "disable_web_page_preview": true});
        let mut last = Err(String::new());
        for _ in 0..2 {
            last = self
                .call("sendMessage", body.clone(), Some(Duration::from_secs(15)))
                .await;
            if last.is_ok() {
                break;
            }
        }
        let m = last?;
        if let Some(mid) = m.get("message_id").and_then(Value::as_i64) {
            self.msgs.lock().unwrap().insert(id.to_string(), mid);
        }
        Ok(())
    }

    /// Replaces the message text and removes the buttons.
    pub async fn finish(&self, id: &str, text: &str) {
        let Some(mid) = self.msgs.lock().unwrap().remove(id) else {
            return;
        };
        let (_, chat) = self.owner();
        if let Err(e) = self
            .call(
                "editMessageText",
                json!({"chat_id": chat, "message_id": mid, "text": text}),
                None,
            )
            .await
        {
            eprintln!("WARN telegram finish: {e}");
        }
    }

    async fn say(&self, chat: i64, text: &str) {
        if let Err(e) = self
            .call("sendMessage", json!({"chat_id": chat, "text": text}), None)
            .await
        {
            eprintln!("WARN telegram say: {e}");
        }
    }

    /// Polls until `stop` fires. Old updates are skipped first, so a button
    /// pressed while the service was down cannot act later.
    pub async fn run(self: Arc<Self>, mut stop: tokio::sync::watch::Receiver<bool>) {
        let mut offset: i64 = 0;
        if let Ok(Value::Array(old)) = self
            .call("getUpdates", json!({"offset": -1, "timeout": 0}), None)
            .await
            && let Some(id) = old
                .last()
                .and_then(|u| u.get("update_id"))
                .and_then(Value::as_i64)
        {
            offset = id + 1;
        }
        let mut backoff = Duration::from_secs(1);
        loop {
            if *stop.borrow() {
                return;
            }
            let poll = self.call("getUpdates", json!({"offset": offset, "timeout": 25, "allowed_updates": ["message", "callback_query"]}), None);
            let res = tokio::select! {
                r = poll => r,
                _ = stop.changed() => return,
            };
            match res {
                Ok(Value::Array(ups)) => {
                    backoff = Duration::from_secs(1);
                    *self.link.lock().unwrap() =
                        (Some(std::time::SystemTime::now()), String::new());
                    for u in ups {
                        if let Some(id) = u.get("update_id").and_then(Value::as_i64) {
                            offset = id + 1;
                        }
                        self.handle(&u).await;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("WARN telegram poll: {e}");
                    self.link.lock().unwrap().1 = e.to_string().chars().take(200).collect();
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = stop.changed() => return,
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
        }
    }

    /// The last successful poll and the last error since then.
    pub fn link(&self) -> (Option<std::time::SystemTime>, String) {
        self.link.lock().unwrap().clone()
    }

    async fn handle(&self, u: &Value) {
        let Some(h) = self.handler.clone() else {
            return;
        };
        if let Some(c) = u.get("callback_query") {
            return self.handle_callback(h.as_ref(), c).await;
        }
        let Some(m) = u.get("message") else { return };
        if m.pointer("/from/is_bot")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return;
        }
        let from = m.pointer("/from/id").and_then(Value::as_i64).unwrap_or(0);
        let chat = m.pointer("/chat/id").and_then(Value::as_i64).unwrap_or(0);
        let text = m
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if let Some(code) = text.strip_prefix("/pair ") {
            let private = m.pointer("/chat/type").and_then(Value::as_str) == Some("private");
            if private && h.pair(code.trim(), from, chat) {
                {
                    let mut c = self.cfg.write().unwrap();
                    c.user_id = from;
                    c.chat_id = chat;
                }
                self.say(
                    chat,
                    &self.t("Đã ghép nối. Từ giờ chỉ tài khoản này được duyệt yêu cầu."),
                )
                .await;
            }
            return;
        }
        if !self.authorized(from, chat) {
            return; // stay silent for strangers
        }
        if text.len() != 6 || !text.bytes().all(|b| b.is_ascii_digit()) {
            return;
        }
        let pending = self.waiting.lock().unwrap().remove(&from);
        let Some(p) = pending.filter(|p| Instant::now() < p.until) else {
            self.say(chat, &self.t("Không có yêu cầu nào đang chờ mã."))
                .await;
            return;
        };
        let msg = match h.decide(
            &p.id,
            &p.short,
            true,
            &format!("telegram:{from}"),
            &text,
            &p.secret,
        ) {
            Ok(m) => self.t(&m),
            Err(e) => format!("{} {}", self.t("Không duyệt được:"), self.t(&e)),
        };
        self.say(chat, &msg).await;
    }

    async fn handle_callback(&self, h: &dyn Handler, c: &Value) {
        let cid = c
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let answer = |t: String| {
            let body = json!({"callback_query_id": cid, "text": self.t(&t)});
            async move {
                if let Err(e) = self.call("answerCallbackQuery", body, None).await {
                    eprintln!("WARN telegram answer: {e}");
                }
            }
        };
        let from = c.pointer("/from/id").and_then(Value::as_i64).unwrap_or(0);
        let chat = c.pointer("/message/chat/id").and_then(Value::as_i64);
        let Some(chat) = chat.filter(|&ch| self.authorized(from, ch)) else {
            return answer("Không có quyền".into()).await;
        };
        let data = c.get("data").and_then(Value::as_str).unwrap_or("");
        let parts: Vec<&str> = data.split(':').collect();
        if parts.len() != 3 && parts.len() != 4 {
            return answer("Dữ liệu sai".into()).await;
        }
        let (approve, id, short) = (parts[0] == "a", parts[1], parts[2]);
        let mut secret = String::new();
        if parts.len() == 4 {
            match parts[3]
                .parse::<usize>()
                .ok()
                .and_then(|i| h.secret_at(id, i))
            {
                Some(n) => secret = n,
                None => return answer("Lựa chọn không hợp lệ".into()).await,
            }
        }
        if approve && h.needs_totp(id) {
            self.waiting.lock().unwrap().insert(
                from,
                Pending {
                    id: id.into(),
                    short: short.into(),
                    secret,
                    until: Instant::now() + Duration::from_secs(120),
                },
            );
            answer("Cần mã TOTP".into()).await;
            let msg = format!(
                "{} {id}. {}",
                self.t("Yêu cầu rủi ro cao"),
                self.t("Gửi mã TOTP 6 số trong 2 phút.")
            );
            return self.say(chat, &msg).await;
        }
        match h.decide(id, short, approve, &format!("telegram:{from}"), "", &secret) {
            Ok(m) => answer(m).await,
            Err(e) => answer(e).await,
        }
    }
}
