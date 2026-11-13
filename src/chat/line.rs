//! LINE Messaging API: a bot account with a webhook.
//!
//! LINE signs each webhook with the channel secret (HMAC-SHA256, base64 in
//! `x-line-signature`), which is checked before the body is read. Pairing is
//! `/pair CODE` in a chat with the bot; approval is a postback button, and a
//! TOTP code is the next message.

use std::sync::Arc;
use std::time::SystemTime;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};

use super::{
    BoxFut, Channel, Common, Hook, Outcome, Owner, Reply, Settings, clip, data, hmac_ok,
    parse_press,
};
use crate::telegram::{Handler, Translate};

pub const API: &str = "https://api.line.me";

pub struct Line {
    c: Common,
}

/// Checks a channel access token; returns the bot's display name.
pub async fn check(base: &str, token: &str) -> Result<String, String> {
    let base = if base.is_empty() { API } else { base };
    let r = reqwest::Client::new()
        .get(format!("{base}/v2/bot/info"))
        .bearer_auth(token)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    if !r.status().is_success() {
        return Err(format!("LINE answered HTTP {}", r.status().as_u16()));
    }
    let v: Value = r.json().await.map_err(|e| e.to_string())?;
    Ok(v["displayName"].as_str().unwrap_or("").to_string())
}

impl Line {
    pub fn new(
        settings: Settings,
        owner: Owner,
        handler: Arc<dyn Handler>,
        translate: Translate,
        base: &str,
    ) -> Arc<Line> {
        let base = if base.is_empty() {
            API.to_string()
        } else {
            base.to_string()
        };
        Arc::new(Line {
            c: Common::new("line", settings, owner, handler, translate, base),
        })
    }

    async fn post(&self, path: &str, body: Value) -> Result<(), String> {
        let r = self
            .c
            .http
            .post(format!("{}{path}", self.c.base))
            .bearer_auth(&self.c.settings.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if !r.status().is_success() {
            return Err(format!("LINE HTTP {}", r.status().as_u16()));
        }
        Ok(())
    }

    async fn reply(&self, token: &str, text: &str) {
        if token.is_empty() {
            return;
        }
        let _ = self
            .post("/v2/bot/message/reply", json!({"replyToken": token, "messages": [{"type": "text", "text": clip(text, 4900)}]}))
            .await;
    }

    async fn push(&self, text: &str) -> Result<(), String> {
        let o = self.c.owner();
        if o.chat.is_empty() {
            return Err("not paired".into());
        }
        self.post(
            "/v2/bot/message/push",
            json!({"to": o.chat, "messages": [{"type": "text", "text": clip(text, 4900)}]}),
        )
        .await
    }

    async fn event(&self, e: &Value) {
        let user = e
            .pointer("/source/userId")
            .and_then(Value::as_str)
            .unwrap_or("");
        let one_to_one = e.pointer("/source/type").and_then(Value::as_str) == Some("user");
        let token = e["replyToken"].as_str().unwrap_or("");
        match e["type"].as_str().unwrap_or("") {
            "message" => {
                let text = e
                    .pointer("/message/text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                if let Some(code) = text.strip_prefix("/pair ") {
                    if one_to_one && self.c.pair(code, user, user) {
                        self.reply(
                            token,
                            &self
                                .c
                                .t("Đã ghép nối. Từ giờ chỉ tài khoản này được duyệt yêu cầu."),
                        )
                        .await;
                    }
                    return;
                }
                if !self.c.is_owner(user) {
                    return; // stay silent for strangers
                }
                if let Some(m) = self.c.code(user, text) {
                    self.reply(token, &m).await;
                }
            }
            "postback" => {
                if !self.c.is_owner(user) {
                    return;
                }
                let d = e
                    .pointer("/postback/data")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let Some(p) = parse_press(d) else { return };
                let id = p.id.clone();
                match self.c.press(user, &p, "") {
                    Outcome::Done(m) => self.reply(token, &m).await,
                    Outcome::NeedCode => self.reply(token, &self.c.need_code_text(&id)).await,
                }
            }
            _ => {}
        }
    }
}

impl Channel for Line {
    fn kind(&self) -> &'static str {
        "line"
    }

    fn notify<'a>(
        &'a self,
        id: &'a str,
        short: &'a str,
        text: &'a str,
        choices: &'a [String],
    ) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            let o = self.c.owner();
            if o.chat.is_empty() {
                return Err("not paired".into());
            }
            let act = |label: String, d: String| json!({"type": "postback", "label": clip(&label, 20), "data": d});
            let mut actions: Vec<Value> = if choices.is_empty() {
                vec![act(self.c.t("Duyệt"), data(true, id, short, None))]
            } else {
                choices
                    .iter()
                    .take(3)
                    .enumerate()
                    .map(|(i, n)| act(n.clone(), data(true, id, short, Some(i))))
                    .collect()
            };
            actions.push(act(self.c.t("Từ chối"), data(false, id, short, None)));
            let label = if choices.len() > 3 {
                self.c.t("Chọn secret trên web nếu không có ở đây.")
            } else {
                self.c.t("Duyệt yêu cầu?")
            };
            self.post("/v2/bot/message/push", json!({"to": o.chat, "messages": [
                {"type": "text", "text": clip(text, 4900)},
                {"type": "template", "altText": clip(&self.c.t("Duyệt yêu cầu?"), 400),
                 "template": {"type": "buttons", "text": clip(&label, 160), "actions": actions}},
            ]}))
            .await
            .inspect_err(|e| self.c.error(e))
        })
    }

    fn finish<'a>(&'a self, _id: &'a str, text: &'a str) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let _ = self.push(text).await;
        })
    }

    fn webhook<'a>(&'a self, h: Hook<'a>) -> BoxFut<'a, Reply> {
        Box::pin(async move {
            let sig = B64.decode(h.header("x-line-signature")).unwrap_or_default();
            if h.method != "POST"
                || sig.is_empty()
                || !hmac_ok(self.c.settings.key.as_bytes(), h.body, &sig)
            {
                return Reply::unauthorized();
            }
            self.c.seen();
            let Ok(v) = serde_json::from_slice::<Value>(h.body) else {
                return Reply::text(400, "bad json");
            };
            for e in v["events"].as_array().into_iter().flatten().take(20) {
                self.event(e).await;
            }
            Reply::ok()
        })
    }

    fn link(&self) -> (Option<SystemTime>, String) {
        self.c.link()
    }
}

#[cfg(test)]
mod unit {
    use super::*;
    use crate::chat::fake;
    use hmac::{Hmac, Mac};

    fn hook_for(secret: &str, body: &str, method: &str) -> (Vec<u8>, String, String) {
        let mut m = <Hmac<sha2::Sha256> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
        m.update(body.as_bytes());
        (
            body.as_bytes().to_vec(),
            B64.encode(m.finalize().into_bytes()),
            method.into(),
        )
    }

    async fn send(l: &Line, secret: &str, v: &Value) -> Reply {
        let (b, sig, m) = hook_for(secret, &v.to_string(), "POST");
        let headers = vec![("x-line-signature".to_string(), sig)];
        l.webhook(Hook {
            method: &m,
            query: "",
            headers: &headers,
            body: &b,
        })
        .await
    }

    #[tokio::test]
    async fn signature_pairing_postback_and_code() {
        let core = Arc::new(fake::Core {
            code: "PAIR#1".into(),
            totp: true,
            ..Default::default()
        });
        let s = Settings {
            token: "t".into(),
            key: "chan-secret".into(),
            ..Default::default()
        };
        let l = Line::new(
            s,
            Owner::default(),
            core.clone(),
            fake::translate(),
            "http://127.0.0.1:1",
        );
        let msg = |user: &str, text: &str| json!({"events": [{"type": "message", "source": {"type": "user", "userId": user}, "message": {"type": "text", "text": text}}]});
        assert_eq!(
            send(&l, "wrong-secret", &msg("U1", "/pair PAIR#1"))
                .await
                .status,
            401
        );
        assert!(!l.c.is_owner("U1"));
        assert_eq!(
            send(&l, "chan-secret", &msg("U1", "/pair PAIR#1"))
                .await
                .status,
            200
        );
        assert!(l.c.is_owner("U1"));
        let pb = |user: &str, d: &str| json!({"events": [{"type": "postback", "source": {"type": "user", "userId": user}, "postback": {"data": d}}]});
        send(&l, "chan-secret", &pb("U2", "a:ab12:cd34")).await;
        send(&l, "chan-secret", &pb("U1", "a:ab12:cd34")).await;
        assert!(
            core.decided.lock().unwrap().is_empty(),
            "waits for the code"
        );
        send(&l, "chan-secret", &msg("U2", "123456")).await;
        assert!(
            core.decided.lock().unwrap().is_empty(),
            "a stranger's code does nothing"
        );
        send(&l, "chan-secret", &msg("U1", "123456")).await;
        assert_eq!(
            core.decided.lock().unwrap()[0],
            (
                "ab12".into(),
                true,
                "line:U1".into(),
                "123456".into(),
                String::new()
            )
        );
    }
}
