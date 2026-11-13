//! WhatsApp Cloud API: a business phone number with a webhook.
//!
//! Meta signs each webhook with the app secret (HMAC-SHA256, hex in
//! `x-hub-signature-256`); the one-time GET that sets the webhook up must echo
//! the verify token. Pairing is `/pair CODE` from the owner's phone; approval
//! is a reply button, and a TOTP code is the next message.
//!
//! WhatsApp only delivers free text to someone who wrote in the last 24
//! hours. Outside that window a request still waits on the web.

use std::sync::Arc;
use std::time::SystemTime;

use serde_json::{Value, json};
use subtle::ConstantTimeEq;

use super::{
    BoxFut, Channel, Common, Hook, Outcome, Owner, Reply, Settings, clip, data, hmac_ok,
    parse_press,
};
use crate::telegram::{Handler, Translate};

pub const API: &str = "https://graph.facebook.com/v21.0";

pub struct WhatsApp {
    c: Common,
}

/// Checks the access token against the phone number id; returns the number.
pub async fn check(base: &str, token: &str, phone_id: &str) -> Result<String, String> {
    let base = if base.is_empty() { API } else { base };
    if phone_id.is_empty() || !phone_id.bytes().all(|b| b.is_ascii_digit()) {
        return Err("the phone number id is digits only".into());
    }
    let r = reqwest::Client::new()
        .get(format!(
            "{base}/{phone_id}?fields=display_phone_number,verified_name"
        ))
        .bearer_auth(token)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    if !r.status().is_success() {
        return Err(format!("WhatsApp answered HTTP {}", r.status().as_u16()));
    }
    let v: Value = r.json().await.map_err(|e| e.to_string())?;
    Ok(v["display_phone_number"].as_str().unwrap_or("").to_string())
}

fn query(q: &str, key: &str) -> String {
    url::form_urlencoded::parse(q.as_bytes())
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

impl WhatsApp {
    pub fn new(
        settings: Settings,
        owner: Owner,
        handler: Arc<dyn Handler>,
        translate: Translate,
        base: &str,
    ) -> Arc<WhatsApp> {
        let base = if base.is_empty() {
            API.to_string()
        } else {
            base.to_string()
        };
        Arc::new(WhatsApp {
            c: Common::new("whatsapp", settings, owner, handler, translate, base),
        })
    }

    async fn send(&self, body: Value) -> Result<(), String> {
        let r = self
            .c
            .http
            .post(format!("{}/{}/messages", self.c.base, self.c.settings.id))
            .bearer_auth(&self.c.settings.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if !r.status().is_success() {
            return Err(format!("WhatsApp HTTP {}", r.status().as_u16()));
        }
        Ok(())
    }

    async fn text(&self, to: &str, text: &str) -> Result<(), String> {
        self.send(json!({"messaging_product": "whatsapp", "to": to, "type": "text", "text": {"body": clip(text, 4000)}}))
            .await
    }

    async fn message(&self, m: &Value) {
        let from = m["from"].as_str().unwrap_or("");
        match m["type"].as_str().unwrap_or("") {
            "text" => {
                let text = m
                    .pointer("/text/body")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                if let Some(code) = text.strip_prefix("/pair ") {
                    if self.c.pair(code, from, from) {
                        let _ = self
                            .text(
                                from,
                                &self
                                    .c
                                    .t("Đã ghép nối. Từ giờ chỉ tài khoản này được duyệt yêu cầu."),
                            )
                            .await;
                    }
                    return;
                }
                if !self.c.is_owner(from) {
                    return; // stay silent for strangers
                }
                if let Some(msg) = self.c.code(from, text) {
                    let _ = self.text(from, &msg).await;
                }
            }
            "interactive" => {
                if !self.c.is_owner(from) {
                    return;
                }
                let d = m
                    .pointer("/interactive/button_reply/id")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let Some(p) = parse_press(d) else { return };
                let id = p.id.clone();
                let msg = match self.c.press(from, &p, "") {
                    Outcome::Done(m) => m,
                    Outcome::NeedCode => self.c.need_code_text(&id),
                };
                let _ = self.text(from, &msg).await;
            }
            _ => {}
        }
    }
}

impl Channel for WhatsApp {
    fn kind(&self) -> &'static str {
        "whatsapp"
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
            let btn = |title: String, d: String| json!({"type": "reply", "reply": {"id": d, "title": clip(&title, 20)}});
            let mut buttons: Vec<Value> = if choices.is_empty() {
                vec![btn(self.c.t("Duyệt"), data(true, id, short, None))]
            } else {
                choices
                    .iter()
                    .take(2)
                    .enumerate()
                    .map(|(i, n)| btn(n.clone(), data(true, id, short, Some(i))))
                    .collect()
            };
            buttons.push(btn(self.c.t("Từ chối"), data(false, id, short, None)));
            let mut body = clip(text, 1000);
            if choices.len() > 2 {
                body = clip(
                    &format!(
                        "{body}\n\n{}",
                        self.c.t("Chọn secret trên web nếu không có ở đây.")
                    ),
                    1024,
                );
            }
            self.send(json!({"messaging_product": "whatsapp", "to": o.chat, "type": "interactive",
                "interactive": {"type": "button", "body": {"text": body}, "action": {"buttons": buttons}}}))
                .await
                .inspect_err(|e| self.c.error(e))
        })
    }

    fn finish<'a>(&'a self, _id: &'a str, text: &'a str) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let o = self.c.owner();
            if !o.chat.is_empty() {
                let _ = self.text(&o.chat, text).await;
            }
        })
    }

    fn webhook<'a>(&'a self, h: Hook<'a>) -> BoxFut<'a, Reply> {
        Box::pin(async move {
            if h.method == "GET" {
                // Webhook setup: echo the challenge only for our verify token.
                let token = query(h.query, "hub.verify_token");
                let ok = query(h.query, "hub.mode") == "subscribe"
                    && !self.c.settings.verify.is_empty()
                    && bool::from(token.as_bytes().ct_eq(self.c.settings.verify.as_bytes()));
                if !ok {
                    return Reply::unauthorized();
                }
                let challenge: String = query(h.query, "hub.challenge")
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .take(64)
                    .collect();
                return Reply::text(200, &challenge);
            }
            let sig = h.header("x-hub-signature-256");
            let sig = sig
                .strip_prefix("sha256=")
                .and_then(|s| hex::decode(s).ok())
                .unwrap_or_default();
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
            let msgs = v["entry"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|e| e["changes"].as_array().cloned().unwrap_or_default())
                .flat_map(|c| {
                    c.pointer("/value/messages")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default()
                })
                .take(20)
                .collect::<Vec<_>>();
            for m in &msgs {
                self.message(m).await;
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

    fn wa(core: Arc<fake::Core>) -> Arc<WhatsApp> {
        let s = Settings {
            token: "t".into(),
            key: "app-secret".into(),
            id: "123".into(),
            verify: "vt-abc".into(),
        };
        WhatsApp::new(
            s,
            Owner::default(),
            core,
            fake::translate(),
            "http://127.0.0.1:1",
        )
    }

    async fn post(w: &WhatsApp, secret: &str, v: &Value) -> Reply {
        let raw = v.to_string();
        let mut m = <Hmac<sha2::Sha256> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
        m.update(raw.as_bytes());
        let sig = format!("sha256={}", hex::encode(m.finalize().into_bytes()));
        let headers = vec![("x-hub-signature-256".to_string(), sig)];
        w.webhook(Hook {
            method: "POST",
            query: "",
            headers: &headers,
            body: raw.as_bytes(),
        })
        .await
    }

    fn msgs(m: Value) -> Value {
        json!({"entry": [{"changes": [{"value": {"messages": [m]}}]}]})
    }

    #[tokio::test]
    async fn verify_signature_pairing_buttons() {
        let core = Arc::new(fake::Core {
            code: "PAIR#1".into(),
            ..Default::default()
        });
        let w = wa(core.clone());
        let ok = "hub.mode=subscribe&hub.verify_token=vt-abc&hub.challenge=987";
        let bad = "hub.mode=subscribe&hub.verify_token=nope&hub.challenge=987";
        assert_eq!(
            w.webhook(Hook {
                method: "GET",
                query: ok,
                headers: &[],
                body: b""
            })
            .await
            .body,
            b"987"
        );
        assert_eq!(
            w.webhook(Hook {
                method: "GET",
                query: bad,
                headers: &[],
                body: b""
            })
            .await
            .status,
            401
        );
        let text =
            |from: &str, t: &str| msgs(json!({"from": from, "type": "text", "text": {"body": t}}));
        assert_eq!(
            post(&w, "wrong", &text("84900", "/pair PAIR#1"))
                .await
                .status,
            401
        );
        post(&w, "app-secret", &text("84900", "/pair PAIR#1")).await;
        assert!(w.c.is_owner("84900"));
        let press = |from: &str, id: &str| {
            msgs(
                json!({"from": from, "type": "interactive", "interactive": {"type": "button_reply", "button_reply": {"id": id}}}),
            )
        };
        post(&w, "app-secret", &press("111", "a:ab12:cd34")).await;
        assert!(core.decided.lock().unwrap().is_empty());
        post(&w, "app-secret", &press("84900", "d:ab12:cd34")).await;
        assert!(!core.decided.lock().unwrap()[0].1);
        assert_eq!(core.decided.lock().unwrap()[0].2, "whatsapp:84900");
    }
}
