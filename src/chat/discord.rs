//! Discord: a bot that receives interactions over HTTP.
//!
//! The owner gives a bot token; the application id and its public key come
//! from Discord. Discord signs every interaction with that key (ed25519 over
//! timestamp and body), which is checked before anything is read. Pairing is
//! the slash command `/pair` in a direct message with the bot; approval is a
//! button, and TOTP is asked for in a form.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Value, json};

use super::{
    BoxFut, Channel, Common, Hook, Outcome, Owner, Reply, Settings, clip, data, parse_press,
};
use crate::telegram::{Handler, Translate};

pub const API: &str = "https://discord.com/api/v10";
/// Interactions older than this are refused as replays.
const MAX_AGE_SECS: i64 = 300;
const EPHEMERAL: u64 = 64;

pub struct Discord {
    c: Common,
    key: Option<VerifyingKey>,
    msgs: Mutex<HashMap<String, String>>,
}

/// What `check` learns from a token.
#[derive(Debug, Clone, Default)]
pub struct App {
    pub id: String,
    pub name: String,
    pub public_key: String,
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client")
}

/// Checks a bot token and reads the application's id and public key. Also
/// registers the `/pair` command, usable in direct messages.
pub async fn check(base: &str, token: &str) -> Result<App, String> {
    let base = if base.is_empty() { API } else { base };
    let h = http();
    let r = h
        .get(format!("{base}/applications/@me"))
        .header("authorization", format!("Bot {token}"))
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    if !r.status().is_success() {
        return Err(format!("Discord answered HTTP {}", r.status().as_u16()));
    }
    let v: Value = r.json().await.map_err(|e| e.to_string())?;
    let app = App {
        id: v["id"].as_str().unwrap_or("").into(),
        name: v["name"].as_str().unwrap_or("").into(),
        public_key: v["verify_key"].as_str().unwrap_or("").into(),
    };
    if app.id.is_empty() || app.public_key.len() != 64 {
        return Err("Discord did not return the application id and key".into());
    }
    let cmd = json!([{
        "name": "pair", "type": 1,
        "description": "Pair with ucanrun / Ghép nối với ucanrun",
        "options": [{"type": 3, "name": "code", "description": "Pairing code", "required": true}],
        "integration_types": [0, 1], "contexts": [1],
    }]);
    let r = h
        .put(format!("{base}/applications/{}/commands", app.id))
        .header("authorization", format!("Bot {token}"))
        .json(&cmd)
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    if !r.status().is_success() {
        return Err(format!(
            "could not register /pair: HTTP {}",
            r.status().as_u16()
        ));
    }
    Ok(app)
}

impl Discord {
    pub fn new(
        settings: Settings,
        owner: Owner,
        handler: Arc<dyn Handler>,
        translate: Translate,
        base: &str,
    ) -> Arc<Discord> {
        let key = hex::decode(&settings.key)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| VerifyingKey::from_bytes(&b).ok());
        let base = if base.is_empty() {
            API.to_string()
        } else {
            base.to_string()
        };
        Arc::new(Discord {
            c: Common::new("discord", settings, owner, handler, translate, base),
            key,
            msgs: Mutex::new(HashMap::new()),
        })
    }

    /// Discord's signature over timestamp and body, and a fresh timestamp.
    fn signed(&self, h: &Hook) -> bool {
        let Some(key) = &self.key else { return false };
        let ts = h.header("x-signature-timestamp");
        let Ok(t) = ts.parse::<i64>() else {
            return false;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        if (now - t).abs() > MAX_AGE_SECS {
            return false;
        }
        let Some(sig) = hex::decode(h.header("x-signature-ed25519"))
            .ok()
            .and_then(|b| Signature::from_slice(&b).ok())
        else {
            return false;
        };
        let mut msg = ts.into_bytes();
        msg.extend_from_slice(h.body);
        key.verify_strict(&msg, &sig).is_ok()
    }

    async fn api(&self, method: reqwest::Method, path: &str, body: Value) -> Result<Value, String> {
        let r = self
            .c
            .http
            .request(method, format!("{}{path}", self.c.base))
            .header("authorization", format!("Bot {}", self.c.settings.token))
            .json(&body)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        let ok = r.status().is_success();
        let code = r.status().as_u16();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        if !ok {
            return Err(format!("Discord HTTP {code}"));
        }
        Ok(v)
    }

    fn say(&self, text: &str) -> Reply {
        Reply::json(
            &json!({"type": 4, "data": {"content": clip(text, 1900), "flags": EPHEMERAL, "allowed_mentions": {"parse": []}}}),
        )
    }

    async fn interaction(&self, v: &Value) -> Reply {
        let user = v
            .pointer("/user/id")
            .or_else(|| v.pointer("/member/user/id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let custom = v
            .pointer("/data/custom_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        match v["type"].as_u64().unwrap_or(0) {
            1 => Reply::json(&json!({"type": 1})),
            2 => {
                if v.pointer("/data/name").and_then(Value::as_str) != Some("pair") {
                    return self.say("?");
                }
                if v.get("guild_id").is_some() {
                    return self.say(&self.c.t("Hãy dùng lệnh này trong tin nhắn riêng với bot."));
                }
                let code = v
                    .pointer("/data/options/0/value")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let chat = v["channel_id"]
                    .as_str()
                    .or_else(|| v.pointer("/channel/id").and_then(Value::as_str))
                    .unwrap_or("");
                if self.c.pair(code, &user, chat) {
                    self.say(
                        &self
                            .c
                            .t("Đã ghép nối. Từ giờ chỉ tài khoản này được duyệt yêu cầu."),
                    )
                } else {
                    self.say(&self.c.t("Mã ghép nối sai hoặc đã hết hạn."))
                }
            }
            3 => {
                if !self.c.is_owner(&user) {
                    return self.say(&self.c.t("Không có quyền"));
                }
                let Some(p) = parse_press(custom) else {
                    return self.say(&self.c.t("Dữ liệu sai"));
                };
                match self.c.press(&user, &p, "") {
                    Outcome::Done(m) => self.say(&m),
                    Outcome::NeedCode => Reply::json(&json!({"type": 9, "data": {
                        "custom_id": format!("t:{custom}"),
                        "title": clip(&self.c.t("Mã TOTP"), 45),
                        "components": [{"type": 1, "components": [{"type": 4, "custom_id": "code", "style": 1,
                            "label": clip(&self.c.t("Mã TOTP 6 số"), 45), "min_length": 6, "max_length": 6, "required": true}]}],
                    }})),
                }
            }
            5 => {
                if !self.c.is_owner(&user) {
                    return self.say(&self.c.t("Không có quyền"));
                }
                let Some(p) = custom.strip_prefix("t:").and_then(parse_press) else {
                    return self.say(&self.c.t("Dữ liệu sai"));
                };
                let code = v
                    .pointer("/data/components/0/components/0/value")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                if !super::is_code(code) {
                    return self.say(&self.c.t("sai mã TOTP"));
                }
                match self.c.press(&user, &p, code) {
                    Outcome::Done(m) => self.say(&m),
                    Outcome::NeedCode => self.say(&self.c.t("cần mã TOTP")),
                }
            }
            _ => Reply::text(400, "unknown interaction"),
        }
    }
}

impl Channel for Discord {
    fn kind(&self) -> &'static str {
        "discord"
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
            let btn = |label: String, style: u8, id: String| json!({"type": 2, "style": style, "label": clip(&label, 80), "custom_id": id});
            let mut buttons: Vec<Value> = if choices.is_empty() {
                vec![btn(self.c.t("Duyệt"), 3, data(true, id, short, None))]
            } else {
                choices
                    .iter()
                    .take(19)
                    .enumerate()
                    .map(|(i, n)| {
                        btn(
                            format!("{} {n}", self.c.t("Duyệt với")),
                            1,
                            data(true, id, short, Some(i)),
                        )
                    })
                    .collect()
            };
            buttons.push(btn(self.c.t("Từ chối"), 4, data(false, id, short, None)));
            let rows: Vec<Value> = buttons
                .chunks(5)
                .map(|c| json!({"type": 1, "components": c}))
                .collect();
            let v = self
                .api(reqwest::Method::POST, &format!("/channels/{}/messages", o.chat), json!({
                    "content": clip(text, 1900), "allowed_mentions": {"parse": []}, "components": rows,
                }))
                .await
                .inspect_err(|e| self.c.error(e))?;
            if let Some(m) = v["id"].as_str() {
                self.msgs
                    .lock()
                    .unwrap()
                    .insert(id.to_string(), m.to_string());
            }
            Ok(())
        })
    }

    fn finish<'a>(&'a self, id: &'a str, text: &'a str) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let o = self.c.owner();
            let Some(m) = self.msgs.lock().unwrap().remove(id) else {
                return;
            };
            let _ = self
                .api(reqwest::Method::PATCH, &format!("/channels/{}/messages/{m}", o.chat), json!({
                    "content": clip(text, 1900), "components": [], "allowed_mentions": {"parse": []},
                }))
                .await;
        })
    }

    fn webhook<'a>(&'a self, h: Hook<'a>) -> BoxFut<'a, Reply> {
        Box::pin(async move {
            if h.method != "POST" || !self.signed(&h) {
                return Reply::unauthorized();
            }
            self.c.seen();
            let Ok(v) = serde_json::from_slice::<Value>(h.body) else {
                return Reply::text(400, "bad json");
            };
            self.interaction(&v).await
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
    use ed25519_dalek::{Signer, SigningKey};

    fn bot(core: Arc<fake::Core>, owner: Owner) -> (Arc<Discord>, SigningKey) {
        let k = SigningKey::generate(&mut rand::rngs::OsRng);
        let s = Settings {
            token: "t".into(),
            key: hex::encode(k.verifying_key().to_bytes()),
            id: "app".into(),
            ..Default::default()
        };
        (
            Discord::new(s, owner, core, fake::translate(), "http://127.0.0.1:1"),
            k,
        )
    }

    async fn send(d: &Discord, k: &SigningKey, body: &Value, age: i64) -> Reply {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - age;
        let raw = body.to_string();
        let ts = now.to_string();
        let mut msg = ts.clone().into_bytes();
        msg.extend_from_slice(raw.as_bytes());
        let sig = hex::encode(k.sign(&msg).to_bytes());
        let headers = vec![
            ("x-signature-timestamp".to_string(), ts),
            ("x-signature-ed25519".to_string(), sig),
        ];
        d.webhook(Hook {
            method: "POST",
            query: "",
            headers: &headers,
            body: raw.as_bytes(),
        })
        .await
    }

    fn body(r: &Reply) -> Value {
        serde_json::from_slice(&r.body).unwrap()
    }

    #[tokio::test]
    async fn signature_age_and_ping() {
        let (d, k) = bot(Arc::new(fake::Core::default()), Owner::default());
        let ping = json!({"type": 1});
        assert_eq!(body(&send(&d, &k, &ping, 0).await)["type"], 1);
        assert_eq!(
            send(&d, &k, &ping, 3600).await.status,
            401,
            "old interactions are replays"
        );
        let other = SigningKey::generate(&mut rand::rngs::OsRng);
        assert_eq!(send(&d, &other, &ping, 0).await.status, 401);
        let r = d
            .webhook(Hook {
                method: "POST",
                query: "",
                headers: &[],
                body: b"{}",
            })
            .await;
        assert_eq!(r.status, 401);
    }

    #[tokio::test]
    async fn pair_in_dm_then_buttons_and_totp_form() {
        let core = Arc::new(fake::Core {
            code: "PAIR#1".into(),
            totp: true,
            ..Default::default()
        });
        let (d, k) = bot(core.clone(), Owner::default());
        let pair = |code: &str, guild: bool| {
            let mut v = json!({"type": 2, "user": {"id": "42"}, "channel_id": "dm9", "data": {"name": "pair", "options": [{"value": code}]}});
            if guild {
                v["guild_id"] = json!("g");
            }
            v
        };
        assert!(
            body(&send(&d, &k, &pair("PAIR#1", true), 0).await)["data"]["content"]
                .as_str()
                .unwrap()
                .contains("riêng")
        );
        assert!(!d.c.is_owner("42"));
        send(&d, &k, &pair("WRONG", false), 0).await;
        assert!(!d.c.is_owner("42"));
        send(&d, &k, &pair("PAIR#1", false), 0).await;
        assert!(d.c.is_owner("42"));
        assert_eq!(d.c.owner().chat, "dm9");

        let press = |user: &str, custom: &str| json!({"type": 3, "user": {"id": user}, "data": {"custom_id": custom}});
        let r = body(&send(&d, &k, &press("7", "a:ab12:cd34"), 0).await);
        assert!(
            r["data"]["content"]
                .as_str()
                .unwrap()
                .contains("Không có quyền")
        );
        // TOTP needed: a form comes back instead of a decision.
        let r = body(&send(&d, &k, &press("42", "a:ab12:cd34:1"), 0).await);
        assert_eq!(r["type"], 9);
        assert_eq!(r["data"]["custom_id"], "t:a:ab12:cd34:1");
        assert!(core.decided.lock().unwrap().is_empty());
        let submit = json!({"type": 5, "user": {"id": "42"}, "data": {"custom_id": "t:a:ab12:cd34:1",
            "components": [{"components": [{"value": "123456"}]}]}});
        send(&d, &k, &submit, 0).await;
        let got = core.decided.lock().unwrap().clone();
        assert_eq!(
            got,
            vec![(
                "ab12".into(),
                true,
                "discord:42".into(),
                "123456".into(),
                "gh_b".into()
            )]
        );
        // Deny needs no code.
        send(&d, &k, &press("42", "d:ab12:cd34"), 0).await;
        assert_eq!(core.decided.lock().unwrap().len(), 2);
    }
}
