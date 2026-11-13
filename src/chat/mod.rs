//! Approval channels besides Telegram: Discord, LINE and WhatsApp.
//!
//! Each platform calls ucanrun back through a webhook under `/hooks/<kind>`.
//! Those paths skip the access gate, so every request must carry the
//! platform's own signature, checked here before anything else is read.
//! Only the paired account may decide; everyone else gets no answer.
//!
//! Button data is `a:<id>:<short>[:<choice>]` to approve and `d:<id>:<short>`
//! to deny, as on Telegram. High risk requests ask for a TOTP code: Discord
//! with a form, the others as the next message.

pub mod discord;
pub mod line;
pub mod whatsapp;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::telegram::{Handler, Translate};

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The channels ucanrun knows, in the order the settings page shows them.
pub const KINDS: &[&str] = &["discord", "line", "whatsapp"];

/// One webhook call as the platform sent it.
pub struct Hook<'a> {
    pub method: &'a str,
    pub query: &'a str,
    /// Lower-case names.
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
}

impl Hook<'_> {
    pub fn header(&self, name: &str) -> String {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }
}

/// What to send back to the platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(v: &serde_json::Value) -> Reply {
        Reply {
            status: 200,
            content_type: "application/json",
            body: v.to_string().into_bytes(),
        }
    }
    pub fn text(status: u16, s: &str) -> Reply {
        Reply {
            status,
            content_type: "text/plain; charset=utf-8",
            body: s.as_bytes().to_vec(),
        }
    }
    pub fn ok() -> Reply {
        Reply::text(200, "ok")
    }
    pub fn unauthorized() -> Reply {
        Reply::text(401, "bad signature")
    }
}

/// An approval channel.
pub trait Channel: Send + Sync {
    fn kind(&self) -> &'static str;
    /// Sends an approval request to the paired account.
    fn notify<'a>(
        &'a self,
        id: &'a str,
        short: &'a str,
        text: &'a str,
        choices: &'a [String],
    ) -> BoxFut<'a, Result<(), String>>;
    /// Tells the account how a request ended.
    fn finish<'a>(&'a self, id: &'a str, text: &'a str) -> BoxFut<'a, ()>;
    fn webhook<'a>(&'a self, h: Hook<'a>) -> BoxFut<'a, Reply>;
    /// The last time the platform reached the webhook, and the last error.
    fn link(&self) -> (Option<SystemTime>, String);
}

/// The paired account, as the platform names it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Owner {
    pub user: String,
    /// Where to send messages: a DM channel, or the user again.
    pub chat: String,
}

/// What the owner pastes in for a channel. Kept in the vault as one secret.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Bot or access token.
    pub token: String,
    /// Discord: the application's public key (hex). LINE: the channel
    /// secret. WhatsApp: the app secret.
    pub key: String,
    /// Discord: application id, found from the token. WhatsApp: phone
    /// number id.
    pub id: String,
    /// WhatsApp: the verify token the webhook setup echoes back.
    pub verify: String,
}

/// Shared state of a running channel.
pub struct Common {
    pub kind: &'static str,
    pub settings: Settings,
    pub owner: Mutex<Owner>,
    pub handler: Arc<dyn Handler>,
    pub translate: Translate,
    pub http: reqwest::Client,
    pub base: String,
    waiting: Mutex<HashMap<String, Waiting>>,
    link: Mutex<(Option<SystemTime>, String)>,
}

struct Waiting {
    id: String,
    short: String,
    secret: String,
    until: Instant,
}

/// What a button press asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Press {
    pub approve: bool,
    pub id: String,
    pub short: String,
    pub choice: Option<usize>,
}

/// Reads `a:<id>:<short>[:<choice>]` or `d:<id>:<short>`.
pub fn parse_press(data: &str) -> Option<Press> {
    let p: Vec<&str> = data.split(':').collect();
    if p.len() != 3 && p.len() != 4 {
        return None;
    }
    let approve = match p[0] {
        "a" => true,
        "d" => false,
        _ => return None,
    };
    let ok = |s: &str, n: usize| {
        s.len() <= n && !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
    };
    if !ok(p[1], 32) || !ok(p[2], 64) {
        return None;
    }
    let choice = match p.get(3) {
        Some(c) => Some(c.parse::<usize>().ok().filter(|i| *i < 32)?),
        None => None,
    };
    Some(Press {
        approve,
        id: p[1].into(),
        short: p[2].into(),
        choice,
    })
}

/// What happened to a press.
pub enum Outcome {
    /// Decided; a message for the person.
    Done(String),
    /// Approval needs a TOTP code first.
    NeedCode,
}

pub fn data(approve: bool, id: &str, short: &str, choice: Option<usize>) -> String {
    let mut s = format!("{}:{id}:{short}", if approve { "a" } else { "d" });
    if let Some(i) = choice {
        s.push_str(&format!(":{i}"));
    }
    s
}

pub fn is_code(s: &str) -> bool {
    s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit())
}

impl Common {
    pub fn new(
        kind: &'static str,
        settings: Settings,
        owner: Owner,
        handler: Arc<dyn Handler>,
        translate: Translate,
        base: String,
    ) -> Common {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("http client");
        Common {
            kind,
            settings,
            owner: Mutex::new(owner),
            handler,
            translate,
            http,
            base,
            waiting: Mutex::new(HashMap::new()),
            link: Mutex::new((None, String::new())),
        }
    }

    pub fn t(&self, s: &str) -> String {
        (self.translate)(s)
    }

    pub fn owner(&self) -> Owner {
        self.owner.lock().unwrap().clone()
    }

    pub fn is_owner(&self, user: &str) -> bool {
        let o = self.owner();
        !o.user.is_empty() && o.user == user
    }

    pub fn seen(&self) {
        let mut l = self.link.lock().unwrap();
        l.0 = Some(SystemTime::now());
    }

    pub fn error(&self, e: &str) {
        self.link.lock().unwrap().1 = e.chars().take(200).collect();
    }

    pub fn link(&self) -> (Option<SystemTime>, String) {
        self.link.lock().unwrap().clone()
    }

    fn actor(&self, user: &str) -> String {
        format!("{}:{user}", self.kind)
    }

    /// `/pair CODE` from `user`; on success the account becomes the owner.
    pub fn pair(&self, code: &str, user: &str, chat: &str) -> bool {
        if user.is_empty() || !self.handler.pair_chat(self.kind, code.trim(), user, chat) {
            return false;
        }
        *self.owner.lock().unwrap() = Owner {
            user: user.into(),
            chat: chat.into(),
        };
        true
    }

    /// A button press by the owner.
    pub fn press(&self, user: &str, p: &Press, code: &str) -> Outcome {
        let secret = match p.choice {
            Some(i) => match self.handler.secret_at(&p.id, i) {
                Some(n) => n,
                None => return Outcome::Done(self.t("Lựa chọn không hợp lệ")),
            },
            None => String::new(),
        };
        if p.approve && code.is_empty() && self.handler.needs_totp(&p.id) {
            self.waiting.lock().unwrap().insert(
                user.to_string(),
                Waiting {
                    id: p.id.clone(),
                    short: p.short.clone(),
                    secret,
                    until: Instant::now() + Duration::from_secs(120),
                },
            );
            return Outcome::NeedCode;
        }
        Outcome::Done(self.decide(user, &p.id, &p.short, p.approve, code, &secret))
    }

    /// A six digit message after a press that needed TOTP.
    pub fn code(&self, user: &str, text: &str) -> Option<String> {
        if !is_code(text) {
            return None;
        }
        let w = self.waiting.lock().unwrap().remove(user);
        Some(match w.filter(|w| Instant::now() < w.until) {
            Some(w) => self.decide(user, &w.id, &w.short, true, text, &w.secret),
            None => self.t("Không có yêu cầu nào đang chờ mã."),
        })
    }

    fn decide(
        &self,
        user: &str,
        id: &str,
        short: &str,
        approve: bool,
        code: &str,
        secret: &str,
    ) -> String {
        match self
            .handler
            .decide(id, short, approve, &self.actor(user), code, secret)
        {
            Ok(m) => self.t(&m),
            Err(e) => format!("{} {}", self.t("Không duyệt được:"), self.t(&e)),
        }
    }

    pub fn need_code_text(&self, id: &str) -> String {
        format!(
            "{} {id}. {}",
            self.t("Yêu cầu rủi ro cao"),
            self.t("Gửi mã TOTP 6 số trong 2 phút.")
        )
    }
}

/// HMAC-SHA256 of `body` with `key`, compared in constant time.
pub fn hmac_ok(key: &[u8], body: &[u8], expect: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    let Ok(mut m) = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key) else {
        return false;
    };
    m.update(body);
    m.verify_slice(expect).is_ok()
}

/// Cuts text to `n` characters for platforms with message limits.
pub fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
pub(crate) mod fake {
    //! A recording stand-in for the core, for channel tests.
    use super::*;

    /// id, approved, actor, TOTP code, chosen secret.
    pub type Decision = (String, bool, String, String, String);

    #[derive(Default)]
    pub struct Core {
        pub decided: Mutex<Vec<Decision>>,
        pub totp: bool,
        pub code: String,
    }

    impl Handler for Core {
        fn decide(
            &self,
            id: &str,
            _short: &str,
            approve: bool,
            actor: &str,
            totp: &str,
            secret: &str,
        ) -> Result<String, String> {
            self.decided.lock().unwrap().push((
                id.into(),
                approve,
                actor.into(),
                totp.into(),
                secret.into(),
            ));
            Ok(if approve {
                "Đã duyệt".into()
            } else {
                "Đã từ chối".into()
            })
        }
        fn needs_totp(&self, _id: &str) -> bool {
            self.totp
        }
        fn secret_at(&self, _id: &str, i: usize) -> Option<String> {
            ["gh_a", "gh_b"].get(i).map(|s| s.to_string())
        }
        fn pair(&self, _code: &str, _u: i64, _c: i64) -> bool {
            false
        }
        fn pair_chat(&self, _kind: &str, code: &str, _user: &str, _chat: &str) -> bool {
            !self.code.is_empty() && code == self.code
        }
    }

    pub fn translate() -> Translate {
        Arc::new(|s: &str| s.to_string())
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn press_data_round_trip_and_rejects_junk() {
        let d = data(true, "abc123", "0123456789abcdef", Some(1));
        assert_eq!(
            parse_press(&d),
            Some(Press {
                approve: true,
                id: "abc123".into(),
                short: "0123456789abcdef".into(),
                choice: Some(1)
            })
        );
        assert!(parse_press("x:ab:cd").is_none());
        assert!(parse_press("a:zz:cd").is_none(), "hex only");
        assert!(parse_press("a:ab:cd:99").is_none());
        assert!(parse_press("a:ab").is_none());
    }

    #[test]
    fn hmac_and_clip() {
        use hmac::{Hmac, Mac};
        let mut m = <Hmac<sha2::Sha256> as Mac>::new_from_slice(b"k").unwrap();
        m.update(b"body");
        let sig = m.finalize().into_bytes();
        assert!(hmac_ok(b"k", b"body", &sig));
        assert!(!hmac_ok(b"k", b"body!", &sig));
        assert_eq!(clip("abcdef", 4), "abc…");
        assert_eq!(clip("abc", 4), "abc");
    }
}
