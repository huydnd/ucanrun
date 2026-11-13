//! Approval channels besides Telegram: setup, pairing, notifications and
//! webhooks. Each channel's settings live in the vault as one secret
//! (`_chat_<kind>`); the paired account lives in the signed state.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;

use super::{
    Core, Error, Inner, MAX_PAIR_FAILS, PAIR_TTL, Relay, Result, new_pair_code, rand_hex,
    rfc3339_nano,
};
use crate::chat::{self, Channel, Hook, KINDS, Owner, Reply, Settings};

/// A channel connected this recently counts as reachable.
const FRESH: Duration = Duration::from_secs(7 * 24 * 3600);

fn secret_name(kind: &str) -> String {
    format!("_chat_{kind}")
}

/// What the owner enters for a channel.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ChatInput {
    pub token: String,
    /// LINE: channel secret. WhatsApp: app secret.
    pub secret: String,
    /// WhatsApp: phone number id.
    pub phone_id: String,
}

/// A channel as the settings page shows it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ChatView {
    pub kind: String,
    pub configured: bool,
    pub paired: bool,
    /// Where the platform must send its webhooks, relative to the public URL.
    pub webhook: String,
    /// WhatsApp only: the verify token to paste into Meta's webhook form.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub verify: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_hook: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

impl Core {
    fn chat_base(&self, kind: &str) -> String {
        self.opt.chat_api.get(kind).cloned().unwrap_or_default()
    }

    fn make_chat(&self, kind: &str, s: Settings, owner: Owner) -> Option<Arc<dyn Channel>> {
        let h: Arc<dyn crate::telegram::Handler> = Arc::new(Relay(self.me.clone()));
        let t = self.translator();
        let base = self.chat_base(kind);
        Some(match kind {
            "discord" => chat::discord::Discord::new(s, owner, h, t, &base),
            "line" => chat::line::Line::new(s, owner, h, t, &base),
            "whatsapp" => chat::whatsapp::WhatsApp::new(s, owner, h, t, &base),
            _ => return None,
        })
    }

    fn chat_settings(&self, kind: &str) -> Option<Settings> {
        let raw = self.vault.get(&secret_name(kind)).ok()?;
        serde_json::from_slice(&raw).ok()
    }

    /// Starts every configured channel. Called on unlock and after changes.
    pub(super) fn start_chats_locked(&self, g: &mut Inner) {
        g.chats.clear();
        let Some(st) = g.st.as_ref() else { return };
        let owners = st.chats.clone();
        for kind in KINDS {
            if let Some(s) = self.chat_settings(kind) {
                let owner = owners.get(*kind).cloned().unwrap_or_default();
                if let Some(c) = self.make_chat(kind, s, owner) {
                    g.chats.insert(kind.to_string(), c);
                }
            }
        }
    }

    /// Checks the credentials with the platform, stores them, and starts the
    /// channel. A new setup clears the pairing; the result holds a pairing
    /// code and what to set on the platform's side.
    pub async fn set_chat(&self, kind: &str, input: ChatInput) -> Result<Value> {
        let base = self.chat_base(kind);
        let token = input.token.trim().to_string();
        if token.is_empty() {
            return Err(Error::Msg("token is required".into()));
        }
        let (settings, name) = match kind {
            "discord" => {
                let app = chat::discord::check(&base, &token)
                    .await
                    .map_err(Error::Msg)?;
                (
                    Settings {
                        token,
                        key: app.public_key,
                        id: app.id,
                        ..Default::default()
                    },
                    app.name,
                )
            }
            "line" => {
                let secret = input.secret.trim().to_string();
                if secret.is_empty() {
                    return Err(Error::Msg("the channel secret is required".into()));
                }
                let name = chat::line::check(&base, &token).await.map_err(Error::Msg)?;
                (
                    Settings {
                        token,
                        key: secret,
                        ..Default::default()
                    },
                    name,
                )
            }
            "whatsapp" => {
                let secret = input.secret.trim().to_string();
                let phone = input.phone_id.trim().to_string();
                if secret.is_empty() {
                    return Err(Error::Msg("the app secret is required".into()));
                }
                let name = chat::whatsapp::check(&base, &token, &phone)
                    .await
                    .map_err(Error::Msg)?;
                (
                    Settings {
                        token,
                        key: secret,
                        id: phone,
                        verify: rand_hex(16),
                    },
                    name,
                )
            }
            _ => return Err(Error::NotFound),
        };
        let raw = serde_json::to_vec(&settings).map_err(|e| Error::Msg(e.to_string()))?;
        let mut g = self.inner();
        if g.st.is_none() {
            return Err(Error::Locked);
        }
        self.vault.put(&secret_name(kind), &raw)?;
        g.st.as_mut().ok_or(Error::Locked)?.chats.remove(kind);
        self.save_locked(&mut g)?;
        g.pair_code = new_pair_code();
        g.pair_till = self.now() + PAIR_TTL;
        g.pair_fails = 0;
        self.start_chats_locked(&mut g);
        self.log("chat_set", "web", json!({"kind": kind, "name": name}));
        Ok(
            json!({"kind": kind, "name": name, "code": g.pair_code, "webhook": format!("/hooks/{kind}"), "verify": settings.verify}),
        )
    }

    pub fn delete_chat(&self, kind: &str) -> Result<()> {
        if !KINDS.contains(&kind) {
            return Err(Error::NotFound);
        }
        let mut g = self.inner();
        if g.st.is_none() {
            return Err(Error::Locked);
        }
        let _ = self.vault.delete(&secret_name(kind));
        g.st.as_mut().ok_or(Error::Locked)?.chats.remove(kind);
        self.save_locked(&mut g)?;
        g.chats.remove(kind);
        self.log("chat_removed", "web", json!({"kind": kind}));
        Ok(())
    }

    pub fn chats(&self) -> Result<Vec<ChatView>> {
        let g = self.inner();
        let st = g.st.as_ref().ok_or(Error::Locked)?;
        Ok(KINDS
            .iter()
            .map(|k| {
                let ch = g.chats.get(*k);
                let (seen, error) = ch.map(|c| c.link()).unwrap_or_default();
                ChatView {
                    kind: k.to_string(),
                    configured: ch.is_some(),
                    paired: st.chats.get(*k).is_some_and(|o| !o.user.is_empty()),
                    webhook: format!("/hooks/{k}"),
                    verify: if *k == "whatsapp" && ch.is_some() {
                        self.chat_settings(k).map(|s| s.verify).unwrap_or_default()
                    } else {
                        String::new()
                    },
                    last_hook: seen.map(rfc3339_nano).unwrap_or_default(),
                    error,
                }
            })
            .collect())
    }

    /// Kinds of the channels that are paired and running.
    pub(super) fn paired_chats_locked(&self, g: &Inner) -> Vec<Arc<dyn Channel>> {
        let Some(st) = g.st.as_ref() else {
            return vec![];
        };
        g.chats
            .iter()
            .filter(|(k, _)| st.chats.get(*k).is_some_and(|o| !o.user.is_empty()))
            .map(|(_, c)| c.clone())
            .collect()
    }

    /// Whether any approval channel, Telegram included, has a paired account.
    pub fn any_channel_paired(&self) -> bool {
        let g = self.inner();
        g.st.as_ref().is_some_and(|s| {
            s.telegram.user_id != 0 || s.chats.values().any(|o| !o.user.is_empty())
        })
    }

    /// The single-use pairing code, used on another channel.
    pub fn pair_chat(&self, kind: &str, code: &str, user: &str, chat: &str) -> bool {
        let mut g = self.inner();
        if g.st.is_none()
            || g.pair_code.is_empty()
            || self.now() > g.pair_till
            || !g.chats.contains_key(kind)
        {
            return false;
        }
        if !bool::from(code.as_bytes().ct_eq(g.pair_code.as_bytes())) {
            g.pair_fails += 1;
            if g.pair_fails >= MAX_PAIR_FAILS {
                g.pair_code.clear();
                self.log("pair_code_burned", kind, Value::Null);
            }
            return false;
        }
        g.pair_code.clear();
        if let Some(st) = g.st.as_mut() {
            st.chats.insert(
                kind.to_string(),
                Owner {
                    user: user.to_string(),
                    chat: chat.to_string(),
                },
            );
        }
        if self.save_locked(&mut g).is_err() {
            return false;
        }
        self.log("chat_paired", kind, json!({"user": user}));
        true
    }

    /// A webhook call from a platform. Unknown or unconfigured channels get
    /// 404, so nothing tells a stranger which ones exist.
    pub async fn chat_hook(
        &self,
        kind: &str,
        method: &str,
        query: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Reply {
        let ch = self.inner().chats.get(kind).cloned();
        let Some(ch) = ch else {
            return Reply::text(404, "not found");
        };
        ch.webhook(Hook {
            method,
            query,
            headers,
            body,
        })
        .await
    }

    /// Whether a channel's webhook was reached recently.
    pub fn chat_recent(&self, kind: &str) -> bool {
        self.inner()
            .chats
            .get(kind)
            .and_then(|c| c.link().0)
            .is_some_and(|t| self.now().duration_since(t).map_or(true, |d| d < FRESH))
    }
}
