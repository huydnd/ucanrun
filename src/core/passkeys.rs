//! Passkeys for signing in and for approving high risk requests, next to
//! TOTP. The public keys live in the signed state; challenges live in memory
//! for two minutes and are used once.
//!
//! Signing in with a passkey takes two steps. The first checks the master
//! password and reads the registered passkeys without opening the vault; the
//! second checks the passkey and only then opens it.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use serde::Serialize;
use serde_json::{Value, json};

use super::{Core, Error, Inner, Result, audit, rfc3339_nano, state};
use crate::runner::proto::{self, PinnedPasskeys, Signed};
use crate::webauthn::{self, Credential, Passkey, Rp};

const CHALLENGE_TTL: Duration = Duration::from_secs(120);
const MAX_PASSKEYS: usize = 20;

/// Challenges waiting for an answer.
#[derive(Default)]
pub(super) struct Pending {
    register: Option<(Vec<u8>, SystemTime)>,
    /// Request id: challenge, nonce, deadline.
    approve: HashMap<String, (Vec<u8>, String, SystemTime)>,
    login: Option<Login>,
}

pub(super) struct Login {
    challenge: Vec<u8>,
    id: age::x25519::Identity,
    keys: Vec<Passkey>,
    till: SystemTime,
}

/// A passkey as the settings page lists it.
#[derive(Debug, Clone, Serialize)]
pub struct PasskeyView {
    pub id: String,
    pub name: String,
    /// Compare with what `ucr runner trust-passkeys` prints.
    pub fingerprint: String,
    pub alg: String,
    pub created: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_used: String,
}

fn alg_name(a: i64) -> &'static str {
    match a {
        webauthn::ES256 => "ES256",
        webauthn::EDDSA => "EdDSA",
        webauthn::RS256 => "RS256",
        _ => "?",
    }
}

fn clean_name(s: &str) -> String {
    let n: String = s
        .chars()
        .filter(|c| !c.is_control() && !crate::policy::gourl::is_control_or_format(*c))
        .take(40)
        .collect();
    let n = n.trim().to_string();
    if n.is_empty() { "Passkey".into() } else { n }
}

impl Core {
    pub fn passkeys(&self) -> Result<Vec<PasskeyView>> {
        let g = self.inner();
        let st = g.st.as_ref().ok_or(Error::Locked)?;
        Ok(st
            .passkeys
            .iter()
            .map(|p| PasskeyView {
                id: p.id.clone(),
                name: p.name.clone(),
                fingerprint: proto::fingerprint(&p.key),
                alg: alg_name(p.alg).into(),
                created: p.created.clone(),
                last_used: p.last_used.clone(),
            })
            .collect())
    }

    pub fn has_passkeys(&self) -> bool {
        self.inner()
            .st
            .as_ref()
            .is_some_and(|s| !s.passkeys.is_empty())
    }

    /// Options for registering a new passkey.
    pub fn passkey_register_start(&self, rp: &Rp) -> Result<Value> {
        let mut g = self.inner();
        let now = self.now();
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        if st.passkeys.len() >= MAX_PASSKEYS {
            return Err(Error::Msg(format!("at most {MAX_PASSKEYS} passkeys")));
        }
        if st.webauthn_user.is_empty() {
            st.webauthn_user = webauthn::b64u(&rand::random::<[u8; 16]>());
        }
        let user = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &st.webauthn_user,
        )
        .unwrap_or_default();
        let ch = webauthn::new_challenge();
        let opts = webauthn::creation_options(rp, &user, &ch, &st.passkeys);
        g.pending.register = Some((ch, now + CHALLENGE_TTL));
        self.save_locked(&mut g)?;
        Ok(opts)
    }

    /// Stores a new passkey. Adding a way in needs the second factor: the
    /// current TOTP code, or the master password while TOTP is off.
    pub fn passkey_register_finish(
        &self,
        rp: &Rp,
        name: &str,
        cred: &Credential,
        code: &str,
        pass: &[u8],
    ) -> Result<()> {
        let totp_on = self.totp_enabled();
        if !totp_on {
            // scrypt; outside the main lock.
            let _l = self.login_guard()?;
            self.vault
                .open(pass)
                .map_err(|_| Error::Msg("sai mật khẩu chính".into()))?;
        }
        let mut g = self.inner();
        if g.st.is_none() {
            return Err(Error::Locked);
        }
        if totp_on {
            self.check_totp_locked(&mut g, code)?;
        }
        let Some((ch, till)) = g.pending.register.take() else {
            return Err(Error::Msg("bắt đầu lại việc thêm passkey".into()));
        };
        if self.now() > till {
            return Err(Error::Msg(
                "hết thời gian, bắt đầu lại việc thêm passkey".into(),
            ));
        }
        let mut p = webauthn::finish_register(rp, &ch, cred).map_err(Error::Msg)?;
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        if st.passkeys.iter().any(|x| x.id == p.id) {
            return Err(Error::Msg("passkey này đã được thêm".into()));
        }
        p.name = clean_name(name);
        p.created = rfc3339_nano(self.now());
        let name = p.name.clone();
        st.passkeys.push(p);
        self.save_locked(&mut g)?;
        self.log("passkey_added", "web", json!({"name": name}));
        Ok(())
    }

    /// Removes a passkey; needs the current TOTP code when TOTP is on.
    pub fn passkey_delete(&self, id: &str, code: &str) -> Result<()> {
        let mut g = self.inner();
        let on = g.st.as_ref().ok_or(Error::Locked)?.totp_enabled;
        if on {
            self.check_totp_locked(&mut g, code)?;
        }
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        let before = st.passkeys.len();
        st.passkeys.retain(|p| p.id != id);
        if st.passkeys.len() == before {
            return Err(Error::NotFound);
        }
        self.save_locked(&mut g)?;
        self.log("passkey_removed", "web", Value::Null);
        Ok(())
    }

    fn use_passkey_locked(&self, g: &mut Inner, idx: usize, count: u32) {
        let now = rfc3339_nano(self.now());
        if let Some(p) = g.st.as_mut().and_then(|s| s.passkeys.get_mut(idx)) {
            p.sign_count = count;
            p.last_used = now;
        }
        let _ = self.save_locked(g);
    }

    /// Step one of signing in with a passkey: checks the master password and
    /// returns the options for `navigator.credentials.get`. The vault stays
    /// as it was.
    pub fn login_passkey_start(&self, rp: &Rp, pass: &[u8]) -> Result<Value> {
        let _l = self.login_guard()?;
        let id = self.vault.open(pass)?;
        let mut g = self.inner();
        let keys = match g.st.as_ref() {
            Some(st) => st.passkeys.clone(),
            None => {
                let k = crate::vault::Vault::mac_key_for(&id)?;
                state::load(&self.state_path(), &k)?.passkeys
            }
        };
        if keys.is_empty() {
            return Err(Error::Msg(
                "chưa có passkey nào, hãy đăng nhập bằng TOTP".into(),
            ));
        }
        let ch = webauthn::new_challenge();
        let opts = webauthn::request_options(rp, &ch, &keys);
        g.pending.login = Some(Login {
            challenge: ch,
            id,
            keys,
            till: self.now() + CHALLENGE_TTL,
        });
        Ok(opts)
    }

    /// Step two: checks the passkey, then opens the vault.
    pub fn login_passkey_finish(&self, rp: &Rp, cred: &Credential) -> Result<()> {
        let _l = self.login_guard()?;
        let mut g = self.inner();
        let Some(p) = g.pending.login.take() else {
            return Err(Error::Msg("bắt đầu lại việc đăng nhập".into()));
        };
        if self.now() > p.till {
            return Err(Error::Msg("hết thời gian, đăng nhập lại".into()));
        }
        let (idx, count) = match webauthn::finish_assert(rp, &p.challenge, cred, &p.keys) {
            Ok(x) => x,
            Err(e) => {
                self.log("login_failed", "web", json!({"why": "passkey"}));
                return Err(Error::Msg(e));
            }
        };
        let was_locked = g.st.is_none();
        if was_locked {
            self.vault.adopt(p.id);
            if let Err(e) = self.load_locked(&mut g) {
                self.log("state_tamper", "web", Value::Null);
                return Err(e);
            }
            let st = g.st.as_ref().expect("loaded");
            let (count, hash) = (st.audit_count, st.audit_hash.clone());
            if !audit::contains(&self.audit_path(), count.max(0) as usize, &hash).unwrap_or(false) {
                g.audit_cut = true;
                self.log("audit_truncated", "web", json!({"count": count}));
            }
            self.start_channels_locked(&mut g);
        }
        // The passkey must still be registered in the state now open.
        let key_id = p.keys[idx].id.clone();
        let Some(i) =
            g.st.as_ref()
                .and_then(|s| s.passkeys.iter().position(|x| x.id == key_id))
        else {
            return Err(Error::Msg("passkey này đã bị gỡ".into()));
        };
        self.use_passkey_locked(&mut g, i, count);
        self.log("login", "web", json!({"with": "passkey"}));
        Ok(())
    }

    /// Options for approving request `id` with a passkey.
    pub fn approve_passkey_start(&self, rp: &Rp, id: &str) -> Result<Value> {
        let mut g = self.inner();
        let keys = g.st.as_ref().ok_or(Error::Locked)?.passkeys.clone();
        if keys.is_empty() {
            return Err(Error::Msg("chưa có passkey nào".into()));
        }
        // The challenge covers the action itself, so a runner can check the
        // approval against the job it receives.
        let (hash, digest) = g
            .reqs
            .get(id)
            .map(|e| (e.req.hash.clone(), proto::action_digest(&e.action)))
            .ok_or(Error::Decided)?;
        let nonce = hex::encode(rand::random::<[u8; 16]>());
        let ch = proto::approval_challenge(&digest, &hash, &nonce);
        let opts = webauthn::request_options(rp, &ch, &keys);
        let till = self.now() + CHALLENGE_TTL;
        g.pending
            .approve
            .retain(|_, (_, _, t)| *t > SystemTime::now() - CHALLENGE_TTL);
        g.pending.approve.insert(id.to_string(), (ch, nonce, till));
        Ok(opts)
    }

    /// Approves request `id` with a passkey, in place of a TOTP code.
    pub fn approve_passkey_finish(
        &self,
        rp: &Rp,
        id: &str,
        hash: &str,
        cred: &Credential,
        secret: &str,
    ) -> Result<String> {
        {
            let mut g = self.inner();
            let Some((ch, nonce, till)) = g.pending.approve.remove(id) else {
                return Err(Error::Msg("bắt đầu lại việc duyệt bằng passkey".into()));
            };
            if self.now() > till {
                return Err(Error::Msg("hết thời gian, duyệt lại".into()));
            }
            let keys = g.st.as_ref().ok_or(Error::Locked)?.passkeys.clone();
            match webauthn::finish_assert(rp, &ch, cred, &keys) {
                Ok((idx, count)) => {
                    self.use_passkey_locked(&mut g, idx, count);
                    // Kept with the request: a runner that requires a
                    // passkey checks this answer itself.
                    if let Some(e) = g.reqs.get_mut(id) {
                        e.proof = Some(proto::Approval {
                            credential: cred.clone(),
                            nonce,
                        });
                    }
                }
                Err(e) => {
                    self.log("decide_passkey_failed", "web", json!({"id": id}));
                    return Err(Error::Msg(e));
                }
            }
        }
        self.decide_checked(id, hash, true, "web:passkey", "", secret, true)
    }

    /// The passkeys a runner should trust, signed with the server key. The
    /// runner pins them at enrolment, or when its owner runs
    /// `ucr runner trust-passkeys` on that machine.
    pub fn runner_passkeys(&self, runner: &str, rp: &Rp) -> Result<Signed> {
        let keys = self
            .inner()
            .st
            .as_ref()
            .ok_or(Error::Locked)?
            .passkeys
            .clone();
        let key = self.signing_key_for_runners()?;
        Ok(Signed::new(
            &key,
            &PinnedPasskeys {
                runner: runner.to_string(),
                rp_id: rp.id.clone(),
                origin: rp.origin.clone(),
                keys,
            },
        ))
    }
}
