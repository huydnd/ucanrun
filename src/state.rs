//! Authenticated state file (port of `internal/core/state.go`).

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::policy::{Connection, Profile, SecretMeta};

pub const CURRENT_STATE_VERSION: i64 = 1;

#[derive(Debug)]
pub enum Error {
    /// "state file failed authentication"
    Tampered,
    /// "state file version is newer than this binary"
    TooNew,
    Msg(String),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Tampered => f.write_str("state file failed authentication"),
            Error::TooNew => f.write_str("state file version is newer than this binary"),
            Error::Msg(m) => f.write_str(m),
            Error::Io(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Agent token. Only the SHA-256 of the value is stored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub id: String,
    pub name: String,
    pub hash: String,
    /// Empty means all profiles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,
    /// Workspaces whose secrets the token may use. Empty means all; "" is
    /// the default workspace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workspaces: Vec<String>,
    /// RFC 3339 timestamp, kept as written.
    pub created: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelegramCfg {
    #[serde(default)]
    pub user_id: i64,
    #[serde(default)]
    pub chat_id: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub version: i64,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub connections: BTreeMap<String, Connection>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, SecretMeta>,
    #[serde(default)]
    pub tokens: BTreeMap<String, Token>,
    #[serde(default)]
    pub telegram: TelegramCfg,
    #[serde(default)]
    pub totp_enabled: bool,
    #[serde(default)]
    pub last_totp_step: i64,
    /// SHA-256 of single-use recovery codes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_hashes: Vec<String>,
    #[serde(default)]
    pub audit_count: i64,
    #[serde(default)]
    pub audit_hash: String,
    /// Minutes without any activity before the vault locks itself; 0 never.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub auto_lock_min: i64,
    /// The owner's own secret templates. They hold no secret values, because
    /// this file is signed, not encrypted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub templates: Vec<SecretTemplate>,
    /// Passkeys that sign in and approve, next to TOTP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkeys: Vec<crate::webauthn::Passkey>,
    /// The WebAuthn user handle, random, base64url.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub webauthn_user: String,
    /// Paired accounts on approval channels besides Telegram, by kind.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub chats: BTreeMap<String, crate::chat::Owner>,
    /// Machines enrolled to run approved commands.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub runners: BTreeMap<String, RunnerRec>,
}

/// An enrolled runner: its public keys and the hash of its token.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RunnerRec {
    pub name: String,
    /// ed25519, base64: checks the runner's results.
    pub sign_key: String,
    /// age X25519 recipient that job secrets are sealed to.
    pub age_key: String,
    pub token_hash: String,
    pub created: String,
    /// TOTP when approving jobs for this runner: empty or `always` asks
    /// every time; `secrets` follows the rules of the secrets used.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub totp: String,
}

impl RunnerRec {
    /// Whether every job for this runner needs a TOTP code.
    pub fn totp_always(&self) -> bool {
        self.totp != RUNNER_TOTP_SECRETS
    }
}

/// `RunnerRec::totp` value that leaves TOTP to the secrets.
pub const RUNNER_TOTP_SECRETS: &str = "secrets";

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// A template the owner saved: everything to prefill the secret form except
/// the value. Only public fields may carry a default value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretTemplate {
    pub id: String,
    pub title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hint: String,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<TemplateField>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub multiline: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub allow_commands: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub totp: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub workspace: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TemplateField {
    pub name: String,
    pub public: bool,
    /// Default value, public fields only.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub value: String,
}

#[derive(Serialize)]
struct SignedOut<'a> {
    mac: String,
    data: &'a serde_json::value::RawValue,
}

#[derive(Deserialize)]
struct SignedIn<'a> {
    mac: String,
    #[serde(borrow)]
    data: &'a serde_json::value::RawValue,
}

fn mac(key: &[u8], data: &[u8]) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    hex::encode(m.finalize().into_bytes())
}

/// Writes the state signed with `key`.
pub fn save(path: &Path, st: &State, key: &[u8]) -> Result<()> {
    let data = serde_json::to_string(st).map_err(|e| Error::Msg(e.to_string()))?;
    let raw = serde_json::value::RawValue::from_string(data.clone())
        .map_err(|e| Error::Msg(e.to_string()))?;
    let out = serde_json::to_vec(&SignedOut {
        mac: mac(key, data.as_bytes()),
        data: &raw,
    })
    .map_err(|e| Error::Msg(e.to_string()))?;
    crate::vault::atomic_write(path, &out).map_err(|e| match e {
        crate::vault::Error::Io(e) => Error::Io(e),
        e => Error::Msg(e.to_string()),
    })
}

/// Verifies the HMAC over the raw `data` bytes, then parses and migrates.
pub fn load(path: &Path, key: &[u8]) -> Result<State> {
    let raw = match std::fs::read(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::Tampered),
        Err(e) => return Err(e.into()),
    };
    let f: SignedIn = serde_json::from_slice(&raw).map_err(|_| Error::Tampered)?;
    let data = f.data.get();
    if !bool::from(f.mac.as_bytes().ct_eq(mac(key, data.as_bytes()).as_bytes())) {
        return Err(Error::Tampered);
    }
    let mut st: State = serde_json::from_str(data).map_err(|e| Error::Msg(e.to_string()))?;
    if st.version < 0 {
        return Err(Error::Tampered);
    }
    if st.version > CURRENT_STATE_VERSION {
        return Err(Error::TooNew);
    }
    while st.version < CURRENT_STATE_VERSION {
        // Migration 0 -> 1 only bumps the version.
        st.version += 1;
    }
    Ok(st)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        vec![7; 32]
    }

    #[test]
    fn roundtrip_and_tamper() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("state.json");
        assert!(matches!(load(&p, &key()), Err(Error::Tampered)));
        let mut st = State {
            version: 1,
            ..Default::default()
        };
        st.tokens.insert(
            "t1".into(),
            Token {
                id: "t1".into(),
                name: "n".into(),
                hash: "h".into(),
                profiles: vec![],
                workspaces: vec![],
                created: "2026-01-01T00:00:00Z".into(),
            },
        );
        st.audit_count = 3;
        save(&p, &st, &key()).unwrap();
        assert_eq!(load(&p, &key()).unwrap(), st);
        assert!(matches!(load(&p, &[8; 32]), Err(Error::Tampered)));
        let s = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, s.replace("\"audit_count\":3", "\"audit_count\":4")).unwrap();
        assert!(matches!(load(&p, &key()), Err(Error::Tampered)));
        std::fs::write(&p, "garbage").unwrap();
        assert!(matches!(load(&p, &key()), Err(Error::Tampered)));
    }

    #[test]
    fn versions() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("state.json");
        let st = State::default(); // version 0 migrates
        save(&p, &st, &key()).unwrap();
        assert_eq!(load(&p, &key()).unwrap().version, 1);
        let st = State {
            version: 2,
            ..Default::default()
        };
        save(&p, &st, &key()).unwrap();
        assert!(matches!(load(&p, &key()), Err(Error::TooNew)));
        let st = State {
            version: -1,
            ..Default::default()
        };
        save(&p, &st, &key()).unwrap();
        assert!(matches!(load(&p, &key()), Err(Error::Tampered)));
    }
}
