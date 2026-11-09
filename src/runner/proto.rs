//! What the server (A) and a runner (B) send each other.
//!
//! A job is signed by A with ed25519 and carries its secrets encrypted with
//! age to the runner's own key. A result is signed by B. Either side checks
//! the other's pinned key, so the transport only needs to carry bytes:
//! someone who can read or alter it can neither forge a job or a result nor
//! read a secret.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::str::FromStr;

use age::x25519;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::policy::ExecSpec;

pub const VERSION: u32 = 1;
/// How long A holds a poll open when there is no job.
pub const POLL_WAIT_SECS: u64 = 25;
/// A runner that has not polled for this long counts as offline.
pub const ONLINE_SECS: u64 = 75;
/// Extra time a job stays valid beyond its own timeout.
pub const JOB_GRACE_SECS: i64 = 120;
/// Runner tokens start with this, so they cannot be mistaken for agent tokens.
pub const TOKEN_PREFIX: &str = "ucr_r_";

/// A payload and a signature over its exact bytes. Signing the bytes as sent
/// avoids any canonical JSON form.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub payload: String,
    pub sig: String,
}

impl Signed {
    pub fn new<T: Serialize>(key: &SigningKey, v: &T) -> Signed {
        let payload = serde_json::to_string(v).expect("serializable payload");
        let sig = B64.encode(key.sign(payload.as_bytes()).to_bytes());
        Signed { payload, sig }
    }

    /// Checks the signature, then parses the payload.
    pub fn open<T: DeserializeOwned>(&self, key: &VerifyingKey) -> Result<T, String> {
        let raw = B64.decode(&self.sig).map_err(|_| "bad signature")?;
        let sig = Signature::from_slice(&raw).map_err(|_| "bad signature")?;
        key.verify(self.payload.as_bytes(), &sig)
            .map_err(|_| "signature does not match")?;
        serde_json::from_str(&self.payload).map_err(|e| format!("bad payload: {e}"))
    }
}

pub fn verifying_key(b64: &str) -> Result<VerifyingKey, String> {
    let raw = B64.decode(b64.trim()).map_err(|_| "bad public key")?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| "bad public key")?;
    VerifyingKey::from_bytes(&arr).map_err(|_| "bad public key".to_string())
}

pub fn public_b64(k: &SigningKey) -> String {
    B64.encode(k.verifying_key().to_bytes())
}

/// A short form of a public key for people to compare, such as
/// `3f9a-1c02-77be-d410`.
pub fn fingerprint(public_b64: &str) -> String {
    let h = Sha256::digest(public_b64.trim().as_bytes());
    let x = hex::encode(&h[..8]);
    x.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-")
}

/// Encrypts secret values to the runner: JSON `{ref: base64}`, then age.
pub fn seal(
    age_recipient: &str,
    values: &BTreeMap<String, Zeroizing<Vec<u8>>>,
) -> Result<String, String> {
    let r = x25519::Recipient::from_str(age_recipient.trim()).map_err(|e| e.to_string())?;
    let map: BTreeMap<&String, String> = values
        .iter()
        .map(|(k, v)| (k, B64.encode(v.as_slice())))
        .collect();
    let plain = Zeroizing::new(serde_json::to_vec(&map).map_err(|e| e.to_string())?);
    let enc = age::Encryptor::with_recipients(std::iter::once(&r as &dyn age::Recipient))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut w = enc.wrap_output(&mut out).map_err(|e| e.to_string())?;
    w.write_all(&plain).map_err(|e| e.to_string())?;
    w.finish().map_err(|e| e.to_string())?;
    Ok(B64.encode(out))
}

/// Reverses `seal` with the runner's identity.
pub fn unseal(
    id: &x25519::Identity,
    sealed: &str,
) -> Result<BTreeMap<String, Zeroizing<Vec<u8>>>, String> {
    if sealed.is_empty() {
        return Ok(BTreeMap::new());
    }
    let raw = B64.decode(sealed).map_err(|_| "bad sealed secrets")?;
    let dec = age::Decryptor::new(&raw[..]).map_err(|e| e.to_string())?;
    let mut r = dec
        .decrypt(std::iter::once(id as &dyn age::Identity))
        .map_err(|e| format!("cannot decrypt the secrets: {e}"))?;
    let mut plain = Zeroizing::new(Vec::new());
    r.read_to_end(&mut plain).map_err(|e| e.to_string())?;
    let mut map: BTreeMap<String, String> =
        serde_json::from_slice(&plain).map_err(|_| "bad sealed secrets")?;
    let mut out = BTreeMap::new();
    let mut bad = false;
    for (k, v) in map.iter_mut() {
        match B64.decode(v.as_bytes()) {
            Ok(b) => {
                out.insert(k.clone(), Zeroizing::new(b));
            }
            Err(_) => bad = true,
        }
        zeroize::Zeroize::zeroize(v);
    }
    if bad {
        return Err("bad sealed secrets".into());
    }
    Ok(out)
}

/// One approved command for one runner.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Job {
    pub v: u32,
    /// The request id, for the logs on both sides.
    pub id: String,
    /// Random and single use: what the runner checks against replays.
    pub job: String,
    pub runner: String,
    /// Unix seconds after which the runner refuses the job.
    pub not_after: i64,
    /// Hash of the action the human approved.
    pub hash: String,
    pub approved_by: String,
    /// Whether the approval needed a TOTP code.
    pub totp: bool,
    pub exec: ExecSpec,
    pub timeout_sec: i64,
    /// References that are public fields, which are not redacted.
    pub public: Vec<String>,
    /// `seal` of the values the command needs.
    pub secrets: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct JobResult {
    pub v: u32,
    pub job: String,
    pub id: String,
    pub runner: String,
    pub ok: bool,
    pub exit: i32,
    pub output: String,
    /// Set when the runner refused the job before running anything.
    pub refused: bool,
}

/// What a runner says about itself on every poll. It describes the runner's
/// own policy file, so the owner can see what each machine allows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Info {
    pub version: String,
    pub host: String,
    pub os: String,
    pub arch: String,
    pub user: String,
    /// -1 where there is no uid, as on Windows.
    pub uid: i64,
    pub root: bool,
    pub sudo: bool,
    pub require_totp: bool,
    pub allow: Vec<String>,
    /// Set when the policy file could not be read; nothing runs then.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub policy_error: String,
}

impl Info {
    /// Keeps only short, printable values, since another machine wrote them.
    pub fn cleaned(mut self) -> Info {
        let clean = |s: &str, n: usize| -> String {
            s.chars()
                .filter(|c| !c.is_control() && !crate::policy::gourl::is_control_or_format(*c))
                .take(n)
                .collect()
        };
        self.version = clean(&self.version, 32);
        self.host = clean(&self.host, 64);
        self.os = clean(&self.os, 32);
        self.arch = clean(&self.arch, 32);
        self.user = clean(&self.user, 64);
        self.policy_error = clean(&self.policy_error, 200);
        self.allow = self.allow.iter().take(50).map(|a| clean(a, 200)).collect();
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EnrollIn {
    pub code: String,
    pub name: String,
    /// ed25519, base64: checks the runner's results.
    pub sign_key: String,
    /// age X25519 recipient: secrets are sealed to it.
    pub age_key: String,
    pub info: Info,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EnrollOut {
    pub name: String,
    pub token: String,
    /// ed25519, base64: the runner pins it and checks every job with it.
    pub server_key: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PollIn {
    pub info: Info,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PollOut {
    pub jobs: Vec<Signed>,
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn signed_round_trip_and_tamper() {
        let k = SigningKey::generate(&mut rand::rngs::OsRng);
        let other = SigningKey::generate(&mut rand::rngs::OsRng);
        let j = Job {
            v: VERSION,
            id: "abc".into(),
            ..Default::default()
        };
        let s = Signed::new(&k, &j);
        assert_eq!(s.open::<Job>(&k.verifying_key()).unwrap(), j);
        assert!(s.open::<Job>(&other.verifying_key()).is_err());
        let mut t = s.clone();
        t.payload = t.payload.replace("abc", "abd");
        assert!(t.open::<Job>(&k.verifying_key()).is_err());
        let pk = verifying_key(&public_b64(&k)).unwrap();
        assert_eq!(pk, k.verifying_key());
        assert_eq!(fingerprint(&public_b64(&k)).len(), 19);
    }

    #[test]
    fn seal_round_trip() {
        let id = x25519::Identity::generate();
        let other = x25519::Identity::generate();
        let mut m = BTreeMap::new();
        m.insert("pw".to_string(), Zeroizing::new(b"hunter2\n".to_vec()));
        let s = seal(&id.to_public().to_string(), &m).unwrap();
        assert!(!s.contains("hunter2"));
        let back = unseal(&id, &s).unwrap();
        assert_eq!(back["pw"].as_slice(), b"hunter2\n");
        assert!(unseal(&other, &s).is_err());
        assert!(unseal(&id, "").unwrap().is_empty());
    }
}
