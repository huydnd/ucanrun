//! What the server (A) and a runner (B) send each other, version 2.
//!
//! - A job is sealed with age to the runner's key (command, arguments and
//!   secrets alike) and signed by A with ed25519. Only routing fields are
//!   readable: which runner, a single-use id, and a deadline.
//! - A result is sealed to A's age key and signed by B.
//! - Every poll and result is a request signed by B with its own key, a
//!   timestamp and a nonce: there is no token to steal.
//! - Pairing never sends the code: each side proves it knows the code with
//!   an HMAC over the keys it presents, so neither key can be swapped.
//!
//! Someone who can read or change the traffic can therefore read nothing but
//! routing data, forge nothing, and replay nothing.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::str::FromStr;

use age::x25519;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::policy::ExecSpec;

pub const VERSION: u32 = 2;
/// How long A holds a poll open when there is no job.
pub const POLL_WAIT_SECS: u64 = 25;
/// A runner that has not polled for this long counts as offline.
pub const ONLINE_SECS: u64 = 75;
/// Extra time a job stays valid beyond its own timeout.
pub const JOB_GRACE_SECS: i64 = 120;
/// A runner refuses a job whose deadline is further away than this, so a
/// wrong clock or a hostile server cannot make one live for long.
pub const MAX_JOB_LIFE_SECS: i64 = 600 + JOB_GRACE_SECS + 60;
/// How far a signed request's clock may be from the server's.
pub const REQUEST_SKEW_SECS: i64 = 60;

pub const H_RUNNER: &str = "x-ucanrun-runner";
pub const H_DATE: &str = "x-ucanrun-date";
pub const H_NONCE: &str = "x-ucanrun-nonce";
pub const H_SIG: &str = "x-ucanrun-sig";

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
        verify(key, self.payload.as_bytes(), &self.sig)?;
        serde_json::from_str(&self.payload).map_err(|e| format!("bad payload: {e}"))
    }
}

/// Strict ed25519 check: no malleable or weak-key signatures.
pub fn verify(key: &VerifyingKey, msg: &[u8], sig_b64: &str) -> Result<(), String> {
    let raw = B64.decode(sig_b64.trim()).map_err(|_| "bad signature")?;
    let sig = Signature::from_slice(&raw).map_err(|_| "bad signature")?;
    key.verify_strict(msg, &sig)
        .map_err(|_| "signature does not match".to_string())
}

pub fn verifying_key(b64: &str) -> Result<VerifyingKey, String> {
    let raw = B64.decode(b64.trim()).map_err(|_| "bad public key")?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| "bad public key")?;
    let k = VerifyingKey::from_bytes(&arr).map_err(|_| "bad public key")?;
    if k.is_weak() {
        return Err("bad public key".into());
    }
    Ok(k)
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

/// Encrypts any value to an age recipient, as base64.
pub fn seal<T: Serialize>(age_recipient: &str, v: &T) -> Result<String, String> {
    let r = x25519::Recipient::from_str(age_recipient.trim()).map_err(|e| e.to_string())?;
    let plain = Zeroizing::new(serde_json::to_vec(v).map_err(|e| e.to_string())?);
    let enc = age::Encryptor::with_recipients(std::iter::once(&r as &dyn age::Recipient))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut w = enc.wrap_output(&mut out).map_err(|e| e.to_string())?;
    w.write_all(&plain).map_err(|e| e.to_string())?;
    w.finish().map_err(|e| e.to_string())?;
    Ok(B64.encode(out))
}

/// The plaintext of `seal`, given the identity it was sealed to.
pub fn unseal_bytes(id: &dyn age::Identity, sealed: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let raw = B64.decode(sealed).map_err(|_| "bad sealed data")?;
    let dec = age::Decryptor::new(&raw[..]).map_err(|e| e.to_string())?;
    let mut r = dec
        .decrypt(std::iter::once(id))
        .map_err(|e| format!("cannot decrypt: {e}"))?;
    let mut plain = Zeroizing::new(Vec::new());
    r.read_to_end(&mut plain).map_err(|e| e.to_string())?;
    Ok(plain)
}

pub fn unseal<T: DeserializeOwned>(id: &dyn age::Identity, sealed: &str) -> Result<T, String> {
    let plain = unseal_bytes(id, sealed)?;
    serde_json::from_slice(&plain).map_err(|_| "bad sealed data".to_string())
}

/// Secret values for a job, as base64, wiped when dropped.
#[derive(Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Values(pub BTreeMap<String, String>);

impl Values {
    pub fn from_bytes(m: &BTreeMap<String, Zeroizing<Vec<u8>>>) -> Values {
        Values(
            m.iter()
                .map(|(k, v)| (k.clone(), B64.encode(v.as_slice())))
                .collect(),
        )
    }

    pub fn to_bytes(&self) -> Result<BTreeMap<String, Zeroizing<Vec<u8>>>, String> {
        let mut out = BTreeMap::new();
        for (k, v) in &self.0 {
            let b = B64.decode(v.as_bytes()).map_err(|_| "bad secret value")?;
            out.insert(k.clone(), Zeroizing::new(b));
        }
        Ok(out)
    }
}

impl Drop for Values {
    fn drop(&mut self) {
        for v in self.0.values_mut() {
            zeroize::Zeroize::zeroize(v);
        }
    }
}

impl std::fmt::Debug for Values {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.keys()).finish()
    }
}

/// The readable part of a job: only what routing needs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Job {
    pub v: u32,
    pub runner: String,
    /// Random and single use: what the runner checks against replays.
    pub job: String,
    /// Unix seconds after which the runner refuses the job.
    pub not_after: i64,
    /// `seal` of a `JobBody`, to the runner's key.
    pub sealed: String,
}

/// What the runner reads once it has opened the job.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct JobBody {
    /// Repeats the outer fields, so they cannot be moved onto another body.
    pub job: String,
    pub runner: String,
    /// The request id, for the logs on both sides.
    pub id: String,
    /// Hash of the action the human approved.
    pub hash: String,
    pub approved_by: String,
    /// Whether the approval needed a TOTP code.
    pub totp: bool,
    pub exec: ExecSpec,
    pub timeout_sec: i64,
    /// References that are public fields, which are not redacted.
    pub public: Vec<String>,
    pub secrets: Values,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct JobResult {
    pub v: u32,
    pub job: String,
    pub runner: String,
    /// `seal` of a `ResultBody`, to the server's key.
    pub sealed: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ResultBody {
    pub job: String,
    pub id: String,
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

/// The pairing code without dashes or case, as both sides key the HMAC.
pub fn normalize_code(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn hmac_b64(code: &str, parts: &[&str]) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(normalize_code(code).as_bytes())
        .expect("hmac accepts any key length");
    for p in parts {
        m.update(p.as_bytes());
        m.update(b"\n");
    }
    B64.encode(m.finalize().into_bytes())
}

fn ct_eq(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EnrollIn {
    pub v: u32,
    pub name: String,
    /// ed25519, base64: checks the runner's requests and results.
    pub sign_key: String,
    /// age X25519 recipient: jobs are sealed to it.
    pub age_key: String,
    /// HMAC with the pairing code over the fields above. The code itself
    /// never travels.
    pub proof: String,
    pub info: Info,
}

impl EnrollIn {
    pub fn proof_for(&self, code: &str) -> String {
        hmac_b64(
            code,
            &[
                "ucanrun-enroll-v2",
                &self.name,
                &self.sign_key,
                &self.age_key,
            ],
        )
    }

    pub fn proves(&self, code: &str) -> bool {
        ct_eq(&self.proof, &self.proof_for(code))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EnrollOut {
    pub name: String,
    /// ed25519, base64: the runner pins it and checks every job with it.
    pub server_key: String,
    /// age recipient the runner seals its results to.
    pub server_age: String,
    /// HMAC with the same code over the server keys and the runner's own key,
    /// so the runner knows it reached the server that showed the code.
    pub proof: String,
}

impl EnrollOut {
    pub fn proof_for(&self, code: &str, runner_key: &str) -> String {
        hmac_b64(
            code,
            &[
                "ucanrun-enroll-ok-v2",
                &self.name,
                &self.server_key,
                &self.server_age,
                runner_key,
            ],
        )
    }

    pub fn proves(&self, code: &str, runner_key: &str) -> bool {
        ct_eq(&self.proof, &self.proof_for(code, runner_key))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PollIn {
    /// `seal` of the runner's `Info`, to the server: its rules say which
    /// programs exist there, which is nobody else's business.
    pub info: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PollOut {
    pub jobs: Vec<Signed>,
}

/// The bytes a runner signs for one request.
pub fn request_message(method: &str, path: &str, date: i64, nonce: &str, body: &[u8]) -> Vec<u8> {
    format!(
        "ucanrun-runner-v2\n{method}\n{path}\n{date}\n{nonce}\n{}",
        hex::encode(Sha256::digest(body))
    )
    .into_bytes()
}

/// Headers for one signed runner request.
pub fn sign_request(
    key: &SigningKey,
    name: &str,
    method: &str,
    path: &str,
    date: i64,
    body: &[u8],
) -> Vec<(&'static str, String)> {
    let nonce = hex::encode(rand::random::<[u8; 16]>());
    let sig = B64.encode(
        key.sign(&request_message(method, path, date, &nonce, body))
            .to_bytes(),
    );
    vec![
        (H_RUNNER, name.to_string()),
        (H_DATE, date.to_string()),
        (H_NONCE, nonce),
        (H_SIG, sig),
    ]
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
            job: "abc".into(),
            ..Default::default()
        };
        let s = Signed::new(&k, &j);
        assert_eq!(s.open::<Job>(&k.verifying_key()).unwrap(), j);
        assert!(s.open::<Job>(&other.verifying_key()).is_err());
        let mut t = s.clone();
        t.payload = t.payload.replace("abc", "abd");
        assert!(t.open::<Job>(&k.verifying_key()).is_err());
        assert_eq!(verifying_key(&public_b64(&k)).unwrap(), k.verifying_key());
        assert_eq!(fingerprint(&public_b64(&k)).len(), 19);
        // The identity point is a weak key.
        let mut ident = [0u8; 32];
        ident[0] = 1;
        assert!(verifying_key(&B64.encode(ident)).is_err());
    }

    #[test]
    fn seal_round_trip() {
        let id = x25519::Identity::generate();
        let other = x25519::Identity::generate();
        let mut m = BTreeMap::new();
        m.insert("pw".to_string(), Zeroizing::new(b"hunter2\n".to_vec()));
        let body = JobBody {
            exec: ExecSpec {
                argv: vec!["/usr/bin/systemctl".into()],
                ..Default::default()
            },
            secrets: Values::from_bytes(&m),
            ..Default::default()
        };
        let s = seal(&id.to_public().to_string(), &body).unwrap();
        assert!(!s.contains("hunter2") && !s.contains("systemctl"));
        let back: JobBody = unseal(&id, &s).unwrap();
        assert_eq!(
            back.secrets.to_bytes().unwrap()["pw"].as_slice(),
            b"hunter2\n"
        );
        assert_eq!(back.exec.argv[0], "/usr/bin/systemctl");
        assert!(unseal::<JobBody>(&other, &s).is_err());
    }

    #[test]
    fn enroll_proofs_bind_code_and_keys() {
        let mut e = EnrollIn {
            name: "box".into(),
            sign_key: "S".into(),
            age_key: "A".into(),
            ..Default::default()
        };
        e.proof = e.proof_for("ABCD-EFGH-JKLM");
        assert!(e.proves("abcdefghjklm"), "case and dashes do not matter");
        assert!(!e.proves("ABCD-EFGH-JKLN"));
        let mut swapped = e.clone();
        swapped.sign_key = "S2".into();
        assert!(
            !swapped.proves("ABCD-EFGH-JKLM"),
            "a swapped key breaks the proof"
        );
        let mut o = EnrollOut {
            name: "box".into(),
            server_key: "K".into(),
            server_age: "age1x".into(),
            ..Default::default()
        };
        o.proof = o.proof_for("ABCD-EFGH-JKLM", "S");
        assert!(o.proves("ABCDEFGHJKLM", "S"));
        assert!(!o.proves("ABCDEFGHJKLM", "S2"));
        o.server_key = "K2".into();
        assert!(!o.proves("ABCDEFGHJKLM", "S"));
    }

    #[test]
    fn request_signature_covers_every_part() {
        let k = SigningKey::generate(&mut rand::rngs::OsRng);
        let hs = sign_request(&k, "box", "POST", "/v1/runner/poll", 100, b"{}");
        let get = |n: &str| hs.iter().find(|(k, _)| *k == n).unwrap().1.clone();
        let nonce = get(H_NONCE);
        let ok = |m: &str, p: &str, d: i64, b: &[u8]| {
            verify(
                &k.verifying_key(),
                &request_message(m, p, d, &nonce, b),
                &get(H_SIG),
            )
            .is_ok()
        };
        assert!(ok("POST", "/v1/runner/poll", 100, b"{}"));
        assert!(!ok("POST", "/v1/runner/result", 100, b"{}"));
        assert!(!ok("POST", "/v1/runner/poll", 101, b"{}"));
        assert!(!ok("POST", "/v1/runner/poll", 100, b"{ }"));
    }
}
