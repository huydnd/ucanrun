//! Passkeys (WebAuthn): registration and assertion checks.
//!
//! Only what ucanrun needs: one relying party (the public host), user
//! verification always required, no attestation (the browser is asked for
//! none), and ES256, EdDSA or RS256 keys. Every check a relying party must
//! make is here: type, challenge and origin in the client data; RP id hash,
//! user present and verified flags, and a signature counter that must grow in
//! the authenticator data.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use ciborium::value::Value as Cbor;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const ES256: i64 = -7;
pub const EDDSA: i64 = -8;
pub const RS256: i64 = -257;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

/// The site passkeys are bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rp {
    /// Host name, such as `ucanrun.example.com`.
    pub id: String,
    /// Scheme, host and port the browser shows, such as `https://ucanrun.example.com`.
    pub origin: String,
}

impl Rp {
    /// From a public URL such as `https://ucanrun.example.com`.
    pub fn from_url(url: &str) -> Option<Rp> {
        let u = url::Url::parse(url.trim()).ok()?;
        let host = u.host_str()?.to_ascii_lowercase();
        if host.parse::<std::net::IpAddr>().is_ok() {
            return None; // WebAuthn does not accept IP addresses
        }
        let secure = u.scheme() == "https" || host == "localhost";
        if !secure {
            return None;
        }
        Some(Rp {
            id: host,
            origin: u.origin().ascii_serialization(),
        })
    }
}

/// A registered passkey. The public key is not secret; the state file it
/// lives in is signed, so it cannot be swapped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Passkey {
    /// Credential id, base64url.
    pub id: String,
    pub name: String,
    pub alg: i64,
    /// ES256: SEC1 point. EdDSA: 32 bytes. RS256: `n` then `e`, see `Rsa`.
    pub key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub key_e: String,
    pub sign_count: u32,
    pub created: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_used: String,
}

pub fn b64u(b: &[u8]) -> String {
    B64U.encode(b)
}

fn unb64u(s: &str) -> Result<Vec<u8>, String> {
    B64U.decode(s.trim_end_matches('='))
        .map_err(|_| "bad base64url".to_string())
}

pub fn new_challenge() -> Vec<u8> {
    rand::random::<[u8; 32]>().to_vec()
}

/// Options for `navigator.credentials.create`, binary fields as base64url.
pub fn creation_options(rp: &Rp, user: &[u8], challenge: &[u8], existing: &[Passkey]) -> Value {
    json!({
        "challenge": b64u(challenge),
        "rp": {"id": rp.id, "name": "ucanrun"},
        "user": {"id": b64u(user), "name": "owner", "displayName": "ucanrun"},
        "pubKeyCredParams": [
            {"type": "public-key", "alg": ES256},
            {"type": "public-key", "alg": EDDSA},
            {"type": "public-key", "alg": RS256},
        ],
        "authenticatorSelection": {"residentKey": "preferred", "userVerification": "required"},
        "attestation": "none",
        "excludeCredentials": existing.iter().map(|p| json!({"type": "public-key", "id": p.id})).collect::<Vec<_>>(),
        "timeout": 120000,
    })
}

/// Options for `navigator.credentials.get`.
pub fn request_options(rp: &Rp, challenge: &[u8], keys: &[Passkey]) -> Value {
    json!({
        "challenge": b64u(challenge),
        "rpId": rp.id,
        "allowCredentials": keys.iter().map(|p| json!({"type": "public-key", "id": p.id})).collect::<Vec<_>>(),
        "userVerification": "required",
        "timeout": 120000,
    })
}

/// The credential the browser returned, as the web page sends it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Credential {
    pub id: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data: String,
    #[serde(rename = "attestationObject")]
    pub attestation: String,
    #[serde(rename = "authenticatorData")]
    pub auth_data: String,
    pub signature: String,
}

fn check_client(rp: &Rp, raw: &[u8], kind: &str, challenge: &[u8]) -> Result<(), String> {
    let c: Value = serde_json::from_slice(raw).map_err(|_| "bad client data")?;
    if c["type"].as_str() != Some(kind) {
        return Err("wrong ceremony".into());
    }
    let got = unb64u(c["challenge"].as_str().unwrap_or(""))?;
    if !bool::from(got.ct_eq(challenge)) {
        return Err("the challenge does not match".into());
    }
    if c["origin"].as_str() != Some(rp.origin.as_str()) {
        return Err(format!("wrong origin {}", c["origin"]));
    }
    if c["crossOrigin"].as_bool() == Some(true) {
        return Err("cross-origin use is not allowed".into());
    }
    Ok(())
}

struct AuthData<'a> {
    flags: u8,
    count: u32,
    rest: &'a [u8],
}

fn parse_auth<'a>(rp: &Rp, b: &'a [u8]) -> Result<AuthData<'a>, String> {
    if b.len() < 37 {
        return Err("short authenticator data".into());
    }
    let want = Sha256::digest(rp.id.as_bytes());
    if !bool::from(b[..32].ct_eq(&want)) {
        return Err("the passkey belongs to another site".into());
    }
    let flags = b[32];
    if flags & FLAG_UP == 0 || flags & FLAG_UV == 0 {
        return Err("the authenticator did not verify the user".into());
    }
    let count = u32::from_be_bytes([b[33], b[34], b[35], b[36]]);
    Ok(AuthData {
        flags,
        count,
        rest: &b[37..],
    })
}

fn map_get(m: &[(Cbor, Cbor)], key: i64) -> Option<&Cbor> {
    m.iter()
        .find(|(k, _)| k.as_integer().and_then(|i| i64::try_from(i).ok()) == Some(key))
        .map(|(_, v)| v)
}

fn bytes(v: Option<&Cbor>) -> Result<Vec<u8>, String> {
    v.and_then(|v| v.as_bytes().cloned())
        .ok_or_else(|| "bad key".to_string())
}

/// Reads a COSE public key into a `Passkey`'s alg and key fields.
fn cose(raw: &[u8], p: &mut Passkey) -> Result<(), String> {
    let v: Cbor = ciborium::de::from_reader(raw).map_err(|_| "bad key")?;
    let m = v.as_map().ok_or("bad key")?;
    let alg = map_get(m, 3)
        .and_then(|v| v.as_integer())
        .and_then(|i| i64::try_from(i).ok())
        .ok_or("bad key")?;
    match alg {
        ES256 => {
            let (x, y) = (bytes(map_get(m, -2))?, bytes(map_get(m, -3))?);
            if x.len() != 32 || y.len() != 32 {
                return Err("bad key".into());
            }
            let mut pt = vec![4u8];
            pt.extend(x);
            pt.extend(y);
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&pt).map_err(|_| "bad key")?;
            p.key = b64u(&pt);
        }
        EDDSA => {
            let x = bytes(map_get(m, -2))?;
            let arr: [u8; 32] = x.as_slice().try_into().map_err(|_| "bad key")?;
            ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|_| "bad key")?;
            p.key = b64u(&x);
        }
        RS256 => {
            let (n, e) = (bytes(map_get(m, -1))?, bytes(map_get(m, -2))?);
            if n.len() < 256 {
                return Err("RSA keys under 2048 bits are refused".into());
            }
            p.key = b64u(&n);
            p.key_e = b64u(&e);
        }
        _ => return Err(format!("unsupported key algorithm {alg}")),
    }
    p.alg = alg;
    Ok(())
}

/// Checks a `create()` result and returns the new passkey.
pub fn finish_register(rp: &Rp, challenge: &[u8], c: &Credential) -> Result<Passkey, String> {
    let client = unb64u(&c.client_data)?;
    check_client(rp, &client, "webauthn.create", challenge)?;
    let att: Cbor =
        ciborium::de::from_reader(&unb64u(&c.attestation)?[..]).map_err(|_| "bad attestation")?;
    let m = att.as_map().ok_or("bad attestation")?;
    let auth = m
        .iter()
        .find(|(k, _)| k.as_text() == Some("authData"))
        .and_then(|(_, v)| v.as_bytes())
        .ok_or("bad attestation")?;
    let a = parse_auth(rp, auth)?;
    if a.flags & FLAG_AT == 0 || a.rest.len() < 18 {
        return Err("no credential in the attestation".into());
    }
    let n = u16::from_be_bytes([a.rest[16], a.rest[17]]) as usize;
    if n == 0 || n > 1023 || a.rest.len() < 18 + n {
        return Err("bad credential id".into());
    }
    let id = &a.rest[18..18 + n];
    if b64u(id) != c.id.trim_end_matches('=') {
        return Err("credential id mismatch".into());
    }
    let mut p = Passkey {
        id: b64u(id),
        sign_count: a.count,
        ..Default::default()
    };
    cose(&a.rest[18 + n..], &mut p)?;
    Ok(p)
}

/// Checks a `get()` result against the registered passkeys. Returns the
/// index of the passkey used and its new signature count.
pub fn finish_assert(
    rp: &Rp,
    challenge: &[u8],
    c: &Credential,
    keys: &[Passkey],
) -> Result<(usize, u32), String> {
    let i = keys
        .iter()
        .position(|p| p.id == c.id.trim_end_matches('='))
        .ok_or("this passkey is not registered")?;
    let p = &keys[i];
    let client = unb64u(&c.client_data)?;
    check_client(rp, &client, "webauthn.get", challenge)?;
    let auth = unb64u(&c.auth_data)?;
    let a = parse_auth(rp, &auth)?;
    // A counter that does not grow means a cloned authenticator; zero on
    // both sides means the authenticator keeps none.
    if (a.count != 0 || p.sign_count != 0) && a.count <= p.sign_count {
        return Err("the passkey's counter went backwards; it may have been copied".into());
    }
    let mut msg = auth.clone();
    msg.extend_from_slice(&Sha256::digest(&client));
    let sig = unb64u(&c.signature)?;
    verify(p, &msg, &sig)?;
    Ok((i, a.count))
}

fn verify(p: &Passkey, msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let key = unb64u(&p.key)?;
    let bad = || "the passkey signature does not match".to_string();
    match p.alg {
        ES256 => {
            use p256::ecdsa::signature::Verifier;
            let k = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key).map_err(|_| bad())?;
            let s = p256::ecdsa::Signature::from_der(sig).map_err(|_| bad())?;
            k.verify(msg, &s).map_err(|_| bad())
        }
        EDDSA => {
            let arr: [u8; 32] = key.as_slice().try_into().map_err(|_| bad())?;
            let k = ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|_| bad())?;
            let s = ed25519_dalek::Signature::from_slice(sig).map_err(|_| bad())?;
            k.verify_strict(msg, &s).map_err(|_| bad())
        }
        RS256 => {
            use rsa::pkcs1v15::{Signature, VerifyingKey};
            use rsa::signature::Verifier;
            let n = rsa::BigUint::from_bytes_be(&key);
            let e = rsa::BigUint::from_bytes_be(&unb64u(&p.key_e)?);
            let k = rsa::RsaPublicKey::new(n, e).map_err(|_| bad())?;
            let v = VerifyingKey::<Sha256>::new(k);
            let s = Signature::try_from(sig).map_err(|_| bad())?;
            v.verify(msg, &s).map_err(|_| bad())
        }
        _ => Err(bad()),
    }
}

#[cfg(test)]
pub(crate) mod testkit {
    //! A software authenticator for tests: makes the same bytes a browser
    //! and a security key would.
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    pub struct Fake {
        pub key: SigningKey,
        pub id: Vec<u8>,
        pub count: u32,
    }

    pub fn rp() -> Rp {
        Rp::from_url("https://ucanrun.example.com").unwrap()
    }

    fn client(rp: &Rp, kind: &str, challenge: &str) -> Vec<u8> {
        json!({"type": kind, "challenge": challenge, "origin": rp.origin, "crossOrigin": false})
            .to_string()
            .into_bytes()
    }

    fn auth(rp: &Rp, flags: u8, count: u32) -> Vec<u8> {
        let mut a = Sha256::digest(rp.id.as_bytes()).to_vec();
        a.push(flags);
        a.extend(count.to_be_bytes());
        a
    }

    impl Fake {
        pub fn new() -> Fake {
            Fake {
                key: SigningKey::random(&mut rand::rngs::OsRng),
                id: rand::random::<[u8; 16]>().to_vec(),
                count: 0,
            }
        }

        /// The browser's answer to `creation_options`.
        pub fn create(&self, rp: &Rp, options: &Value) -> Value {
            let point = self.key.verifying_key().to_encoded_point(false);
            let cose = Cbor::Map(vec![
                (Cbor::Integer(1.into()), Cbor::Integer(2.into())),
                (Cbor::Integer(3.into()), Cbor::Integer((-7).into())),
                (Cbor::Integer((-1).into()), Cbor::Integer(1.into())),
                (
                    Cbor::Integer((-2).into()),
                    Cbor::Bytes(point.x().unwrap().to_vec()),
                ),
                (
                    Cbor::Integer((-3).into()),
                    Cbor::Bytes(point.y().unwrap().to_vec()),
                ),
            ]);
            let mut a = auth(rp, FLAG_UP | FLAG_UV | FLAG_AT, 0);
            a.extend([0u8; 16]);
            a.extend((self.id.len() as u16).to_be_bytes());
            a.extend(&self.id);
            ciborium::ser::into_writer(&cose, &mut a).unwrap();
            let att = Cbor::Map(vec![
                (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
                (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
                (Cbor::Text("authData".into()), Cbor::Bytes(a)),
            ]);
            let mut raw = vec![];
            ciborium::ser::into_writer(&att, &mut raw).unwrap();
            json!({"id": b64u(&self.id),
                   "clientDataJSON": b64u(&client(rp, "webauthn.create", options["challenge"].as_str().unwrap())),
                   "attestationObject": b64u(&raw)})
        }

        /// The browser's answer to `request_options`.
        pub fn get(&mut self, rp: &Rp, options: &Value) -> Value {
            self.count += 1;
            let a = auth(rp, FLAG_UP | FLAG_UV, self.count);
            let c = client(rp, "webauthn.get", options["challenge"].as_str().unwrap());
            let mut msg = a.clone();
            msg.extend_from_slice(&Sha256::digest(&c));
            let sig: p256::ecdsa::Signature = self.key.sign(&msg);
            json!({"id": b64u(&self.id), "clientDataJSON": b64u(&c), "authenticatorData": b64u(&a),
                   "signature": b64u(sig.to_der().as_bytes())})
        }
    }
}

#[cfg(test)]
mod unit {
    use super::testkit::*;
    use super::*;

    fn cred(v: Value) -> Credential {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn rp_from_url() {
        assert_eq!(rp().origin, "https://ucanrun.example.com");
        assert!(
            Rp::from_url("http://ucanrun.example.com").is_none(),
            "needs https"
        );
        assert!(Rp::from_url("https://10.0.0.1").is_none(), "no IPs");
        assert_eq!(
            Rp::from_url("http://localhost:8780").unwrap().origin,
            "http://localhost:8780"
        );
    }

    #[test]
    fn register_then_assert_and_every_check() {
        let rp = rp();
        let mut f = Fake::new();
        let ch = new_challenge();
        let opts = creation_options(&rp, b"user", &ch, &[]);
        let p = finish_register(&rp, &ch, &cred(f.create(&rp, &opts))).unwrap();
        assert_eq!(p.alg, ES256);
        // Another challenge, another site, another ceremony: refused.
        assert!(finish_register(&rp, &new_challenge(), &cred(f.create(&rp, &opts))).is_err());
        let evil = Rp::from_url("https://ucanrun.evil.example").unwrap();
        assert!(
            finish_register(
                &rp,
                &ch,
                &cred(f.create(&evil, &creation_options(&evil, b"u", &ch, &[])))
            )
            .is_err()
        );

        let keys = vec![p];
        let ch = new_challenge();
        let opts = request_options(&rp, &ch, &keys);
        let got = f.get(&rp, &opts);
        assert_eq!(
            finish_assert(&rp, &ch, &cred(got.clone()), &keys).unwrap(),
            (0, 1)
        );
        // A changed signature, a stale counter, a wrong challenge: refused.
        let mut bad = got.clone();
        bad["clientDataJSON"] = json!(b64u(
            br#"{"type":"webauthn.get","challenge":"x","origin":"https://ucanrun.example.com"}"#
        ));
        assert!(finish_assert(&rp, &ch, &cred(bad), &keys).is_err());
        let mut k2 = keys.clone();
        k2[0].sign_count = 5;
        assert!(
            finish_assert(&rp, &ch, &cred(got.clone()), &k2)
                .unwrap_err()
                .contains("counter")
        );
        assert!(finish_assert(&rp, &new_challenge(), &cred(got), &keys).is_err());
        let other = Fake::new();
        let mut o = other;
        let stranger = o.get(&rp, &opts);
        assert!(
            finish_assert(&rp, &ch, &cred(stranger), &keys)
                .unwrap_err()
                .contains("not registered")
        );
    }
}
