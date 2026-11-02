//! RFC 6238 with SHA-1, 30 s steps and 6 digits.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use subtle::ConstantTimeEq;

const STEP: u64 = 30;

/// A new secret: 20 random bytes, base32 without padding.
pub fn generate() -> String {
    let mut b = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut b);
    BASE32_NOPAD.encode(&b)
}

/// Go's `url.PathEscape` for a path segment.
fn path_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => out.push(b as char),
            b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b'=' | b':' | b'@' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Go's `url.QueryEscape`.
fn query_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn uri(secret: &str, account: &str) -> String {
    // url.Values.Encode sorts by key.
    let q = [
        ("digits", "6"),
        ("issuer", "ucanrun"),
        ("period", "30"),
        ("secret", secret),
    ]
    .iter()
    .map(|(k, v)| format!("{k}={}", query_escape(v)))
    .collect::<Vec<_>>()
    .join("&");
    format!("otpauth://totp/ucanrun:{}?{q}", path_escape(account))
}

fn code_for(key: &[u8], counter: u64) -> String {
    let mut m = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(&counter.to_be_bytes());
    let h = m.finalize().into_bytes();
    let o = (h[h.len() - 1] & 0x0f) as usize;
    let n = u32::from_be_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]) & 0x7fff_ffff;
    format!("{:06}", n % 1_000_000)
}

fn decode(secret: &str) -> Option<Vec<u8>> {
    BASE32_NOPAD
        .decode(secret.trim().to_uppercase().as_bytes())
        .ok()
}

/// Code for Unix time `unix`; None when the secret is not valid base32.
pub fn code(secret: &str, unix: i64) -> Option<String> {
    Some(code_for(&decode(secret)?, (unix / STEP as i64) as u64))
}

/// Accepts the current step +/-1 and only steps newer than `last`, making
/// every code single-use. Returns the matched step, or 0 on failure.
pub fn verify(secret: &str, input: &str, unix: i64, last: u64) -> u64 {
    let Some(key) = decode(secret) else { return 0 };
    if input.len() != 6 {
        return 0;
    }
    let cur = unix / STEP as i64;
    let mut matched = 0;
    for c in cur - 1..=cur + 1 {
        if c < 0 {
            continue;
        }
        let c = c as u64;
        let ok: bool = code_for(&key, c).as_bytes().ct_eq(input.as_bytes()).into();
        if ok && c > last {
            matched = c;
        }
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_vectors() {
        assert_eq!(code(SECRET, 59).unwrap(), "287082");
        assert_eq!(code(SECRET, 1111111109).unwrap(), "081804");
        assert!(code("!!!", 0).is_none());
    }

    #[test]
    fn verify_window_and_replay() {
        let t = 1_111_111_109;
        let c = code(SECRET, t).unwrap();
        let step = (t / 30) as u64;
        assert_eq!(verify(SECRET, &c, t, 0), step);
        assert_eq!(verify(SECRET, &c, t + 30, 0), step); // one step late
        assert_eq!(verify(SECRET, &c, t + 90, 0), 0);
        assert_eq!(verify(SECRET, &c, t, step), 0); // replay
        assert_eq!(verify(SECRET, &c[..5], t, 0), 0);
        assert_eq!(verify("bad!", &c, t, 0), 0);
        assert_eq!(verify(&SECRET.to_lowercase(), &c, t, 0), step);
    }

    #[test]
    fn generate_and_uri() {
        let s = generate();
        assert_eq!(s.len(), 32);
        assert!(decode(&s).is_some());
        assert_eq!(
            uri("ABC", "a b@x"),
            "otpauth://totp/ucanrun:a%20b@x?digits=6&issuer=ucanrun&period=30&secret=ABC"
        );
    }
}
