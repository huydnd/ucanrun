//! Append-only JSONL log with a SHA-256 hash chain. Never log secret values.

use std::fmt;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::gojson;

#[derive(Debug)]
pub enum Error {
    /// Display is "chain broken at entry N"; the payload is N (1-based).
    ChainBroken(usize),
    Msg(String),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ChainBroken(n) => write!(f, "chain broken at entry {n}"),
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// RFC 3339 nanoseconds, UTC, trailing zeros trimmed.
    pub time: String,
    pub event: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub actor: String,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub fields: Map<String, Value>,
    pub prev: String,
    pub hash: String,
}

/// Same bytes as Go's `json.Marshal(Entry)`: struct order, omitempty, HTML escaping.
fn marshal(e: &Entry, hash: &str) -> String {
    let mut s = String::from("{\"time\":");
    gojson::write_str(&mut s, &e.time);
    s.push_str(",\"event\":");
    gojson::write_str(&mut s, &e.event);
    if !e.actor.is_empty() {
        s.push_str(",\"actor\":");
        gojson::write_str(&mut s, &e.actor);
    }
    if !e.fields.is_empty() {
        s.push_str(",\"fields\":");
        s.push_str(&gojson::to_string(&Value::Object(e.fields.clone())));
    }
    s.push_str(",\"prev\":");
    gojson::write_str(&mut s, &e.prev);
    s.push_str(",\"hash\":");
    gojson::write_str(&mut s, hash);
    s.push('}');
    s
}

fn hash_of(e: &Entry) -> String {
    hex::encode(Sha256::digest(marshal(e, "").as_bytes()))
}

/// Go's RFC3339Nano in UTC.
fn now_rfc3339_nano() -> String {
    let t = OffsetDateTime::now_utc();
    let mut s = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    let frac = format!("{:09}", t.nanosecond());
    let frac = frac.trim_end_matches('0');
    if !frac.is_empty() {
        s.push('.');
        s.push_str(frac);
    }
    s.push('Z');
    s
}

fn read_all(path: &Path) -> Result<Vec<Entry>> {
    let text = match std::fs::read(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    let mut lines: Vec<&[u8]> = text.split(|b| *b == b'\n').collect();
    if lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop(); // text after the final newline only
    }
    for l in lines {
        let l = l.strip_suffix(b"\r").unwrap_or(l);
        let e: Entry = serde_json::from_slice(l)
            .map_err(|e| Error::Msg(format!("line {}: {e}", out.len() + 1)))?;
        out.push(e);
    }
    Ok(out)
}

pub struct Log {
    path: PathBuf,
    head: Mutex<(usize, String)>,
}

impl Log {
    pub fn open(path: impl Into<PathBuf>) -> Result<Log> {
        let path = path.into();
        let es = read_all(&path)?;
        let head = match es.last() {
            Some(e) => (es.len(), e.hash.clone()),
            None => (0, String::new()),
        };
        Ok(Log {
            path,
            head: Mutex::new(head),
        })
    }

    pub fn head(&self) -> (usize, String) {
        self.head.lock().unwrap().clone()
    }

    pub fn append(&self, event: &str, actor: &str, fields: Map<String, Value>) -> Result<()> {
        let mut head = self.head.lock().unwrap();
        let mut e = Entry {
            time: now_rfc3339_nano(),
            event: event.to_owned(),
            actor: actor.to_owned(),
            fields,
            prev: head.1.clone(),
            hash: String::new(),
        };
        e.hash = hash_of(&e);
        let mut line = marshal(&e, &e.hash);
        line.push('\n');
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.path)?;
        f.write_all(line.as_bytes())?;
        head.0 += 1;
        head.1 = e.hash;
        Ok(())
    }

    /// Newest n entries, newest first.
    pub fn tail(&self, n: usize) -> Result<Vec<Entry>> {
        let _g = self.head.lock().unwrap();
        let es = read_all(&self.path)?;
        Ok(es.into_iter().rev().take(n).collect())
    }
}

/// Walks the chain and returns the number of valid entries.
pub fn verify(path: &Path) -> Result<usize> {
    let es = read_all(path)?;
    let mut prev = String::new();
    for (i, e) in es.iter().enumerate() {
        if e.prev != prev || hash_of(e) != e.hash {
            return Err(Error::ChainBroken(i + 1));
        }
        prev = e.hash.clone();
    }
    Ok(es.len())
}

/// Whether 1-based entry number `count` exists with the given hash.
pub fn contains(path: &Path, count: usize, hash: &str) -> Result<bool> {
    if count == 0 {
        return Ok(true);
    }
    let es = read_all(path)?;
    Ok(es.len() >= count && es[count - 1].hash == hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fields(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn chain_append_tail_contains() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("audit.jsonl");
        assert_eq!(verify(&p).unwrap(), 0);
        let l = Log::open(&p).unwrap();
        l.append("a", "", Map::new()).unwrap();
        l.append("b", "web", fields(json!({"k": "<v>&", "n": 3})))
            .unwrap();
        l.append("c", "x", Map::new()).unwrap();
        let (n, h) = l.head();
        assert_eq!(n, 3);
        assert_eq!(verify(&p).unwrap(), 3);
        let t = l.tail(2).unwrap();
        assert_eq!(
            t.iter().map(|e| e.event.as_str()).collect::<Vec<_>>(),
            ["c", "b"]
        );
        assert!(contains(&p, 3, &h).unwrap());
        assert!(!contains(&p, 3, "x").unwrap());
        assert!(!contains(&p, 4, &h).unwrap());
        assert!(contains(&p, 0, "").unwrap());
        let l2 = Log::open(&p).unwrap();
        assert_eq!(l2.head(), (3, h));
        l2.append("d", "", Map::new()).unwrap();
        assert_eq!(verify(&p).unwrap(), 4);
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(raw.contains("\\u003c") && raw.contains("\\u0026"));
    }

    #[test]
    fn detects_edit_and_removal() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("audit.jsonl");
        let l = Log::open(&p).unwrap();
        for e in ["a", "b", "c"] {
            l.append(e, "", Map::new()).unwrap();
        }
        let raw = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, raw.replacen("\"event\":\"b\"", "\"event\":\"x\"", 1)).unwrap();
        assert_eq!(
            verify(&p).unwrap_err().to_string(),
            "chain broken at entry 2"
        );
        let lines: Vec<_> = raw.lines().collect();
        std::fs::write(&p, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(matches!(verify(&p), Err(Error::ChainBroken(2))));
    }

    #[test]
    fn time_format_trims_zeros() {
        let s = now_rfc3339_nano();
        assert!(s.ends_with('Z') && !s.contains("0Z"));
    }
}
