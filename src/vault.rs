//! Secrets as individual age files. A random X25519 identity decrypts them and
//! is itself wrapped with the passphrase (age scrypt). Adding a secret needs only
//! the public recipient, so it works while the vault is locked.

use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::RwLock;
use std::time::SystemTime;

use age::secrecy::{ExposeSecret, SecretString};
use age::{Decryptor, Encryptor, x25519};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Bound for a single secret value.
pub const MAX_SECRET_SIZE: usize = 64 << 10;

#[derive(Debug)]
pub enum Error {
    Locked,
    BadPass,
    Exists,
    NotFound,
    InvalidName,
    Msg(String),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Locked => f.write_str("vault locked"),
            Error::BadPass => f.write_str("wrong passphrase"),
            Error::Exists => f.write_str("vault already initialized"),
            Error::NotFound => f.write_str("secret not found"),
            Error::InvalidName => f.write_str("invalid secret name"),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub name: String,
    pub updated: SystemTime,
}

pub struct Vault {
    dir: PathBuf,
    /// scrypt log2(N). Zero means the age default.
    pub work_factor: u8,
    identity: RwLock<Option<x25519::Identity>>,
}

/// `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`
pub fn valid_name(n: &str) -> bool {
    let b = n.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return false;
    }
    let first = b[0].is_ascii_alphanumeric() || b[0] == b'_';
    first
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

fn pass_secret(pass: &[u8]) -> Result<SecretString> {
    // Go converts the bytes to a string without validation; require UTF-8 here.
    let s = std::str::from_utf8(pass).map_err(|_| Error::Msg("passphrase is not UTF-8".into()))?;
    Ok(SecretString::from(s.to_owned()))
}

impl Vault {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Vault {
            dir: dir.into(),
            work_factor: 0,
            identity: RwLock::new(None),
        }
    }

    fn identity_path(&self) -> PathBuf {
        self.dir.join("identity.age")
    }

    fn recipient_path(&self) -> PathBuf {
        self.dir.join("recipient.txt")
    }

    fn secret_path(&self, n: &str) -> PathBuf {
        self.dir.join("secrets").join(format!("{n}.age"))
    }

    pub fn initialized(&self) -> bool {
        self.identity_path().exists()
    }

    pub fn is_locked(&self) -> bool {
        self.identity.read().unwrap().is_none()
    }

    /// Creates a new vault and leaves it unlocked.
    pub fn init(&self, pass: &[u8]) -> Result<()> {
        let mut guard = self.identity.write().unwrap();
        if self.initialized() {
            return Err(Error::Exists);
        }
        mkdir_all(&self.dir.join("secrets"))?;
        let id = x25519::Identity::generate();
        self.write_identity(&id, pass)?;
        let rcpt = format!("{}\n", id.to_public());
        atomic_write(&self.recipient_path(), rcpt.as_bytes())?;
        *guard = Some(id);
        Ok(())
    }

    fn write_identity(&self, id: &x25519::Identity, pass: &[u8]) -> Result<()> {
        let mut r = age::scrypt::Recipient::new(pass_secret(pass)?);
        if self.work_factor > 0 {
            r.set_work_factor(self.work_factor);
        }
        let enc = Encryptor::with_recipients(std::iter::once(&r as &dyn age::Recipient))
            .map_err(|e| Error::Msg(e.to_string()))?;
        let mut buf = Vec::new();
        let mut w = enc.wrap_output(&mut buf)?;
        w.write_all(id.to_string().expose_secret().as_bytes())?;
        w.finish()?;
        atomic_write(&self.identity_path(), &buf)
    }

    fn load_identity(&self, pass: &[u8]) -> Result<x25519::Identity> {
        let f = fs::File::open(self.identity_path())?;
        let si = age::scrypt::Identity::new(pass_secret(pass)?);
        let dec = Decryptor::new(f).map_err(|_| Error::BadPass)?;
        let mut r = dec
            .decrypt(std::iter::once(&si as &dyn age::Identity))
            .map_err(|_| Error::BadPass)?;
        let mut b = Zeroizing::new(Vec::new());
        r.read_to_end(&mut b).map_err(|_| Error::BadPass)?;
        let s = Zeroizing::new(
            std::str::from_utf8(&b)
                .map_err(|_| Error::BadPass)?
                .trim()
                .to_owned(),
        );
        x25519::Identity::from_str(&s).map_err(|e| Error::Msg(e.to_string()))
    }

    pub fn unlock(&self, pass: &[u8]) -> Result<()> {
        let id = self.open(pass)?;
        self.adopt(id);
        Ok(())
    }

    /// Derives the identity without changing state. scrypt is slow, so callers
    /// run it outside their own locks and then `adopt` the result.
    pub fn open(&self, pass: &[u8]) -> Result<x25519::Identity> {
        self.load_identity(pass)
    }

    pub fn adopt(&self, id: x25519::Identity) {
        *self.identity.write().unwrap() = Some(id);
    }

    /// Checks a passphrase without changing the lock state.
    pub fn verify(&self, pass: &[u8]) -> Result<()> {
        self.load_identity(pass).map(|_| ())
    }

    pub fn lock(&self) {
        *self.identity.write().unwrap() = None;
    }

    /// Re-wraps the identity. Secret files are untouched.
    pub fn change_passphrase(&self, old: &[u8], new: &[u8]) -> Result<()> {
        let id = self.load_identity(old)?;
        let _guard = self.identity.write().unwrap();
        self.write_identity(&id, new)
    }

    /// Key that authenticates server state.
    pub fn mac_key(&self) -> Result<Vec<u8>> {
        let g = self.identity.read().unwrap();
        let id = g.as_ref().ok_or(Error::Locked)?;
        Self::mac_key_for(id)
    }

    /// The state key of an identity that is not adopted, to read the state
    /// before the vault opens.
    pub fn mac_key_for(id: &x25519::Identity) -> Result<Vec<u8>> {
        let s = id.to_string();
        let hk = Hkdf::<Sha256>::new(None, s.expose_secret().as_bytes());
        let mut out = vec![0u8; 32];
        hk.expand(b"ucanrun state mac v1", &mut out)
            .map_err(|e| Error::Msg(e.to_string()))?;
        Ok(out)
    }

    /// The vault's public age recipient, for data sealed to the server.
    pub fn recipient(&self) -> Result<String> {
        Ok(fs::read_to_string(self.recipient_path())?
            .trim()
            .to_string())
    }

    /// Opens data sealed to the vault's recipient. Needs the vault open.
    pub fn unseal_bytes(&self, sealed: &str) -> Result<Zeroizing<Vec<u8>>> {
        let g = self.identity.read().unwrap();
        let id = g.as_ref().ok_or(Error::Locked)?;
        crate::runner::proto::unseal_bytes(id, sealed).map_err(Error::Msg)
    }

    /// Seed of the key that signs runner jobs. Derived from the identity like
    /// the state key, so it needs no storage and exists only while unlocked.
    pub fn runner_seed(&self) -> Result<Zeroizing<[u8; 32]>> {
        let g = self.identity.read().unwrap();
        let id = g.as_ref().ok_or(Error::Locked)?;
        let s = id.to_string();
        let hk = Hkdf::<Sha256>::new(None, s.expose_secret().as_bytes());
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(b"ucanrun runner signing v1", &mut out[..])
            .map_err(|e| Error::Msg(e.to_string()))?;
        Ok(out)
    }

    /// Encrypts a secret. Needs only the recipient, so it works while locked.
    pub fn put(&self, name: &str, value: &[u8]) -> Result<()> {
        if !valid_name(name) {
            return Err(Error::InvalidName);
        }
        if value.is_empty() || value.len() > MAX_SECRET_SIZE {
            return Err(Error::Msg(format!(
                "secret size must be 1..{MAX_SECRET_SIZE} bytes"
            )));
        }
        let raw = fs::read_to_string(self.recipient_path())?;
        let rcpt =
            x25519::Recipient::from_str(raw.trim()).map_err(|e| Error::Msg(e.to_string()))?;
        let enc = Encryptor::with_recipients(std::iter::once(&rcpt as &dyn age::Recipient))
            .map_err(|e| Error::Msg(e.to_string()))?;
        let mut buf = Vec::new();
        let mut w = enc.wrap_output(&mut buf)?;
        w.write_all(value)?;
        w.finish()?;
        atomic_write(&self.secret_path(name), &buf)
    }

    pub fn get(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        if !valid_name(name) {
            return Err(Error::InvalidName);
        }
        let id = self.identity.read().unwrap().clone();
        let id = id.ok_or(Error::Locked)?;
        let f = match fs::File::open(self.secret_path(name)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::NotFound),
            Err(e) => return Err(e.into()),
        };
        let wrap = |e: String| Error::Msg(format!("decrypt {name}: {e}"));
        let dec = Decryptor::new(f).map_err(|e| wrap(e.to_string()))?;
        let mut r = dec
            .decrypt(std::iter::once(&id as &dyn age::Identity))
            .map_err(|e| wrap(e.to_string()))?;
        let mut out = Zeroizing::new(Vec::new());
        r.read_to_end(&mut out).map_err(|e| wrap(e.to_string()))?;
        Ok(out)
    }

    pub fn delete(&self, name: &str) -> Result<()> {
        if !valid_name(name) {
            return Err(Error::InvalidName);
        }
        match fs::remove_file(self.secret_path(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// Secret metadata, sorted by name. Names starting with `_` are internal.
    pub fn list(&self) -> Result<Vec<Meta>> {
        let rd = match fs::read_dir(self.dir.join("secrets")) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for e in rd {
            let e = e?;
            let fname = e.file_name().to_string_lossy().into_owned();
            let Some(n) = fname.strip_suffix(".age") else {
                continue;
            };
            if n.starts_with('_') {
                continue;
            }
            let updated = e
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            out.push(Meta {
                name: n.to_owned(),
                updated,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

fn mkdir_all(p: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(p)
}

/// Writes via a temp file and rename, mode 0600; creates parents 0700.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        mkdir_all(parent)?;
    }
    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", hex::encode(suffix)));
    let tmp = PathBuf::from(tmp);
    let res = (|| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

impl Drop for Vault {
    fn drop(&mut self) {
        // Identity zeroizes itself on drop; clear eagerly anyway.
        if let Ok(mut g) = self.identity.write() {
            *g = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> (tempfile::TempDir, Vault) {
        let d = tempfile::tempdir().unwrap();
        let mut v = Vault::new(d.path().join("vault"));
        v.work_factor = 2;
        (d, v)
    }

    #[test]
    fn names() {
        for n in ["a", "_x", "A.b-c_1", &"a".repeat(64)] {
            assert!(valid_name(n), "{n}");
        }
        for n in ["", ".a", "-a", "a/b", "a b", "../x", &"a".repeat(65), "é"] {
            assert!(!valid_name(n), "{n}");
        }
    }

    #[test]
    fn roundtrip_lock_and_errors() {
        let (_d, v) = vault();
        assert!(!v.initialized());
        v.init(b"pw").unwrap();
        assert!(v.initialized() && !v.is_locked());
        assert!(matches!(v.init(b"pw"), Err(Error::Exists)));
        v.put("b", b"two").unwrap();
        v.put("a", b"one").unwrap();
        v.put("_hidden", b"h").unwrap();
        assert_eq!(&**v.get("a").unwrap(), b"one");
        let names: Vec<_> = v.list().unwrap().into_iter().map(|m| m.name).collect();
        assert_eq!(names, ["a", "b"]);
        let k1 = v.mac_key().unwrap();
        v.lock();
        assert!(matches!(v.get("a"), Err(Error::Locked)));
        assert!(matches!(v.mac_key(), Err(Error::Locked)));
        v.put("c", b"three").unwrap(); // works while locked
        assert!(matches!(v.unlock(b"bad"), Err(Error::BadPass)));
        v.unlock(b"pw").unwrap();
        assert_eq!(&**v.get("c").unwrap(), b"three");
        assert_eq!(v.mac_key().unwrap(), k1);
        assert!(matches!(v.get("zz"), Err(Error::NotFound)));
        assert!(matches!(v.get("../x"), Err(Error::InvalidName)));
        v.delete("a").unwrap();
        assert!(matches!(v.delete("a"), Err(Error::NotFound)));
        assert!(v.put("e", b"").is_err());
        assert_eq!(
            v.put("e", &vec![0; MAX_SECRET_SIZE + 1])
                .unwrap_err()
                .to_string(),
            "secret size must be 1..65536 bytes"
        );
    }

    #[test]
    fn change_passphrase_and_modes() {
        use std::os::unix::fs::PermissionsExt;
        let (d, v) = vault();
        v.init(b"old").unwrap();
        v.put("s", b"val").unwrap();
        v.change_passphrase(b"old", b"new").unwrap();
        assert!(matches!(v.verify(b"old"), Err(Error::BadPass)));
        v.verify(b"new").unwrap();
        v.lock();
        v.unlock(b"new").unwrap();
        assert_eq!(&**v.get("s").unwrap(), b"val");
        let root = d.path().join("vault");
        let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(root.clone()), 0o700);
        assert_eq!(mode(root.join("secrets")), 0o700);
        assert_eq!(mode(root.join("identity.age")), 0o600);
        assert_eq!(mode(root.join("secrets/s.age")), 0o600);
        assert!(
            fs::read_dir(root.join("secrets")).unwrap().all(|e| !e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp"))
        );
    }
}
