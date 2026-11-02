//! tar.gz backups of the data directory (port of `internal/backup`).

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use rand::RngCore;
use tar::{Archive, EntryType};

/// Limits against decompression bombs; parameters so tests stay fast.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_file_size: u64,
    pub max_total_size: u64,
    pub max_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_file_size: 64 << 20,
            max_total_size: 1 << 30,
            max_entries: 100_000,
        }
    }
}

const REQUIRED: [&str; 3] = ["vault/identity.age", "vault/recipient.txt", "state.json"];

/// A fresh server creates these before anyone can restore.
const STARTUP_FILES: [&str; 2] = [".keep", "gate.token"];

#[derive(Debug)]
pub enum Error {
    Msg(String),
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Msg(m) => f.write_str(m),
            Error::Io(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn err<T>(m: impl Into<String>) -> Result<T> {
    Err(Error::Msg(m.into()))
}

/// Writes a gzipped tar of the regular files under `data_dir`.
pub fn create<W: Write>(w: W, data_dir: &Path) -> Result<()> {
    let md = fs::symlink_metadata(data_dir)?;
    if !md.is_dir() {
        return err("data directory is not a directory");
    }
    let mut tw = tar::Builder::new(GzEncoder::new(w, Compression::default()));
    walk(&mut tw, data_dir, "")?;
    tw.into_inner()?.finish()?;
    Ok(())
}

fn walk<W: Write>(tw: &mut tar::Builder<W>, dir: &Path, prefix: &str) -> Result<()> {
    let mut names: Vec<_> = fs::read_dir(dir)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<io::Result<_>>()?;
    names.sort();
    for n in names {
        let name = n.to_string_lossy().into_owned();
        if name.ends_with(".tmp") || name == "gate.token" {
            continue;
        }
        let path = dir.join(&n);
        let md = fs::symlink_metadata(&path)?;
        let rel = format!("{prefix}{name}");
        if md.is_dir() {
            walk(tw, &path, &format!("{rel}/"))?;
        } else if md.is_file() {
            // Read it whole so a concurrent size change cannot corrupt the stream.
            let data = fs::read(&path)?;
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(EntryType::Regular);
            h.set_size(data.len() as u64);
            h.set_mode(0o600);
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            h.set_mtime(mtime);
            tw.append_data(&mut h, &rel, data.as_slice())?;
        }
    }
    Ok(())
}

/// Validates a backup and returns its entry count.
pub fn check<R: Read>(r: R) -> Result<usize> {
    check_with(r, &Limits::default())
}

pub fn check_with<R: Read>(r: R, lim: &Limits) -> Result<usize> {
    let mut gz = GzDecoder::new(r);
    let mut seen = HashSet::new();
    let (mut count, mut total) = (0usize, 0u64);
    {
        let mut ar = Archive::new(&mut gz);
        for e in ar.entries()? {
            let mut e = e?;
            let (name, kind) = validate_header(&e, total, lim)?;
            let n = io::copy(&mut (&mut e).take(lim.max_file_size + 1), &mut io::sink())?;
            if n > lim.max_file_size {
                return err(format!("file {name:?} exceeds size limit"));
            }
            total += n;
            if total > lim.max_total_size {
                return err("backup exceeds total size limit");
            }
            count += 1;
            if count > lim.max_entries {
                return err("backup has too many entries");
            }
            if kind == EntryType::Regular {
                seen.insert(name);
            }
        }
    }
    drain(&mut gz)?;
    check_required(&seen)?;
    Ok(count)
}

/// Reads to the end of the gzip stream so a bad checksum is reported.
fn drain<R: Read>(r: &mut R) -> Result<()> {
    io::copy(r, &mut io::sink())?;
    Ok(())
}

fn check_required(seen: &HashSet<String>) -> Result<()> {
    for req in REQUIRED {
        if !seen.contains(req) {
            return err(format!("backup missing {req}"));
        }
    }
    Ok(())
}

fn validate_header<R: Read>(
    e: &tar::Entry<R>,
    total: u64,
    lim: &Limits,
) -> Result<(String, EntryType)> {
    let raw_bytes = e.path_bytes();
    let raw = String::from_utf8_lossy(&raw_bytes).into_owned();
    if e.link_name_bytes().is_some_and(|l| !l.is_empty()) {
        return err(format!("links are not allowed: {raw:?}"));
    }
    let kind = e.header().entry_type();
    if !matches!(kind, EntryType::Regular | EntryType::Directory) {
        return err(format!(
            "unsupported entry type {} for {raw:?}",
            kind.as_byte()
        ));
    }
    if raw.is_empty()
        || raw.contains('\\')
        || raw.contains('\0')
        || raw.starts_with('/')
        || std::str::from_utf8(&raw_bytes).is_err()
    {
        return err(format!("invalid archive path {raw:?}"));
    }
    let clean = raw.strip_suffix('/').unwrap_or(&raw);
    if clean.is_empty()
        || clean
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return err(format!("invalid archive path {raw:?}"));
    }
    let size = e.size();
    if size > lim.max_file_size {
        return err(format!("file {raw:?} exceeds size limit ({size} bytes)"));
    }
    if kind == EntryType::Directory && size != 0 {
        return err(format!("directory {raw:?} has non-zero size"));
    }
    if total + size > lim.max_total_size {
        return err("backup exceeds total size limit");
    }
    Ok((clean.to_owned(), kind))
}

/// Extracts a backup into `data_dir` if it does not exist, is empty, or holds
/// only startup files. Nothing changes unless the whole archive is valid.
pub fn restore<R: Read>(r: R, data_dir: &Path) -> Result<()> {
    restore_with(r, data_dir, &Limits::default())
}

pub fn restore_with<R: Read>(r: R, data_dir: &Path, lim: &Limits) -> Result<()> {
    let mut existed = false;
    match fs::symlink_metadata(data_dir) {
        Ok(md) => {
            if !md.is_dir() {
                return err("restore target is not a directory");
            }
            for e in fs::read_dir(data_dir)? {
                let n = e?.file_name();
                if !STARTUP_FILES.iter().any(|s| n == **s) {
                    return err("restore target directory is not empty");
                }
            }
            existed = true;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    // Inside the target when it exists: in a container the data directory is a
    // mounted volume and its parent is read-only.
    let parent = if existed {
        data_dir.to_path_buf()
    } else {
        let p = data_dir.parent().unwrap_or(Path::new(".")).to_path_buf();
        let p = if p.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            p
        };
        mkdir_all(&p)?;
        p
    };
    let tmp = make_temp(&parent)?;
    let res = restore_into(r, &tmp, lim).and_then(|()| {
        if existed {
            move_dir_contents(&tmp, data_dir)
        } else {
            fs::rename(&tmp, data_dir).map_err(Error::from)
        }
    });
    let _ = fs::remove_dir_all(&tmp);
    res
}

fn restore_into<R: Read>(r: R, tmp: &Path, lim: &Limits) -> Result<()> {
    let mut gz = GzDecoder::new(r);
    let mut seen = HashSet::new();
    let (mut count, mut total) = (0usize, 0u64);
    {
        let mut ar = Archive::new(&mut gz);
        for e in ar.entries()? {
            let mut e = e?;
            let (name, kind) = validate_header(&e, total, lim)?;
            count += 1;
            if count > lim.max_entries {
                return err("backup has too many entries");
            }
            let target = tmp.join(&name);
            if kind == EntryType::Directory {
                mkdir_all_0700(tmp, &target)?;
                continue;
            }
            seen.insert(name.clone());
            let mut data = Vec::new();
            (&mut e)
                .take(lim.max_file_size + 1)
                .read_to_end(&mut data)?;
            if data.len() as u64 > lim.max_file_size {
                return err(format!("file {name:?} exceeds size limit"));
            }
            total += data.len() as u64;
            if total > lim.max_total_size {
                return err("backup exceeds total size limit");
            }
            mkdir_all_0700(tmp, target.parent().unwrap_or(tmp))?;
            write_file(&target, &data)?;
        }
    }
    drain(&mut gz)?;
    check_required(&seen)
}

fn write_file(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn mkdir_all(p: &Path) -> io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(p)
}

fn make_temp(parent: &Path) -> io::Result<PathBuf> {
    loop {
        let mut b = [0u8; 6];
        rand::rngs::OsRng.fill_bytes(&mut b);
        let p = parent.join(format!(".ucr-restore-{}", hex::encode(b)));
        match fs::DirBuilder::new().mode(0o700).create(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Creates `dir` and chmods every new component under `root` to 0700.
fn mkdir_all_0700(root: &Path, dir: &Path) -> io::Result<()> {
    mkdir_all(dir)?;
    let Ok(rel) = dir.strip_prefix(root) else {
        return Ok(());
    };
    let mut cur = root.to_path_buf();
    for part in rel.components() {
        cur.push(part);
        fs::set_permissions(&cur, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn move_dir_contents(src: &Path, dst: &Path) -> Result<()> {
    for e in fs::read_dir(src)? {
        let e = e?;
        let d = dst.join(e.file_name());
        if fs::rename(e.path(), &d).is_err() {
            copy_tree(&e.path(), &d)?;
        }
    }
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    if fs::symlink_metadata(src)?.is_dir() {
        mkdir_all(dst)?;
        fs::set_permissions(dst, fs::Permissions::from_mode(0o700))?;
        for e in fs::read_dir(src)? {
            let e = e?;
            copy_tree(&e.path(), &dst.join(e.file_name()))?;
        }
    } else {
        write_file(dst, &fs::read(src)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(root: &Path) {
        for (p, d) in [
            ("vault/identity.age", "id"),
            ("vault/recipient.txt", "r"),
            ("vault/secrets/a.age", "s"),
            ("state.json", "{}"),
            ("audit.jsonl", ""),
        ] {
            let f = root.join(p);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, d).unwrap();
        }
    }

    pub(crate) fn archive(entries: &[(&str, EntryType, &[u8], &str)]) -> Vec<u8> {
        let mut tw = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (name, ty, data, link) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(*ty);
            h.set_size(data.len() as u64);
            h.set_mode(0o600);
            // Write the name directly so ".." and absolute paths survive.
            h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            if !link.is_empty() {
                h.set_link_name(link).unwrap();
            }
            h.set_cksum();
            tw.append(&h, *data).unwrap();
        }
        tw.into_inner().unwrap().finish().unwrap()
    }

    fn valid() -> Vec<(&'static str, EntryType, &'static [u8], &'static str)> {
        vec![
            ("vault/identity.age", EntryType::Regular, b"i", ""),
            ("vault/recipient.txt", EntryType::Regular, b"r", ""),
            ("state.json", EntryType::Regular, b"{}", ""),
        ]
    }

    #[test]
    fn round_trip_skips_tmp_and_gate() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        fixture(&src);
        fs::write(src.join("gate.token"), "x").unwrap();
        fs::write(src.join("vault/x.tmp"), "x").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", src.join("link")).unwrap();
        let mut buf = Vec::new();
        create(&mut buf, &src).unwrap();
        assert_eq!(check(buf.as_slice()).unwrap(), 5);
        let dst = d.path().join("dst");
        restore(buf.as_slice(), &dst).unwrap();
        assert_eq!(fs::read(dst.join("vault/secrets/a.age")).unwrap(), b"s");
        assert!(!dst.join("gate.token").exists() && !dst.join("link").exists());
        let m = |p: &str| fs::metadata(dst.join(p)).unwrap().permissions().mode() & 0o777;
        assert_eq!((m("vault"), m("state.json")), (0o700, 0o600));
        // existing target: only startup files allowed, temp dir cleaned up
        assert!(restore(buf.as_slice(), &dst).is_err());
        let dst2 = d.path().join("dst2");
        fs::create_dir(&dst2).unwrap();
        fs::write(dst2.join(".keep"), "").unwrap();
        fs::write(dst2.join("gate.token"), "t").unwrap();
        restore(buf.as_slice(), &dst2).unwrap();
        assert!(dst2.join("state.json").exists());
        assert!(fs::read_dir(&dst2).unwrap().all(|e| {
            !e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".ucr-restore")
        }));
    }

    #[test]
    fn rejects_bad_entries() {
        let cases: Vec<(&str, EntryType, &str, &str)> = vec![
            (
                "../evil",
                EntryType::Regular,
                "",
                "invalid archive path \"../evil\"",
            ),
            (
                "/abs",
                EntryType::Regular,
                "",
                "invalid archive path \"/abs\"",
            ),
            (
                "a/../b",
                EntryType::Regular,
                "",
                "invalid archive path \"a/../b\"",
            ),
            (
                "a\\b",
                EntryType::Regular,
                "",
                "invalid archive path \"a\\\\b\"",
            ),
            (
                "sym",
                EntryType::Symlink,
                "/etc/passwd",
                "links are not allowed: \"sym\"",
            ),
            (
                "hard",
                EntryType::Link,
                "state.json",
                "links are not allowed: \"hard\"",
            ),
            (
                "dev",
                EntryType::Char,
                "",
                "unsupported entry type 51 for \"dev\"",
            ),
            (
                "fifo",
                EntryType::Fifo,
                "",
                "unsupported entry type 54 for \"fifo\"",
            ),
        ];
        for (name, ty, link, want) in cases {
            let mut e = valid();
            e.push((name, ty, b"", link));
            let a = archive(&e);
            assert_eq!(check(a.as_slice()).unwrap_err().to_string(), want, "{name}");
            let d = tempfile::tempdir().unwrap();
            let dst = d.path().join("t");
            assert!(restore(a.as_slice(), &dst).is_err());
            assert!(!dst.exists());
            assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0, "temp leftover");
        }
    }

    #[test]
    fn missing_required_and_limits() {
        let a = archive(&valid()[..2]);
        assert_eq!(
            check(a.as_slice()).unwrap_err().to_string(),
            "backup missing state.json"
        );
        let a = archive(&valid());
        let lim = Limits {
            max_file_size: 1,
            ..Default::default()
        };
        assert!(
            check_with(a.as_slice(), &lim)
                .unwrap_err()
                .to_string()
                .contains("exceeds size limit")
        );
        let lim = Limits {
            max_total_size: 2,
            ..Default::default()
        };
        assert_eq!(
            check_with(a.as_slice(), &lim).unwrap_err().to_string(),
            "backup exceeds total size limit"
        );
        let lim = Limits {
            max_entries: 2,
            ..Default::default()
        };
        assert_eq!(
            check_with(a.as_slice(), &lim).unwrap_err().to_string(),
            "backup has too many entries"
        );
        assert!(check(&b"not gzip"[..]).is_err());
    }

    #[test]
    fn failed_restore_leaves_existing_target_untouched() {
        let d = tempfile::tempdir().unwrap();
        let dst = d.path().join("t");
        fs::create_dir(&dst).unwrap();
        fs::write(dst.join(".keep"), "").unwrap();
        let mut e = valid();
        e.push(("../x", EntryType::Regular, b"", ""));
        assert!(restore(archive(&e).as_slice(), &dst).is_err());
        let names: Vec<_> = fs::read_dir(&dst)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [std::ffi::OsString::from(".keep")]);
    }
}
