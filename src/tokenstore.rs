//! Where `ucr` keeps the agent's server URL and token between runs, so the
//! token does not have to sit in an environment variable every process
//! inherits. Windows: the user's Credential Manager (DPAPI-protected).
//! Elsewhere: `~/.config/ucanrun/token` and `url`, both 0600.

/// What `ucr login` saved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Saved {
    pub url: String,
    pub token: String,
}

#[cfg(not(windows))]
mod imp {
    use super::Saved;
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    use std::path::PathBuf;

    fn dir() -> PathBuf {
        match std::env::var("XDG_CONFIG_HOME") {
            Ok(d) if !d.is_empty() => PathBuf::from(d).join("ucanrun"),
            _ => PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config/ucanrun"),
        }
    }

    pub fn location() -> String {
        dir().join("token").display().to_string()
    }

    pub fn load() -> Option<Saved> {
        let d = dir();
        let token = std::fs::read_to_string(d.join("token"))
            .ok()?
            .trim()
            .to_string();
        if token.is_empty() {
            return None;
        }
        let url = std::fs::read_to_string(d.join("url"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        Some(Saved { url, token })
    }

    fn write(path: PathBuf, s: &str) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(format!("{s}\n").as_bytes())?;
        f.sync_all()?;
        std::fs::rename(tmp, path)
    }

    pub fn save(s: &Saved) -> Result<String, String> {
        let d = dir();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&d)
            .map_err(|e| e.to_string())?;
        write(d.join("token"), &s.token).map_err(|e| e.to_string())?;
        if !s.url.is_empty() {
            write(d.join("url"), &s.url).map_err(|e| e.to_string())?;
        }
        Ok(d.join("token").display().to_string())
    }

    pub fn delete() -> Result<Option<String>, String> {
        let d = dir();
        let had = d
            .join("token")
            .exists()
            .then(|| d.join("token").display().to_string());
        for f in ["token", "url"] {
            match std::fs::remove_file(d.join(f)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(had)
    }
}

#[cfg(windows)]
mod imp {
    use super::Saved;
    use std::path::PathBuf;
    use std::ptr;
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree,
        CredReadW, CredWriteW,
    };

    /// One generic credential per Windows user.
    const TARGET: &str = "ucanrun";
    const CRED: &str = "Windows Credential Manager (ucanrun)";
    /// ERROR_NOT_FOUND
    const NOT_FOUND: i32 = 1168;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Used when the Credential Manager is not there, as in an SSH session
    /// (error 1312). %APPDATA% is readable by its user only by default.
    fn dir() -> PathBuf {
        PathBuf::from(std::env::var("APPDATA").unwrap_or_default()).join("ucanrun")
    }

    pub fn location() -> String {
        format!("{CRED}, or {} where that is not available", dir().display())
    }

    fn cred_load() -> Option<Saved> {
        let target = wide(TARGET);
        let mut cred: *mut CREDENTIALW = ptr::null_mut();
        // SAFETY: target is NUL-terminated; on success cred points to memory
        // that CredFree releases below.
        if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) } == 0 {
            return None;
        }
        // SAFETY: cred is valid until CredFree; the blob and user name are
        // owned by it.
        let saved = unsafe {
            let c = &*cred;
            let blob = std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize);
            let token = String::from_utf8_lossy(blob).trim().to_string();
            let mut url = String::new();
            if !c.UserName.is_null() {
                let mut n = 0;
                while *c.UserName.add(n) != 0 {
                    n += 1;
                }
                url = String::from_utf16_lossy(std::slice::from_raw_parts(c.UserName, n));
            }
            Saved { url, token }
        };
        // SAFETY: frees what CredReadW allocated.
        unsafe { CredFree(cred.cast()) };
        (!saved.token.is_empty()).then_some(saved)
    }

    fn cred_save(s: &Saved) -> std::io::Result<()> {
        let mut target = wide(TARGET);
        let mut user = wide(&s.url);
        let mut blob = s.token.as_bytes().to_vec();
        let cred = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            Comment: ptr::null_mut(),
            // SAFETY: FILETIME is plain data; zero means unset.
            LastWritten: unsafe { std::mem::zeroed() },
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: ptr::null_mut(),
            TargetAlias: ptr::null_mut(),
            UserName: user.as_mut_ptr(),
        };
        // SAFETY: every pointer in cred stays valid for the call.
        let ok = unsafe { CredWriteW(&cred, 0) } != 0;
        let err = std::io::Error::last_os_error();
        zeroize::Zeroize::zeroize(&mut blob);
        if ok { Ok(()) } else { Err(err) }
    }

    fn cred_delete() -> std::io::Result<bool> {
        let target = wide(TARGET);
        // SAFETY: target is NUL-terminated.
        if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0 {
            return Ok(true);
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(NOT_FOUND) {
            Ok(false)
        } else {
            Err(e)
        }
    }

    fn file_load() -> Option<Saved> {
        let d = dir();
        let token = std::fs::read_to_string(d.join("token"))
            .ok()?
            .trim()
            .to_string();
        let url = std::fs::read_to_string(d.join("url"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        (!token.is_empty()).then_some(Saved { url, token })
    }

    pub fn load() -> Option<Saved> {
        cred_load().or_else(file_load)
    }

    pub fn save(s: &Saved) -> Result<String, String> {
        if cred_save(s).is_ok() {
            // A file left from an SSH session would be read as a fallback.
            let _ = std::fs::remove_file(dir().join("token"));
            return Ok(CRED.into());
        }
        let d = dir();
        std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
        std::fs::write(d.join("token"), format!("{}\n", s.token)).map_err(|e| e.to_string())?;
        if !s.url.is_empty() {
            std::fs::write(d.join("url"), format!("{}\n", s.url)).map_err(|e| e.to_string())?;
        }
        Ok(d.join("token").display().to_string())
    }

    pub fn delete() -> Result<Option<String>, String> {
        let mut gone = None;
        // In an SSH session the Credential Manager is missing; that is not
        // an error here, the file may still be there.
        if let Ok(true) = cred_delete() {
            gone = Some(CRED.to_string());
        }
        let d = dir();
        for f in ["token", "url"] {
            match std::fs::remove_file(d.join(f)) {
                Ok(()) if f == "token" => gone = Some(d.join(f).display().to_string()),
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(gone)
    }
}

pub use imp::{delete, load, location, save};
