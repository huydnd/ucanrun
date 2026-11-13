//! What the server is and what it is connected to, for the overview.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use super::{Core, rfc3339_nano};

/// A Telegram poll this recent means the bot is connected.
const TELEGRAM_FRESH: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, Default, Serialize)]
pub struct TelegramLink {
    pub configured: bool,
    pub paired: bool,
    /// The last poll succeeded recently.
    pub connected: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_ok: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SystemInfo {
    pub version: String,
    pub started: String,
    pub uptime_secs: u64,
    pub host: String,
    pub os: String,
    pub arch: String,
    pub uid: i64,
    /// Running in a container, so `host` is the container's id.
    pub container: bool,
    pub exec: bool,
    pub locked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_free_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_total_mb: Option<u64>,
    pub audit_entries: usize,
    pub telegram: TelegramLink,
    /// Discord, LINE, WhatsApp.
    pub chats: Vec<super::ChatView>,
    pub runners: usize,
    pub runners_online: usize,
    pub tokens: usize,
    /// Tokens that sent a request in the last 24 hours.
    pub agents_24h: usize,
}

/// Resident memory of this process, from /proc on Linux.
fn memory_mb() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb: u64 = s
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))?
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    Some(kb / 1024)
}

/// Free and total space of the file system holding `dir`, in MiB.
fn disk_mb(dir: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs fills the struct it is given for a NUL-terminated path.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let unit = s.f_frsize as u64;
    Some((
        s.f_bavail as u64 * unit / (1 << 20),
        s.f_blocks as u64 * unit / (1 << 20),
    ))
}

impl Core {
    pub fn system(&self) -> SystemInfo {
        let now = self.now();
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = i64::from(unsafe { libc::getuid() });
        let audit_entries = self.audit.head().0;
        let (locked, tokens, telegram, bot) = {
            let g = self.inner();
            let st = g.st.as_ref();
            (
                st.is_none(),
                st.map_or(0, |s| s.tokens.len()),
                TelegramLink {
                    configured: g.bot.is_some(),
                    paired: st.is_some_and(|s| s.telegram.user_id != 0),
                    ..Default::default()
                },
                g.bot.clone(),
            )
        };
        let mut telegram = telegram;
        if let Some(b) = bot {
            let (ok, err) = b.link();
            telegram.connected =
                ok.is_some_and(|t| now.duration_since(t).map_or(true, |d| d < TELEGRAM_FRESH));
            telegram.last_ok = ok.map(rfc3339_nano).unwrap_or_default();
            telegram.error = err;
        }
        let runners = self.runners().unwrap_or_default();
        let since = rfc3339_nano(now - Duration::from_secs(24 * 3600));
        let agents_24h = self
            .audit
            .tail(5000)
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e.event == "request" && e.time >= since)
            .map(|e| e.actor)
            .collect::<BTreeSet<_>>()
            .len();
        let disk = disk_mb(&self.opt.data_dir);
        SystemInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            started: rfc3339_nano(self.started),
            uptime_secs: SystemTime::now()
                .duration_since(self.started)
                .map_or(0, |d| d.as_secs()),
            host: crate::client::host_name(),
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            uid,
            container: std::path::Path::new("/.dockerenv").exists()
                || std::path::Path::new("/run/.containerenv").exists(),
            exec: self.opt.allow_exec,
            locked,
            memory_mb: memory_mb(),
            disk_free_mb: disk.map(|d| d.0),
            disk_total_mb: disk.map(|d| d.1),
            audit_entries,
            telegram,
            chats: self.chats().unwrap_or_default(),
            runners_online: runners.iter().filter(|r| r.online).count(),
            runners: runners.len(),
            tokens,
            agents_24h,
        }
    }
}
