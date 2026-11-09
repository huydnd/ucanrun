//! Server commands: they need the data directory, so they run on Unix only.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rand::RngCore;
use zeroize::Zeroizing;

use ucanrun::core::{Core, Options};
use ucanrun::{backup, policy, prompt, vault, web};

use crate::{Res, env};

pub(crate) fn data_dir() -> PathBuf {
    match std::env::var("UCANRUN_DATA") {
        Ok(d) if !d.is_empty() => PathBuf::from(d),
        _ => PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".local/share/ucanrun"),
    }
}

pub(crate) fn vault_at() -> vault::Vault {
    vault::Vault::new(data_dir().join("vault"))
}

pub(crate) fn log(level: &str, msg: &str, kv: &[(&str, &str)]) {
    let t = time::OffsetDateTime::now_utc();
    let mut s = format!(
        "{:04}/{:02}/{:02} {:02}:{:02}:{:02} {level} {msg}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    for (k, v) in kv {
        s.push_str(&format!(" {k}={v}"));
    }
    eprintln!("{s}");
}

/// Go's time.ParseDuration, without negative values.
pub(crate) fn parse_duration(s: &str) -> Result<Duration, String> {
    let q = policy::gourl::quote;
    let bad = || format!("time: invalid duration {}", q(s));
    let mut rest = s.strip_prefix('+').unwrap_or(s);
    if rest == "0" {
        return Ok(Duration::ZERO);
    }
    if rest.is_empty() {
        return Err(bad());
    }
    let mut total = 0f64;
    while !rest.is_empty() {
        let n = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let (num, r) = rest.split_at(n);
        let v: f64 = num.parse().map_err(|_| bad())?;
        let u = r
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(r.len());
        let (unit, r) = r.split_at(u);
        let mult = match unit {
            "ns" => 1e-9,
            "us" | "\u{b5}s" | "\u{3bc}s" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "" => return Err(format!("time: missing unit in duration {}", q(s))),
            _ => {
                return Err(format!(
                    "time: unknown unit {} in duration {}",
                    q(unit),
                    q(s)
                ));
            }
        };
        total += v * mult;
        rest = r;
    }
    Ok(Duration::from_secs_f64(total))
}

/// The port of a host:port address, with Go's net.SplitHostPort errors.
pub(crate) fn port_of(addr: &str) -> Result<String, String> {
    let err = |why: &str| format!("address {addr}: {why}");
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| err("missing port in address"))?;
    let bracketed = host.starts_with('[') && host.ends_with(']');
    if host.contains(':') && !bracketed {
        return Err(err("too many colons in address"));
    }
    Ok(port.to_string())
}

/// The address people use, which also decides cookie security.
pub(crate) fn public_url() -> Result<String, String> {
    let raw = std::env::var("UCANRUN_PUBLIC_URL").unwrap_or_default();
    let v = raw.trim_end_matches('/');
    if v.is_empty() {
        let port = port_of(&env("UCANRUN_WEB_ADDR", "127.0.0.1:8780"))?;
        return Ok(format!("http://127.0.0.1:{port}"));
    }
    match policy::gourl::parse(v) {
        Some(u) if (u.scheme == "https" || u.scheme == "http") && !u.host.is_empty() => {
            Ok(v.to_string())
        }
        _ => Err("UCANRUN_PUBLIC_URL must look like https://ucanrun.example.com".into()),
    }
}

/// Keeps keys out of core files and away from same-uid processes.
pub(crate) fn harden() {
    // SAFETY: prctl with constant integer arguments.
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        let e = std::io::Error::last_os_error().to_string();
        log("WARN", "could not disable dumps", &[("err", &e)]);
    }
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a valid pointer to a local struct.
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) };
}

pub(crate) fn unlock_from_file(c: &Core, path: &str) -> Result<(), String> {
    let fi = std::fs::metadata(path).map_err(|e| e.to_string())?;
    let mode = fi.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        // Docker secrets mount read-only and owner-only.
        let m = format!("{mode:o}");
        log(
            "WARN",
            "UCANRUN_UNLOCK_FILE is readable by group or others",
            &[("mode", &m)],
        );
    }
    let b = Zeroizing::new(std::fs::read(path).map_err(|e| e.to_string())?);
    let mut end = b.len();
    while end > 0 && matches!(b[end - 1], b'\r' | b'\n') {
        end -= 1;
    }
    c.unlock_at_start(&b[..end]).map_err(|e| e.to_string())
}

pub(crate) async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let Ok(mut term) = signal(SignalKind::terminate()) else {
        let _ = tokio::signal::ctrl_c().await;
        return;
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

pub(crate) async fn serve() -> Res {
    let ttl = parse_duration(&env("UCANRUN_APPROVAL_TTL", "2m"))?;
    let dir = data_dir();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| e.to_string())?;
    let c = Core::new(Options {
        data_dir: dir.clone(),
        approval_ttl: ttl,
        telegram_api: env("UCANRUN_TELEGRAM_API", ""),
        allow_exec: env("UCANRUN_ENABLE_EXEC", "") == "1",
        lang: env("UCANRUN_LANG", ""),
        ..Default::default()
    })
    .map_err(|e| e.to_string())?;
    let res = serve_core(&c, &dir).await;
    let closing = c.clone();
    let _ = tokio::task::spawn_blocking(move || closing.close()).await;
    res
}

pub(crate) async fn serve_core(c: &Arc<Core>, dir: &Path) -> Res {
    let f = env("UCANRUN_UNLOCK_FILE", "");
    if !f.is_empty() {
        let cc = c.clone();
        let r = tokio::task::spawn_blocking(move || unlock_from_file(&cc, &f))
            .await
            .map_err(|e| e.to_string())?;
        match r {
            Err(e) => log(
                "ERROR",
                "UCANRUN_UNLOCK_FILE: vault stays locked",
                &[("err", &e)],
            ),
            Ok(()) => log("WARN", "vault unlocked from UCANRUN_UNLOCK_FILE", &[]),
        }
    }
    let mut setup = String::new();
    if !c.initialized() {
        let mut b = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut b);
        setup = hex::encode(b);
        // Goes to stdout, not the audit log, and stops working after setup.
        println!("ucanrun is not set up yet. Setup token: {setup}");
    }
    let public = public_url()?;
    let mut s = web::Server::new(
        c.clone(),
        &setup,
        dir.join("audit.jsonl"),
        public.starts_with("https://"),
    );
    if env("UCANRUN_GATE", "") == "off" {
        log(
            "WARN",
            "UCANRUN_GATE=off: the web UI has no access gate",
            &[],
        );
    } else {
        let (tok, created) =
            web::load_gate_token(dir, &env("UCANRUN_GATE_TOKEN", "")).map_err(|e| e.to_string())?;
        // Shown until setup finishes, so a restart mid-setup does not lose it.
        if created || !setup.is_empty() {
            println!("Access code: {tok}");
        }
        s.gate_token = tok;
    }
    if !setup.is_empty() {
        println!("Open {public} to finish setup. Show the access code again with: ucr gate");
    }
    let _ = std::io::stdout().flush();
    harden();
    let s = Arc::new(s);
    let web_addr = env("UCANRUN_WEB_ADDR", "127.0.0.1:8780");
    let agent_addr = env("UCANRUN_AGENT_ADDR", "127.0.0.1:8781");
    let mut ls = vec![];
    for addr in [&web_addr, &agent_addr] {
        let l = tokio::net::TcpListener::bind(addr.as_str())
            .await
            .map_err(|e| format!("listen tcp {addr}: {e}"))?;
        log("INFO", "listening", &[("addr", addr)]);
        ls.push(l);
    }
    let agent_l = ls.pop().expect("agent listener");
    let web_l = ls.pop().expect("web listener");
    let (tx, rx) = tokio::sync::watch::channel(false);
    let stop = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
        let _ = rx.wait_for(|v| *v).await;
    };
    let a = tokio::spawn(web::serve(web_l, s.handler(), stop(rx.clone())));
    let b = tokio::spawn(web::serve(agent_l, s.agent_handler(), stop(rx)));
    shutdown_signal().await;
    tx.send_replace(true);
    let _ = a.await;
    let _ = b.await;
    Ok(())
}

/// The container health check. The default image has no shell or wget.
pub(crate) async fn health() -> Res {
    let port = port_of(&env("UCANRUN_WEB_ADDR", "127.0.0.1:8780"))?;
    let cl = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| e.to_string())?;
    let r = cl
        .get(format!("http://127.0.0.1:{port}/healthz"))
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    if r.status() != reqwest::StatusCode::OK {
        return Err(format!("status {}", r.status().as_u16()));
    }
    Ok(())
}

pub(crate) fn add(args: &[String]) -> Res {
    if args.len() != 1 {
        return Err("usage: ucr add NAME".into());
    }
    if args[0].starts_with('_') {
        return Err(vault::Error::InvalidName.to_string());
    }
    let line = prompt::read_secret("Value (hidden): ")?;
    let val = line.as_str();
    vault_at()
        .put(&args[0], val.as_bytes())
        .map_err(|e| e.to_string())
}

pub(crate) fn list() -> Res {
    let l = vault_at().list().map_err(|e| e.to_string())?;
    let fmt = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    for m in l {
        let t = time::OffsetDateTime::from(m.updated);
        println!("{}\t{}", m.name, t.format(&fmt).unwrap_or_default());
    }
    Ok(())
}

pub(crate) fn do_backup(args: &[String]) -> Res {
    if args.len() != 1 {
        return Err("usage: ucr backup FILE".into());
    }
    if args[0] == "-" {
        let out = std::io::stdout().lock();
        return backup::create(out, &data_dir()).map_err(|e| e.to_string());
    }
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&args[0])
        .map_err(|e| e.to_string())?;
    if let Err(e) = backup::create(&f, &data_dir()) {
        drop(f);
        let _ = std::fs::remove_file(&args[0]);
        return Err(e.to_string());
    }
    f.sync_all().map_err(|e| e.to_string())
}

pub(crate) fn do_restore(args: &[String]) -> Res {
    if args.len() != 1 {
        return Err("usage: ucr restore FILE".into());
    }
    let r = if args[0] == "-" {
        backup::restore(std::io::stdin().lock(), &data_dir())
    } else {
        let f = std::fs::File::open(&args[0]).map_err(|e| e.to_string())?;
        backup::restore(f, &data_dir())
    };
    r.map_err(|e| e.to_string())
}

pub(crate) fn do_backup_check(args: &[String]) -> Res {
    if args.len() != 1 {
        return Err("usage: ucr backup-check FILE".into());
    }
    let n = if args[0] == "-" {
        backup::check(std::io::stdin().lock())
    } else {
        let f = std::fs::File::open(&args[0]).map_err(|e| e.to_string())?;
        backup::check(f)
    }
    .map_err(|e| e.to_string())?;
    println!("OK: {n} entries");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_like_go() {
        let d = |s: &str| parse_duration(s).unwrap();
        assert_eq!(d("2m"), Duration::from_secs(120));
        assert_eq!(d("1h30m"), Duration::from_secs(5400));
        assert_eq!(d("1.5s"), Duration::from_millis(1500));
        assert_eq!(d("400ms"), Duration::from_millis(400));
        assert_eq!(d("0"), Duration::ZERO);
        assert_eq!(
            parse_duration("x").unwrap_err(),
            "time: invalid duration \"x\""
        );
        assert_eq!(
            parse_duration("5").unwrap_err(),
            "time: missing unit in duration \"5\""
        );
        assert!(parse_duration("5d").is_err() && parse_duration("").is_err());
        assert!(parse_duration("-1s").is_err());
    }

    #[test]
    fn ports() {
        assert_eq!(port_of("127.0.0.1:8780").unwrap(), "8780");
        assert_eq!(port_of("[::1]:9").unwrap(), "9");
        assert_eq!(port_of(":8780").unwrap(), "8780");
        assert!(port_of("localhost").is_err() && port_of("::1:9").is_err());
    }
}
