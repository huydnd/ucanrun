//! `ucr` is the ucanrun credential broker: agents ask for an action, a human
//! approves it, and the server runs it without showing the secret.

use std::collections::BTreeMap;
use std::io::{BufRead, IsTerminal, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rand::RngCore;
use serde_json::Value;
use zeroize::Zeroizing;

use ucanrun::client::Client;
use ucanrun::core::{Core, Options};
use ucanrun::{audit, backup, mcp, policy, vault, web};

const USAGE: &str = "ucr: credential broker with human approval

Server, on the machine that holds the data directory:
  ucr serve                 run the web UI and agent API
  ucr add NAME              add or replace a secret (stdin, or a hidden prompt)
  ucr list                  list secret names
  ucr rm NAME               delete a secret
  ucr backup FILE           write a tar.gz backup of the data directory (- for stdout)
  ucr restore FILE          restore a backup into an empty data directory (- for stdin)
  ucr backup-check FILE     verify a backup archive
  ucr audit-verify          check the audit log chain
  ucr gate                  print the web access code
  ucr health                exit 0 if the server answers

Agent:
  ucr profiles              list permitted actions
  ucr run PROFILE [k=v...]  request an action (--reason \"text\")
  ucr doctor                check agent configuration and server connection
  ucr mcp                   stdio MCP server

Environment: UCANRUN_PUBLIC_URL, UCANRUN_GATE_TOKEN, UCANRUN_GATE=off,
UCANRUN_ENABLE_EXEC=1, UCANRUN_LANG=vi|en, UCANRUN_UNLOCK_FILE, UCANRUN_DATA, UCANRUN_WEB_ADDR, UCANRUN_AGENT_ADDR,
UCANRUN_APPROVAL_TTL, UCANRUN_URL, UCANRUN_TOKEN
";

type Res = Result<(), String>;

fn env(k: &str, d: &str) -> String {
    match std::env::var(k) {
        Ok(v) if !v.is_empty() => v,
        _ => d.to_string(),
    }
}

fn data_dir() -> PathBuf {
    match std::env::var("UCANRUN_DATA") {
        Ok(d) if !d.is_empty() => PathBuf::from(d),
        _ => PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".local/share/ucanrun"),
    }
}

fn vault_at() -> vault::Vault {
    vault::Vault::new(data_dir().join("vault"))
}

fn log(level: &str, msg: &str, kv: &[(&str, &str)]) {
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

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print!("{USAGE}");
        std::process::exit(2);
    }
    let (cmd, rest) = (args[1].as_str(), &args[2..]);
    let res = match cmd {
        "serve" => runtime().block_on(serve()),
        "add" => add(rest),
        "list" => list(),
        "rm" => {
            if rest.len() != 1 {
                Err("usage: ucr rm NAME".into())
            } else {
                vault_at().delete(&rest[0]).map_err(|e| e.to_string())
            }
        }
        "health" => runtime().block_on(health()),
        "gate" => web::load_gate_token(&data_dir(), &env("UCANRUN_GATE_TOKEN", ""))
            .map(|(t, _)| println!("{t}"))
            .map_err(|e| e.to_string()),
        "audit-verify" => audit::verify(&data_dir().join("audit.jsonl"))
            .map(|n| println!("OK: {n} entries"))
            .map_err(|e| e.to_string()),
        "backup" => do_backup(rest),
        "restore" => do_restore(rest),
        "backup-check" => do_backup_check(rest),
        "profiles" => runtime().block_on(profiles()),
        "run" => run(rest),
        "doctor" => runtime().block_on(doctor()),
        "mcp" => match Client::from_env() {
            Ok(c) => runtime().block_on(mcp::serve(c)).map_err(|e| e.to_string()),
            Err(e) => Err(e),
        },
        "version" | "--version" => {
            println!("ucr {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "help" | "-h" | "--help" => {
            print!("{USAGE}");
            Ok(())
        }
        _ => {
            print!("{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(e) = res {
        eprintln!("ucr: {e}");
        std::process::exit(1);
    }
}

/// Go's time.ParseDuration, without negative values.
fn parse_duration(s: &str) -> Result<Duration, String> {
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
fn port_of(addr: &str) -> Result<String, String> {
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
fn public_url() -> Result<String, String> {
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
fn harden() {
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

fn unlock_from_file(c: &Core, path: &str) -> Result<(), String> {
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

async fn shutdown_signal() {
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

async fn serve() -> Res {
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

async fn serve_core(c: &Arc<Core>, dir: &Path) -> Res {
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
async fn health() -> Res {
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

/// Reads one line from the terminal without echo.
fn read_hidden() -> std::io::Result<Zeroizing<String>> {
    // SAFETY: termios calls on stdin with a struct that tcgetattr fills in.
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut old) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut quiet = old;
    quiet.c_lflag &= !libc::ECHO;
    quiet.c_lflag |= libc::ICANON | libc::ISIG;
    quiet.c_iflag |= libc::ICRNL;
    // SAFETY: as above.
    if unsafe { libc::tcsetattr(0, libc::TCSANOW, &quiet) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut line = Zeroizing::new(String::new());
    let r = std::io::stdin().lock().read_line(&mut line);
    // SAFETY: restores the settings read above.
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &old) };
    r?;
    Ok(line)
}

fn add(args: &[String]) -> Res {
    if args.len() != 1 {
        return Err("usage: ucr add NAME".into());
    }
    if args[0].starts_with('_') {
        return Err(vault::Error::InvalidName.to_string());
    }
    let line = if std::io::stdin().is_terminal() {
        eprint!("Value (hidden): ");
        let r = read_hidden();
        eprintln!();
        r.map_err(|e| e.to_string())?
    } else {
        let mut line = Zeroizing::new(String::new());
        let n = std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("EOF".into());
        }
        line
    };
    let val = line.trim_end_matches(['\r', '\n']);
    vault_at()
        .put(&args[0], val.as_bytes())
        .map_err(|e| e.to_string())
}

fn list() -> Res {
    let l = vault_at().list().map_err(|e| e.to_string())?;
    let fmt = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    for m in l {
        let t = time::OffsetDateTime::from(m.updated);
        println!("{}\t{}", m.name, t.format(&fmt).unwrap_or_default());
    }
    Ok(())
}

/// Two-space indented JSON with Go's HTML escaping, like json.Encoder.
fn print_json(v: &Value) {
    let s = serde_json::to_string_pretty(v).unwrap_or_default();
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    println!("{out}");
}

async fn profiles() -> Res {
    let c = Client::from_env()?;
    print_json(&c.profiles().await?);
    Ok(())
}

fn run(args: &[String]) -> Res {
    if args.is_empty() {
        return Err("usage: ucr run PROFILE [k=v...] [--reason text]".into());
    }
    let profile = &args[0];
    let mut params = BTreeMap::new();
    let mut reason = String::new();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--reason" && i + 1 < args.len() {
            reason = args[i + 1].clone();
            i += 2;
            continue;
        }
        let Some((k, v)) = args[i].split_once('=') else {
            return Err(format!(
                "param {} must be k=v",
                policy::gourl::quote(&args[i])
            ));
        };
        params.insert(k.to_string(), v.to_string());
        i += 1;
    }
    let c = Client::from_env()?;
    let r = runtime().block_on(c.run(profile, serde_json::json!(params), &reason, 110))?;
    print_json(&r);
    if r.get("state").and_then(Value::as_str) != Some("done") {
        std::process::exit(1);
    }
    Ok(())
}

fn do_backup(args: &[String]) -> Res {
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

fn do_restore(args: &[String]) -> Res {
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

fn do_backup_check(args: &[String]) -> Res {
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

async fn doctor() -> Res {
    let c = Client::from_env().unwrap_or_else(|_| Client::new(&env("UCANRUN_URL", ""), ""));
    let mut failed = false;
    for ch in c.doctor().await {
        if !ch.ok {
            println!("FAIL {}: {}", ch.name, ch.detail);
            failed = true;
        } else if ch.detail.is_empty() {
            println!("OK  {}", ch.name);
        } else {
            println!("OK  {}: {}", ch.name, ch.detail);
        }
    }
    if failed {
        std::process::exit(1);
    }
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
