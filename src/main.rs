//! `ucr` is the ucanrun credential broker: agents ask for an action, a human
//! approves it, and the server runs it without showing the secret.
//!
//! The server commands need Unix; the agent commands also run on Windows.

use std::collections::BTreeMap;

use serde_json::Value;

use ucanrun::client::Client;
use ucanrun::{mcp, prompt, tokenstore};

#[cfg(unix)]
mod cli_server;

const USAGE: &str = "ucr: credential broker with human approval

Server, on the machine that holds the data directory (Linux, macOS):
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

Agent (Linux, macOS, Windows):
  ucr login [URL]           save the agent token (stdin, or a hidden prompt)
  ucr logout                forget the saved token
  ucr secrets               list secrets you may use (never their values)
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

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

#[cfg(unix)]
fn quote(s: &str) -> String {
    ucanrun::policy::gourl::quote(s)
}

#[cfg(not(unix))]
fn quote(s: &str) -> String {
    format!("{s:?}")
}

/// Server commands; None when `cmd` is not one of them.
#[cfg(unix)]
fn server_command(cmd: &str, rest: &[String]) -> Option<Res> {
    use cli_server as s;
    Some(match cmd {
        "serve" => runtime().block_on(s::serve()),
        "add" => s::add(rest),
        "list" => s::list(),
        "rm" => {
            if rest.len() != 1 {
                Err("usage: ucr rm NAME".into())
            } else {
                s::vault_at().delete(&rest[0]).map_err(|e| e.to_string())
            }
        }
        "health" => runtime().block_on(s::health()),
        "gate" => ucanrun::web::load_gate_token(&s::data_dir(), &env("UCANRUN_GATE_TOKEN", ""))
            .map(|(t, _)| println!("{t}"))
            .map_err(|e| e.to_string()),
        "audit-verify" => ucanrun::audit::verify(&s::data_dir().join("audit.jsonl"))
            .map(|n| println!("OK: {n} entries"))
            .map_err(|e| e.to_string()),
        "backup" => s::do_backup(rest),
        "restore" => s::do_restore(rest),
        "backup-check" => s::do_backup_check(rest),
        _ => return None,
    })
}

#[cfg(not(unix))]
fn server_command(cmd: &str, _rest: &[String]) -> Option<Res> {
    matches!(
        cmd,
        "serve"
            | "add"
            | "list"
            | "rm"
            | "health"
            | "gate"
            | "audit-verify"
            | "backup"
            | "restore"
            | "backup-check"
    )
    .then(|| {
        Err(format!(
            "{cmd} runs on the ucanrun server (Linux or macOS), not here"
        ))
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print!("{USAGE}");
        std::process::exit(2);
    }
    let (cmd, rest) = (args[1].as_str(), &args[2..]);
    let res = if let Some(r) = server_command(cmd, rest) {
        r
    } else {
        match cmd {
            "login" => login(rest),
            "logout" => logout(),
            "profiles" => runtime().block_on(profiles()),
            "secrets" => runtime().block_on(secrets()),
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
        }
    };
    if let Err(e) = res {
        eprintln!("ucr: {e}");
        std::process::exit(ucanrun::client::exit_code(&e));
    }
}

/// Saves the server URL and agent token, after checking the server takes it.
fn login(args: &[String]) -> Res {
    if args.len() > 1 {
        return Err("usage: ucr login [URL]".into());
    }
    let url = args
        .first()
        .cloned()
        .unwrap_or_else(|| env("UCANRUN_URL", "http://127.0.0.1:8781"))
        .trim_end_matches('/')
        .to_string();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("the URL must start with http:// or https://".into());
    }
    let token = prompt::read_secret("Agent token (hidden): ")?;
    if !token.starts_with("ucr_") {
        return Err("that is not an agent token: agent tokens start with ucr_".into());
    }
    let c = Client::new(&url, &token);
    runtime().block_on(c.profiles())?;
    let at = tokenstore::save(&tokenstore::Saved {
        url: url.clone(),
        token: token.to_string(),
    })?;
    eprintln!("Saved for {url} in {at}.");
    Ok(())
}

fn logout() -> Res {
    if let Some(at) = tokenstore::delete()? {
        eprintln!("Removed the saved token from {at}.");
    } else {
        eprintln!("No saved token.");
    }
    Ok(())
}

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

async fn secrets() -> Res {
    let c = Client::from_env()?;
    print_json(&c.secrets().await?);
    Ok(())
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
            return Err(format!("param {} must be k=v", quote(&args[i])));
        };
        params.insert(k.to_string(), v.to_string());
        i += 1;
    }
    let c = Client::from_env()?;
    let r = runtime().block_on(c.run(profile, serde_json::json!(params), &reason, 110))?;
    print_json(&r);
    // 77: the human said no; 75: nobody answered in time, or still waiting.
    match r.get("state").and_then(Value::as_str) {
        Some("done") => {}
        Some("denied") => std::process::exit(77),
        Some("expired" | "pending") => std::process::exit(75),
        _ => std::process::exit(1),
    }
    Ok(())
}

async fn doctor() -> Res {
    let c = Client::from_env().unwrap_or_else(|_| {
        let saved = tokenstore::load().unwrap_or_default();
        let url = if saved.url.is_empty() {
            env("UCANRUN_URL", "http://127.0.0.1:8781")
        } else {
            saved.url
        };
        Client::new(&url, "")
    });
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
