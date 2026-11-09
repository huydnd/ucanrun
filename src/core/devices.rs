//! Where agents call from, and where ucanrun can run commands with which
//! rights. Built from the audit log and the profiles, so it shows what is
//! configured and what actually ran; nothing here is probed live.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

use super::{Core, Error, Result};
use crate::policy::Profile;

/// How far back the audit log is read.
const SCAN: usize = 5000;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AgentSeen {
    /// The token name: the agent's identity.
    pub token: String,
    /// Host name and software the agent's side reported, unverified.
    pub device: String,
    pub app: String,
    pub last_seen: String,
    pub requests: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Target {
    /// "ucanrun" for the server's own container, else the SSH host.
    pub host: String,
    pub user: String,
    /// "root" when commands go through sudo, else "user".
    pub rights: String,
    /// "profile NAME" or "agent".
    pub via: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_run: String,
    pub runs: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Devices {
    /// Enrolled runners and what each reports about itself.
    pub runners: Vec<super::RunnerView>,
    pub agents: Vec<AgentSeen>,
    pub targets: Vec<Target>,
    /// Whether the server runs commands at all.
    pub exec: bool,
    /// Secrets agents may put in commands they write.
    pub command_secrets: Vec<String>,
}

static QUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""((?:[^"\\]|\\.)*)""#).unwrap());

/// The SSH target and rights of a command, from its argv.
pub(crate) fn ssh_target(argv: &[String]) -> Option<(String, String, bool)> {
    let prog = argv.first()?;
    if !prog.rsplit('/').next().is_some_and(|b| b == "ssh") {
        return None;
    }
    // Options that take a value, so their value is not the destination.
    const WITH_VALUE: &[&str] = &[
        "-i", "-o", "-p", "-l", "-F", "-J", "-L", "-R", "-D", "-W", "-E", "-c", "-m", "-b",
    ];
    let mut i = 1;
    let mut login = String::new();
    while i < argv.len() {
        let a = &argv[i];
        if a == "-l" && i + 1 < argv.len() {
            login = argv[i + 1].clone();
        }
        if WITH_VALUE.contains(&a.as_str()) {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        let (user, host) = match a.split_once('@') {
            Some((u, h)) => (u.to_string(), h.to_string()),
            None => (login.clone(), a.clone()),
        };
        let rest = argv[i + 1..].join(" ");
        let root = user == "root" || rest.split_whitespace().any(|w| w == "sudo");
        return Some((host, user, root));
    }
    None
}

/// The runner a logged command went to, and whether it used sudo.
fn runner_of(display: &str) -> Option<(String, bool)> {
    let name = display.lines().find_map(|l| l.strip_prefix("runner: "))?;
    let sudo = display.lines().any(|l| l.starts_with("sudo: "));
    Some((name.to_string(), sudo))
}

/// argv back from the quoted command line the run log keeps.
fn argv_of(display: &str) -> Vec<String> {
    let first = display.lines().next().unwrap_or("");
    // An HTTP call shows "METHOD url"; only commands start with a quote.
    if !first.starts_with('"') {
        return Vec::new();
    }
    QUOTED
        .captures_iter(first)
        .map(|c| c[1].replace("\\\"", "\"").replace("\\\\", "\\"))
        .collect()
}

impl Core {
    pub fn devices(&self) -> Result<Devices> {
        let (profiles, tokens, meta) = {
            let g = self.inner();
            let st = g.st.as_ref().ok_or(Error::Locked)?;
            let profiles: Vec<Profile> = st
                .profiles
                .values()
                .map(|p| crate::policy::resolve(p, &st.connections).unwrap_or_else(|_| p.clone()))
                .collect();
            (
                profiles,
                st.tokens
                    .values()
                    .map(|t| t.name.clone())
                    .collect::<Vec<_>>(),
                st.secrets.clone(),
            )
        };
        let entries = self
            .audit
            .tail(SCAN)
            .map_err(|e| Error::Msg(e.to_string()))?;

        // Commands without SSH run as the server's own user.
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        let local = ("ucanrun".to_string(), format!("uid {uid}"), uid == 0);
        let runners = self.runners().unwrap_or_default();
        // The user a runner reported, for its row.
        let user_of = |n: &str| -> String {
            runners
                .iter()
                .find(|r| r.name == n)
                .and_then(|r| r.info.as_ref())
                .map(|i| i.user.clone())
                .unwrap_or_default()
        };
        let mut agents: BTreeMap<(String, String, String), AgentSeen> = BTreeMap::new();
        let mut targets: BTreeMap<(String, String), Target> = BTreeMap::new();
        let mut add =
            |host: String, user: String, root: bool, via: String, when: &str, ran: bool| {
                let t = targets
                    .entry((host.clone(), user.clone()))
                    .or_insert_with(|| Target {
                        host,
                        user,
                        rights: "user".into(),
                        ..Default::default()
                    });
                if root {
                    t.rights = "root".into();
                }
                if !t.via.contains(&via) {
                    t.via.push(via);
                }
                if ran {
                    t.runs += 1;
                    if t.last_run.is_empty() {
                        t.last_run = when.to_string();
                    }
                }
            };
        // Newest first, so the first time seen is the last one.
        for e in &entries {
            let f = &e.fields;
            let s = |k: &str| f.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            match e.event.as_str() {
                "request" => {
                    let k = (e.actor.clone(), s("device"), s("app"));
                    let a = agents.entry(k.clone()).or_insert_with(|| AgentSeen {
                        token: k.0,
                        device: k.1,
                        app: k.2,
                        last_seen: e.time.clone(),
                        requests: 0,
                    });
                    a.requests += 1;
                }
                "result" => {
                    let cmd = s("command");
                    let via = if s("profile") == crate::policy::ADHOC_PROFILE {
                        "agent".to_string()
                    } else {
                        format!("profile {}", s("profile"))
                    };
                    if let Some((n, sudo)) = runner_of(&cmd) {
                        let u = user_of(&n);
                        add(format!("runner {n}"), u, sudo, via, &e.time, true);
                        continue;
                    }
                    let argv = argv_of(&cmd);
                    if argv.is_empty() {
                        continue;
                    }
                    match ssh_target(&argv) {
                        Some((h, u, root)) => add(h, u, root, via, &e.time, true),
                        None => add(
                            local.0.clone(),
                            local.1.clone(),
                            local.2,
                            via,
                            &e.time,
                            true,
                        ),
                    }
                }
                _ => {}
            }
        }
        for p in &profiles {
            let Some(x) = &p.exec else { continue };
            let via = format!("profile {}", p.name);
            if !p.runner.is_empty() {
                let u = user_of(&p.runner);
                add(
                    format!("runner {}", p.runner),
                    u,
                    !x.sudo.is_empty(),
                    via,
                    "",
                    false,
                );
                continue;
            }
            match ssh_target(&x.argv) {
                Some((h, u, root)) => add(h, u, root, via, "", false),
                None => add(local.0.clone(), local.1.clone(), local.2, via, "", false),
            }
        }
        // Tokens that never called still belong in the list.
        for t in tokens {
            if !agents.keys().any(|k| k.0 == t) {
                agents.insert(
                    (t.clone(), String::new(), String::new()),
                    AgentSeen {
                        token: t,
                        ..Default::default()
                    },
                );
            }
        }
        let mut agents: Vec<AgentSeen> = agents.into_values().collect();
        agents.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.token.cmp(&b.token)));
        let mut command_secrets: Vec<String> = meta
            .iter()
            .filter(|(_, m)| m.allow_commands)
            .map(|(n, _)| n.clone())
            .collect();
        command_secrets.sort();
        Ok(Devices {
            runners,
            agents,
            targets: targets.into_values().collect(),
            exec: self.opt.allow_exec,
            command_secrets,
        })
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn reads_ssh_targets_and_rights() {
        let a = v(&[
            "/usr/bin/ssh",
            "-i",
            "id_key",
            "-o",
            "BatchMode=yes",
            "deploy@web1",
            "sudo -S -p '' /usr/bin/systemctl restart nginx",
        ]);
        assert_eq!(ssh_target(&a), Some(("web1".into(), "deploy".into(), true)));
        let a = v(&[
            "/usr/bin/ssh",
            "-l",
            "ops",
            "-p",
            "2222",
            "db.lan",
            "uptime",
        ]);
        assert_eq!(ssh_target(&a), Some(("db.lan".into(), "ops".into(), false)));
        let a = v(&["/usr/bin/ssh", "root@box", "ls"]);
        assert_eq!(ssh_target(&a), Some(("box".into(), "root".into(), true)));
        assert_eq!(ssh_target(&v(&["/usr/bin/psql", "-c", "select 1"])), None);
        assert_eq!(
            argv_of("\"/usr/bin/ssh\" \"-i\" \"id_key\" \"u@h\" \"sudo -S id\"\nstdin: ‹secret:x›"),
            v(&["/usr/bin/ssh", "-i", "id_key", "u@h", "sudo -S id"])
        );
        assert!(argv_of("POST https://a.example/x\n\n{\"a\": 1}").is_empty());
    }
}
