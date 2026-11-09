//! The server side of runners: enrolment, the job queue each runner polls,
//! and handing an approved command to its runner.
//!
//! A job leaves here signed with a key derived from the vault identity, and
//! its secrets sealed to the runner's own age key. The result comes back
//! signed by the runner and is checked against the key pinned at enrolment.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{Notify, oneshot};
use zeroize::Zeroizing;

use super::{Core, Error, Inner, Result, fields, pick, rand_hex, rfc3339_nano, unix};
use crate::policy::{self, Action, RunResult, gourl};
use crate::runner::proto::{
    self, EnrollIn, EnrollOut, Info, JOB_GRACE_SECS, Job, JobResult, ONLINE_SECS, POLL_WAIT_SECS,
    Signed, TOKEN_PREFIX, VERSION,
};
use crate::state::RunnerRec;

const CODE_TTL: Duration = Duration::from_secs(10 * 60);
const CODE_LETTERS: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const MAX_CODE_FAILS: u32 = 3;
const MAX_RUNNERS: usize = 50;
const MAX_QUEUE: usize = 20;

struct Live {
    seen: SystemTime,
    info: Info,
}

struct Waiter {
    runner: String,
    key: VerifyingKey,
    id: String,
    tx: oneshot::Sender<JobResult>,
}

/// Runner state that lives only in memory.
#[derive(Default)]
pub(super) struct Hub {
    live: HashMap<String, Live>,
    queue: HashMap<String, VecDeque<(String, Signed)>>,
    wait: HashMap<String, Waiter>,
    bell: HashMap<String, Arc<Notify>>,
    code: String,
    code_till: Option<SystemTime>,
    fails: u32,
}

/// A runner as the owner sees it.
#[derive(Debug, Clone, Serialize)]
pub struct RunnerView {
    pub name: String,
    pub created: String,
    pub fingerprint: String,
    pub online: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_seen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<Info>,
}

fn normalize_code(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn token_hash(t: &str) -> String {
    hex::encode(Sha256::digest(t.as_bytes()))
}

fn failed(msg: impl Into<String>) -> RunResult {
    RunResult {
        ok: false,
        exit: -1,
        output: msg.into(),
    }
}

impl Hub {
    fn online(&self, name: &str, now: SystemTime) -> bool {
        self.live.get(name).is_some_and(|l| {
            now.duration_since(l.seen)
                .map_or(true, |d| d < Duration::from_secs(ONLINE_SECS))
        })
    }
}

impl Core {
    fn signing_key(&self) -> Result<SigningKey> {
        let seed = self.vault.runner_seed()?;
        Ok(SigningKey::from_bytes(&seed))
    }

    /// The public key runners pin, base64.
    pub fn runner_server_key(&self) -> Result<String> {
        Ok(proto::public_b64(&self.signing_key()?))
    }

    /// A one-time code to enroll a runner, valid for ten minutes.
    pub fn new_runner_code(&self) -> Result<(String, String)> {
        let mut g = self.inner();
        if g.st.is_none() {
            return Err(Error::Locked);
        }
        let raw: String = (0..10).map(|_| pick(CODE_LETTERS) as char).collect();
        let till = self.now() + CODE_TTL;
        g.runners.code = raw.clone();
        g.runners.code_till = Some(till);
        g.runners.fails = 0;
        self.log("runner_code", "web", Value::Null);
        Ok((format!("{}-{}", &raw[..5], &raw[5..]), rfc3339_nano(till)))
    }

    /// Enrolls a runner with a code from the web UI.
    pub fn enroll_runner(&self, input: EnrollIn) -> Result<EnrollOut> {
        let mut g = self.inner();
        if g.st.is_none() {
            return Err(Error::Locked);
        }
        let now = self.now();
        let live = !g.runners.code.is_empty() && g.runners.code_till.is_some_and(|t| now < t);
        let given = normalize_code(&input.code);
        let ok = live && bool::from(given.as_bytes().ct_eq(g.runners.code.as_bytes()));
        if !ok {
            if live {
                g.runners.fails += 1;
                if g.runners.fails >= MAX_CODE_FAILS {
                    g.runners.code.clear();
                }
            }
            self.log(
                "runner_enroll_failed",
                "runner",
                json!({"name": input.name}),
            );
            return Err(Error::Msg(
                "the code is wrong or has expired; create a new one in the web UI".into(),
            ));
        }
        let name = input.name.trim().to_string();
        if !policy::name_ok(&name) {
            return Err(Error::Msg(
                "runner name must match [a-z0-9][a-z0-9_-]*".into(),
            ));
        }
        let st = g.st.as_ref().ok_or(Error::Locked)?;
        if st.runners.contains_key(&name) {
            return Err(Error::Msg(format!(
                "runner {} exists; remove it in the web UI first or pick another --name",
                gourl::quote(&name)
            )));
        }
        if st.runners.len() >= MAX_RUNNERS {
            return Err(Error::Msg(format!("at most {MAX_RUNNERS} runners")));
        }
        proto::verifying_key(&input.sign_key).map_err(Error::Msg)?;
        if !input.age_key.starts_with("age1")
            || proto::seal(&input.age_key, &BTreeMap::new()).is_err()
        {
            return Err(Error::Msg("bad age key".into()));
        }
        let server_key = self.runner_server_key()?;
        let token = format!("{TOKEN_PREFIX}{}", rand_hex(24));
        let rec = RunnerRec {
            name: name.clone(),
            sign_key: input.sign_key.clone(),
            age_key: input.age_key.clone(),
            token_hash: token_hash(&token),
            created: rfc3339_nano(now),
        };
        g.st.as_mut().unwrap().runners.insert(name.clone(), rec);
        g.runners.code.clear();
        self.save_locked(&mut g)?;
        g.runners.live.insert(
            name.clone(),
            Live {
                seen: now,
                info: input.info.cleaned(),
            },
        );
        self.log(
            "runner_enrolled",
            "runner",
            json!({"name": name, "key": proto::fingerprint(&input.sign_key)}),
        );
        Ok(EnrollOut {
            name,
            token,
            server_key,
        })
    }

    /// The runner a token belongs to. Polls do not count as activity, so a
    /// runner never keeps the vault from locking itself.
    pub fn runner_auth(&self, token: &str) -> Result<String> {
        if !token.starts_with(TOKEN_PREFIX) {
            return Err(Error::Forbidden);
        }
        let h = token_hash(token);
        let g = self.inner();
        let st = g.st.as_ref().ok_or(Error::Locked)?;
        st.runners
            .values()
            .find(|r| bool::from(r.token_hash.as_bytes().ct_eq(h.as_bytes())))
            .map(|r| r.name.clone())
            .ok_or(Error::Forbidden)
    }

    /// Holds a poll open until a job for this runner is queued, or for
    /// `POLL_WAIT_SECS`.
    pub async fn runner_poll(&self, name: &str, info: Info) -> Result<Vec<Signed>> {
        let info = info.cleaned();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(POLL_WAIT_SECS);
        let mut stop = self.shutdown.subscribe();
        loop {
            let bell = {
                let mut g = self.inner();
                if g.st.as_ref().is_none_or(|s| !s.runners.contains_key(name)) {
                    return Err(if g.st.is_none() {
                        Error::Locked
                    } else {
                        Error::Forbidden
                    });
                }
                let now = self.now();
                g.runners.live.insert(
                    name.to_string(),
                    Live {
                        seen: now,
                        info: info.clone(),
                    },
                );
                if let Some((_, j)) = g.runners.queue.get_mut(name).and_then(|q| q.pop_front()) {
                    return Ok(vec![j]);
                }
                g.runners.bell.entry(name.to_string()).or_default().clone()
            };
            tokio::select! {
                _ = bell.notified() => continue,
                _ = tokio::time::sleep_until(deadline) => return Ok(vec![]),
                _ = stop.wait_for(|v| *v) => return Ok(vec![]),
            }
        }
    }

    /// Takes a signed result from the runner that ran the job.
    pub fn runner_result(&self, name: &str, s: Signed) -> Result<()> {
        // Which job it claims to be, to find the key; then the signature.
        let claimed: JobResult =
            serde_json::from_str(&s.payload).map_err(|_| Error::Msg("bad result".into()))?;
        let mut g = self.inner();
        let Some(w) = g.runners.wait.get(&claimed.job) else {
            return Err(Error::NotFound);
        };
        if w.runner != name {
            return Err(Error::Forbidden);
        }
        let r: JobResult = s.open(&w.key).map_err(|e| {
            self.log("runner_bad_result", name, json!({"job": claimed.job}));
            Error::Msg(e)
        })?;
        if r.runner != name || r.id != w.id || r.v != VERSION {
            return Err(Error::Msg("the result does not match the job".into()));
        }
        let w = g.runners.wait.remove(&claimed.job).unwrap();
        let _ = w.tx.send(r);
        Ok(())
    }

    pub fn runners(&self) -> Result<Vec<RunnerView>> {
        let g = self.inner();
        let st = g.st.as_ref().ok_or(Error::Locked)?;
        let now = self.now();
        Ok(st
            .runners
            .values()
            .map(|r| {
                let l = g.runners.live.get(&r.name);
                RunnerView {
                    name: r.name.clone(),
                    created: r.created.clone(),
                    fingerprint: proto::fingerprint(&r.sign_key),
                    online: g.runners.online(&r.name, now),
                    last_seen: l.map(|l| rfc3339_nano(l.seen)).unwrap_or_default(),
                    info: l.map(|l| l.info.clone()),
                }
            })
            .collect())
    }

    /// What an agent may know about the runners: enough to pick one and
    /// write a command its rules allow.
    pub fn runners_for_agent(&self) -> Result<Vec<Value>> {
        Ok(self
            .runners()?
            .into_iter()
            .map(|r| {
                let i = r.info.unwrap_or_default();
                json!({"name": r.name, "online": r.online, "os": i.os, "user": i.user,
                       "sudo": i.sudo, "require_totp": i.require_totp, "allow": i.allow})
            })
            .collect())
    }

    pub fn delete_runner(&self, name: &str) -> Result<()> {
        let mut g = self.inner();
        let st = g.st.as_mut().ok_or(Error::Locked)?;
        if st.runners.remove(name).is_none() {
            return Err(Error::NotFound);
        }
        self.save_locked(&mut g)?;
        g.runners.live.remove(name);
        g.runners.queue.remove(name);
        g.runners.wait.retain(|_, w| w.runner != name);
        if let Some(b) = g.runners.bell.remove(name) {
            b.notify_waiters();
        }
        self.log("runner_removed", "web", json!({"name": name}));
        Ok(())
    }

    /// Refuses a request for a runner that is unknown or not connected, so
    /// nobody is asked to approve something that cannot run.
    pub(super) fn check_runner_locked(&self, g: &Inner, name: &str) -> Result<()> {
        if name.is_empty() {
            return Ok(());
        }
        let known = g.st.as_ref().is_some_and(|s| s.runners.contains_key(name));
        if !known {
            return Err(Error::Msg(format!(
                "unknown runner {}; ask the owner to enroll it (Overview, Devices and rights)",
                gourl::quote(name)
            )));
        }
        if !g.runners.online(name, self.now()) {
            return Err(Error::Msg(format!(
                "runner {} is offline; ask the owner to start ucr runner serve on it",
                gourl::quote(name)
            )));
        }
        Ok(())
    }

    /// Sends an approved command to its runner and waits for the result.
    pub(super) async fn run_on_runner(
        &self,
        id: &str,
        action: &Action,
        public: &BTreeSet<String>,
    ) -> RunResult {
        let name = action.runner.clone();
        let Some(exec) = action.exec.clone() else {
            return failed("a runner only runs commands");
        };
        let (rec, by, totp, hash) = {
            let g = self.inner();
            let Some(rec) = g.st.as_ref().and_then(|s| s.runners.get(&name)).cloned() else {
                return failed(format!("unknown runner {}", gourl::quote(&name)));
            };
            if !g.runners.online(&name, self.now()) {
                return failed(format!("runner {} is offline", gourl::quote(&name)));
            }
            let Some(e) = g.reqs.get(id) else {
                return failed("request gone");
            };
            (
                rec,
                e.req.decided_by.clone(),
                e.req.totp,
                e.req.hash.clone(),
            )
        };
        let Ok(key) = proto::verifying_key(&rec.sign_key) else {
            return failed("the runner's key is not valid");
        };
        let mut values = BTreeMap::new();
        for r in action.secrets() {
            match fields::resolve(&self.vault, &r) {
                Ok(v) => {
                    values.insert(r, Zeroizing::new(v));
                }
                Err(_) => return failed(format!("secret {} unavailable", gourl::quote(&r))),
            }
        }
        let sealed = match proto::seal(&rec.age_key, &values) {
            Ok(s) => s,
            Err(e) => return failed(format!("cannot seal the secrets: {e}")),
        };
        drop(values);
        let signer = match self.signing_key() {
            Ok(k) => k,
            Err(_) => return failed("vault locked"),
        };
        let timeout = if action.timeout_sec > 0 {
            action.timeout_sec
        } else {
            30
        };
        let nonce = rand_hex(16);
        let job = Job {
            v: VERSION,
            id: id.to_string(),
            job: nonce.clone(),
            runner: name.clone(),
            not_after: unix(self.now()) + timeout + JOB_GRACE_SECS,
            hash,
            approved_by: by,
            totp,
            exec,
            timeout_sec: timeout,
            public: public.iter().cloned().collect(),
            secrets: sealed,
        };
        let signed = Signed::new(&signer, &job);
        let (tx, rx) = oneshot::channel();
        {
            let mut g = self.inner();
            let q = g.runners.queue.entry(name.clone()).or_default();
            if q.len() >= MAX_QUEUE {
                return failed(format!(
                    "runner {} has too many queued jobs",
                    gourl::quote(&name)
                ));
            }
            q.push_back((nonce.clone(), signed));
            g.runners.wait.insert(
                nonce.clone(),
                Waiter {
                    runner: name.clone(),
                    key,
                    id: id.to_string(),
                    tx,
                },
            );
            g.runners.bell.entry(name.clone()).or_default().notify_one();
        }
        self.log(
            "runner_job",
            &name,
            json!({"id": id, "job": nonce, "runner": name}),
        );
        let limit = Duration::from_secs((timeout + JOB_GRACE_SECS + 5) as u64);
        let mut stop = self.shutdown.subscribe();
        let got = tokio::select! {
            r = tokio::time::timeout(limit, rx) => r.ok().and_then(|r| r.ok()),
            _ = stop.wait_for(|v| *v) => None,
        };
        let mut g = self.inner();
        g.runners.wait.remove(&nonce);
        if let Some(q) = g.runners.queue.get_mut(&name) {
            q.retain(|(n, _)| *n != nonce);
        }
        drop(g);
        match got {
            Some(r) => RunResult {
                ok: r.ok && !r.refused,
                exit: r.exit,
                output: r.output,
            },
            None => failed(format!(
                "runner {} did not answer in time",
                gourl::quote(&name)
            )),
        }
    }

    /// How long ago, in seconds, each runner last polled. For tests.
    #[cfg(test)]
    pub(crate) fn runner_seen_secs(&self, name: &str) -> Option<u64> {
        let g = self.inner();
        g.runners
            .live
            .get(name)
            .and_then(|l| self.now().duration_since(l.seen).ok())
            .map(|d| d.as_secs())
    }
}
