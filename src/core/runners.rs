//! The server side of runners: enrolment, the job queue each runner polls,
//! and handing an approved command to its runner.
//!
//! A job leaves here sealed to the runner's age key and signed with a key
//! derived from the vault identity. The result comes back sealed to the
//! vault's recipient and signed by the runner. Every runner request is signed
//! with the runner's own key, a timestamp and a single-use nonce.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::{Notify, oneshot};
use zeroize::Zeroizing;

use super::{Core, Error, Inner, Result, fields, pick, rand_hex, rfc3339_nano, unix};
use crate::policy::{self, Action, RunResult, gourl};
use crate::runner::proto::{
    self, EnrollIn, EnrollOut, Info, JOB_GRACE_SECS, Job, JobBody, JobResult, ONLINE_SECS,
    POLL_WAIT_SECS, REQUEST_SKEW_SECS, ResultBody, Signed, VERSION, Values,
};
use crate::state::RunnerRec;

const CODE_TTL: Duration = Duration::from_secs(10 * 60);
const CODE_LETTERS: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
/// 12 letters of 31: about 59 bits, far beyond what fits in ten minutes.
const CODE_LEN: usize = 12;
const MAX_CODE_FAILS: u32 = 3;
const MAX_RUNNERS: usize = 50;
const MAX_QUEUE: usize = 20;
/// Nonces of signed requests kept against replays; more than this many in
/// the skew window means something is flooding, and requests are refused.
const MAX_NONCES: usize = 20_000;
/// The error of a runner request whose signature, time or nonce is wrong.
const UNSIGNED: &str = "bad request signature";

pub fn unsigned() -> &'static str {
    UNSIGNED
}

struct Live {
    seen: SystemTime,
    info: Info,
}

struct Waiter {
    runner: String,
    key: VerifyingKey,
    id: String,
    tx: oneshot::Sender<ResultBody>,
}

/// Runner state that lives only in memory.
#[derive(Default)]
pub(super) struct Hub {
    live: HashMap<String, Live>,
    queue: HashMap<String, VecDeque<(String, Signed)>>,
    wait: HashMap<String, Waiter>,
    bell: HashMap<String, Arc<Notify>>,
    nonces: HashMap<String, i64>,
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

/// The headers of one signed runner request.
#[derive(Debug, Clone, Default)]
pub struct RunnerAuth {
    pub runner: String,
    pub date: String,
    pub nonce: String,
    pub sig: String,
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
    pub(super) fn signing_key_for_runners(&self) -> Result<SigningKey> {
        self.signing_key()
    }

    /// Whether the runner said it only takes jobs approved with a passkey.
    pub(super) fn runner_needs_passkey_locked(&self, g: &Inner, name: &str) -> bool {
        !name.is_empty()
            && g.runners
                .live
                .get(name)
                .is_some_and(|l| l.info.require_passkey)
    }

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
        let raw: String = (0..CODE_LEN).map(|_| pick(CODE_LETTERS) as char).collect();
        let till = self.now() + CODE_TTL;
        g.runners.code = raw.clone();
        g.runners.code_till = Some(till);
        g.runners.fails = 0;
        self.log("runner_code", "web", Value::Null);
        Ok((
            format!("{}-{}-{}", &raw[..4], &raw[4..8], &raw[8..]),
            rfc3339_nano(till),
        ))
    }

    /// Enrolls a runner that proves it knows the current code, and answers
    /// with a proof of the server's own keys under the same code.
    pub fn enroll_runner(&self, input: EnrollIn) -> Result<EnrollOut> {
        let mut g = self.inner();
        if g.st.is_none() {
            return Err(Error::Locked);
        }
        let now = self.now();
        let live = !g.runners.code.is_empty() && g.runners.code_till.is_some_and(|t| now < t);
        let code = g.runners.code.clone();
        if !live || input.v != VERSION || !input.proves(&code) {
            // Logged only while a code is open, so an unauthenticated caller
            // cannot grow the audit log; three tries close the code.
            if live {
                g.runners.fails += 1;
                if g.runners.fails >= MAX_CODE_FAILS {
                    g.runners.code.clear();
                }
                let name: String = input.name.chars().take(64).collect();
                self.log("runner_enroll_failed", "runner", json!({"name": name}));
            }
            return Err(Error::Msg(if input.v != VERSION {
                "this ucr is too old or too new for the server; use the same version".into()
            } else {
                "the code is wrong or has expired; create a new one in the web UI".into()
            }));
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
        if !input.age_key.starts_with("age1") || proto::seal(&input.age_key, &()).is_err() {
            return Err(Error::Msg("bad age key".into()));
        }
        let mut out = EnrollOut {
            name: name.clone(),
            server_key: self.runner_server_key()?,
            server_age: self.vault.recipient()?,
            ..Default::default()
        };
        out.proof = out.proof_for(&code, &input.sign_key);
        let rec = RunnerRec {
            name: name.clone(),
            sign_key: input.sign_key.clone(),
            age_key: input.age_key.clone(),
            token_hash: String::new(),
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
        Ok(out)
    }

    /// Checks a signed runner request and returns the runner's name. Polls
    /// do not count as activity, so a runner never keeps the vault open.
    pub fn runner_verify(
        &self,
        a: &RunnerAuth,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<String> {
        let mut g = self.inner();
        let st = g.st.as_ref().ok_or(Error::Locked)?;
        let Some(rec) = st.runners.get(&a.runner) else {
            return Err(Error::Forbidden);
        };
        let key = proto::verifying_key(&rec.sign_key).map_err(|_| Error::Forbidden)?;
        let date: i64 = a.date.parse().map_err(|_| Error::Msg(UNSIGNED.into()))?;
        let now = unix(self.now());
        if (now - date).abs() > REQUEST_SKEW_SECS || a.nonce.len() != 32 {
            return Err(Error::Msg(UNSIGNED.into()));
        }
        let msg = proto::request_message(method, path, date, &a.nonce, body);
        if proto::verify(&key, &msg, &a.sig).is_err() {
            return Err(Error::Msg(UNSIGNED.into()));
        }
        let n = &mut g.runners.nonces;
        n.retain(|_, t| *t >= now - REQUEST_SKEW_SECS);
        if n.len() >= MAX_NONCES {
            return Err(Error::Busy);
        }
        let k = format!("{}/{}", a.runner, a.nonce);
        if n.contains_key(&k) {
            self.log("runner_replay", &a.runner, json!({"path": path}));
            return Err(Error::Msg(UNSIGNED.into()));
        }
        n.insert(k, date);
        Ok(a.runner.clone())
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

    /// Takes a signed, sealed result from the runner that ran the job.
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
        if r.runner != name || r.v != VERSION {
            return Err(Error::Msg("the result does not match the job".into()));
        }
        let plain = self.vault.unseal_bytes(&r.sealed)?;
        let body: ResultBody =
            serde_json::from_slice(&plain).map_err(|_| Error::Msg("bad result".into()))?;
        if body.job != r.job || body.id != w.id {
            return Err(Error::Msg("the result does not match the job".into()));
        }
        let w = g.runners.wait.remove(&claimed.job).unwrap();
        let _ = w.tx.send(body);
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
                "unknown runner {}; ask the owner to enroll it on the Runner tab",
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

    /// Whether the runner said it only takes jobs approved with TOTP.
    pub(super) fn runner_needs_totp_locked(&self, g: &Inner, name: &str) -> bool {
        !name.is_empty()
            && g.runners
                .live
                .get(name)
                .is_some_and(|l| l.info.require_totp)
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
        let (rec, by, totp, hash, approval) = {
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
                e.proof.clone(),
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
        let body = JobBody {
            job: nonce.clone(),
            runner: name.clone(),
            id: id.to_string(),
            hash,
            approved_by: by,
            totp,
            exec,
            timeout_sec: timeout,
            public: public.iter().cloned().collect(),
            secrets: Values::from_bytes(&values),
            approval,
        };
        drop(values);
        let sealed = match proto::seal(&rec.age_key, &body) {
            Ok(s) => s,
            Err(e) => return failed(format!("cannot seal the job: {e}")),
        };
        drop(body);
        let job = Job {
            v: VERSION,
            runner: name.clone(),
            job: nonce.clone(),
            not_after: unix(self.now()) + timeout + JOB_GRACE_SECS,
            sealed,
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

    /// How long ago, in seconds, a runner last polled. For tests.
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
