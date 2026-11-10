"""Drives the ucanrun lab: real server, real runners, a machine in the middle.

Run from the host: python3 lab.py. Prints one line per check and exits 1 if
any check fails.
"""
import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
WEB, AGENT, CTL = "http://127.0.0.1:28780", "http://127.0.0.1:28781", "http://127.0.0.1:29001"
PASS = "correct horse battery staple"
SUDO_PW = "lab-sudo-PASS-7319"
API_SECRET = "api-VALUE-55aa-9c1e"
results = []
cookie = ""


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def sh(*args, check_rc=True, timeout=120):
    r = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"{args}: {r.stdout}{r.stderr}")
    return r


def dx(svc, cmd, user=None, check_rc=True, detach=False):
    a = ["docker", "exec"] + (["-d"] if detach else []) + (["-u", user] if user else []) + [f"ucr-lab-{svc}-1", "sh", "-c", cmd]
    return sh(*a, check_rc=check_rc)


def http(method, url, body=None, headers=None, raw=False):
    global cookie
    h = {"content-type": "application/json", "X-Ucanrun": "1"}
    if cookie and url.startswith(WEB):
        h["cookie"] = cookie
    h.update(headers or {})
    data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=130) as r:
            sc = r.headers.get("set-cookie")
            if sc:
                cookie = sc.split(";")[0]
            out = r.read()
            return r.status, (out if raw else (json.loads(out) if out else None))
    except urllib.error.HTTPError as e:
        out = e.read()
        try:
            return e.code, json.loads(out)
        except Exception:
            return e.code, out


def mode(**m):
    http("POST", CTL, m)


def traffic():
    with open(os.path.join(HERE, "out", "traffic.jsonl")) as f:
        return [json.loads(l) for l in f if l.strip()]


def wait_req(token, rid, want=("done", "failed", "denied", "expired"), secs=60):
    end = time.time() + secs
    while time.time() < end:
        _, r = http("GET", f"{AGENT}/v1/requests/{rid}", headers={"authorization": "Bearer " + token})
        if r.get("state") in want:
            return r
        time.sleep(1)
    return r


def call(token, call, wait=30):
    return http("POST", f"{AGENT}/v1/requests", {"call": call, "reason": "lab", "wait_sec": wait},
                headers={"authorization": "Bearer " + token})


def runner_log(svc):
    return dx(svc, "cat /home/r/.config/ucanrun/runner.log 2>/dev/null || true").stdout


def start_runner(svc):
    dx(svc, "pkill -f 'ucr runner serve' || true", check_rc=False)
    time.sleep(0.5)
    dx(svc, "su r -s /bin/sh -c 'ucr runner serve >> /home/r/serve.log 2>&1'", detach=True)


def main():
    # --- lab up ---
    sh("docker", "compose", "-f", f"{HERE}/compose.yml", "down", "-v", check_rc=False)
    open(os.path.join(HERE, "out", "traffic.jsonl"), "w").close()
    sh("docker", "compose", "-f", f"{HERE}/compose.yml", "up", "-d")
    for _ in range(60):
        logs = sh("docker", "logs", "ucr-lab-server-1", check_rc=False).stdout
        m = re.search(r"Setup token: ([0-9a-f]+)", logs)
        if m:
            break
        time.sleep(0.5)
    st, _ = http("POST", f"{WEB}/api/setup", {"setup_token": m.group(1), "passphrase": PASS})
    if not cookie:
        http("POST", f"{WEB}/api/login", {"passphrase": PASS})
    http("PUT", f"{WEB}/api/secrets/pw", {"value": SUDO_PW, "description": "sudo of r", "allow_commands": True, "totp": "never"})
    http("PUT", f"{WEB}/api/secrets/api", {"value": API_SECRET, "description": "api", "allow_commands": True, "totp": "never", "approve": "auto"})
    _, t = http("POST", f"{WEB}/api/tokens", {"name": "lab-agent", "profiles": [], "workspaces": []})
    token = t["token"]
    for svc in ("runner1", "runner2"):
        dx(svc, "sh /w/setup.sh")
    print("lab up: server, mitm, runner1, runner2", flush=True)

    # --- pairing ---
    _, c = http("POST", f"{WEB}/api/runners/code")
    code = c["code"]
    r = dx("runner1", f"su r -s /bin/sh -c 'ucr runner enroll http://mitm:9000 {code} --name lab1'", check_rc=False)
    check("enroll through the middle machine works", r.returncode == 0, r.stdout.strip().splitlines()[0] if r.stdout else r.stderr)
    enroll_wire = [x for x in traffic() if x["path"] == "/v1/runner/enroll"]
    norm = code.replace("-", "")
    check("the pairing code never crosses the wire", enroll_wire and all(code not in x["req"] + x["resp"] and norm not in x["req"] + x["resp"] for x in enroll_wire))

    _, c2 = http("POST", f"{WEB}/api/runners/code")
    mode(swap_enroll=True)
    r = dx("runner2", f"su r -s /bin/sh -c 'ucr runner enroll http://mitm:9000 {c2['code']} --name lab2'", check_rc=False)
    saved = dx("runner2", "test -f /home/r/.config/ucanrun/runner.json && echo yes || echo no").stdout.strip()
    check("a swapped server key during pairing is caught", r.returncode != 0 and "could not prove" in r.stderr and saved == "no", r.stderr.strip()[:90])

    dx("runner1", "printf 'allow = [\"/usr/bin/id\", \"/bin/cat\"]\\nsudo = true\\nrequire_totp = false\\n' > /home/r/.config/ucanrun/runner.toml")
    start_runner("runner1")
    time.sleep(2)

    # --- jobs ---
    _, a = call(token, {"runner": "lab1", "exec": {"argv": ["/bin/cat"], "stdin": "{{secret:api}}"}})
    check("auto job runs on the runner and the secret is redacted", a.get("state") == "done" and "[REDACTED]" in a["result"]["output"] and API_SECRET not in a["result"]["output"], json.dumps(a.get("result"))[:80])

    _, b = call(token, {"runner": "lab1", "exec": {"argv": ["/usr/bin/id", "-u"], "sudo": "{{secret:pw}}"}}, wait=0)
    check("a sudo job waits for a person even with a no-TOTP secret", b.get("state") == "pending", b.get("state"))
    st, _ = http("POST", f"{WEB}/api/requests/{b['id']}/decide", {"approve": True, "hash": b["hash"], "totp": "", "secret": ""})
    b2 = wait_req(token, b["id"])
    check("approved sudo job runs as root on the runner", b2.get("state") == "done" and b2["result"]["output"].strip() == "0", json.dumps(b2.get("result"))[:80])

    _, d = call(token, {"runner": "lab1", "exec": {"argv": ["/usr/bin/whoami"], "env": {"K": "{{secret:api}}"}}})
    check("a program outside runner.toml is refused by the runner", d.get("state") == "failed" and "not in the allow list" in d["result"]["output"], d["result"]["output"][:80])

    # --- what the middle machine saw ---
    wire = traffic()
    blob = json.dumps(wire)
    leaks = [s for s in [SUDO_PW, API_SECRET, base64.b64encode(SUDO_PW.encode()).decode(), base64.b64encode(API_SECRET.encode()).decode(),
                         "/usr/bin/id", "/bin/cat", "/usr/bin/whoami", "uid=", "not in the allow list", a["id"], b["id"], b["hash"], token, "Bearer", "ucr_r_"] if s in blob]
    check("the middle machine reads no secret, command, output, id or token", not leaks, ", ".join(leaks))

    # --- replays and forgeries against the server ---
    polls = [x for x in wire if x["path"] == "/v1/runner/poll" and x["status"] == 200]
    p = polls[0]
    st, _ = http("POST", f"{AGENT}/v1/runner/poll", p["req"].encode(), {k: v for k, v in p["req_headers"].items() if k.lower().startswith("x-ucanrun")})
    check("a replayed poll is rejected", st == 401, f"HTTP {st}")
    res = [x for x in wire if x["path"] == "/v1/runner/result"][0]
    st, _ = http("POST", f"{AGENT}/v1/runner/result", res["req"].encode(), {k: v for k, v in res["req_headers"].items() if k.lower().startswith("x-ucanrun")})
    check("a replayed result is rejected", st == 401, f"HTTP {st}")
    hdr = {k: v for k, v in p["req_headers"].items() if k.lower().startswith("x-ucanrun")}
    hdr = {k: (str(int(time.time())) if k.lower() == "x-ucanrun-date" else ("0" * 32 if k.lower() == "x-ucanrun-nonce" else v)) for k, v in hdr.items()}
    st, _ = http("POST", f"{AGENT}/v1/runner/poll", p["req"].encode(), hdr)
    check("a poll with a fresh date but the old signature is rejected", st == 401, f"HTTP {st}")
    hdr2 = {("X-Ucanrun-Runner" if k.lower() == "x-ucanrun-runner" else k): ("nobody" if k.lower() == "x-ucanrun-runner" else v) for k, v in hdr.items()}
    st, _ = http("POST", f"{AGENT}/v1/runner/poll", b"{}", hdr2)
    check("a poll from an unknown runner is rejected", st == 403, f"HTTP {st}")
    st, _ = http("POST", f"{AGENT}/v1/runner/poll", b"{}", {"authorization": "Bearer " + token})
    check("an agent token cannot poll for jobs", st in (401, 403), f"HTTP {st}")

    # --- attacks against the runner ---
    mode(tamper_job=True)
    _, e = call(token, {"runner": "lab1", "exec": {"argv": ["/bin/cat"], "stdin": "{{secret:api}}"}}, wait=8)
    log = runner_log("runner1")
    check("a job changed on the way is not run", e.get("state") == "running" and "bad_signature" in log, e.get("state"))

    job_env = None
    for x in traffic():
        if x["path"] == "/v1/runner/poll" and '"payload"' in x["resp"]:
            job_env = json.loads(x["resp"])["jobs"][0]
            break
    start_runner("runner1")  # a restart must not forget the jobs it has run
    time.sleep(2)
    before = runner_log("runner1").count('"event":"ran"')
    # The injected answer goes out when a poll returns; the old process's
    # poll may take it, so offer it again until the new runner gets it.
    for _ in range(3):
        mode(inject=job_env)
        for _ in range(30):
            log = runner_log("runner1")
            if "already received" in log:
                break
            time.sleep(1)
        if "already received" in log:
            break
    check("a captured job replayed after a runner restart is ignored", "already received" in log and log.count('"event":"ran"') == before)

    # --- signed install commands ---
    ucr = os.path.join(HERE, "ucr")
    dl = os.path.join(HERE, "dl")
    sh("cp", ucr, os.path.join(dl, "ucr-linux-arm64"))
    digest = sh("sha256sum", os.path.join(dl, "ucr-linux-arm64")).stdout.split()[0]
    with open(os.path.join(dl, "SHA256SUMS"), "w") as f:
        f.write(f"{digest}  ucr-linux-arm64\n")
    cmd = sh("node", "-e", NODE_CMD, os.path.join(HERE, "app.js")).stdout.strip()
    r = dx("runner2", f"su r -s /bin/sh -c '{cmd} && ~/.local/bin/ucr --version'", check_rc=False)
    check("the install command checks the download and installs", r.returncode == 0 and "ucr 0.9" in r.stdout, (r.stdout + r.stderr).strip()[-80:])
    with open(os.path.join(dl, "ucr-linux-arm64"), "ab") as f:
        f.write(b"tampered")
    dx("runner2", "rm -f /home/r/.local/bin/ucr")
    r = dx("runner2", f"su r -s /bin/sh -c '{cmd}'", check_rc=False)
    gone = dx("runner2", "test -f /home/r/.local/bin/ucr && echo yes || echo no").stdout.strip()
    check("a tampered download is refused and not installed", r.returncode != 0 and gone == "no", (r.stdout + r.stderr).strip()[-80:])

    # --- the vault locks: runners get nothing ---
    http("POST", f"{WEB}/api/lock")
    st, _ = http("POST", f"{AGENT}/v1/runner/poll", b"{}", hdr)
    check("with the vault locked, runner requests get 423", st == 423, f"HTTP {st}")

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed", flush=True)
    return 1 if failed else 0


# Prints the Linux install command the web UI shows, from app.js itself.
NODE_CMD = r"""
const src = require("fs").readFileSync(process.argv[1], "utf8");
const m = src.slice(src.indexOf("function fetchCmd"), src.indexOf("function copyLine"));
const WIN_UCR = "";
eval(m);
console.log(installCmd("http://mitm:9000/dl", "linux-arm64"));
"""

if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        if os.environ.get("KEEP") != "1":
            sh("docker", "compose", "-f", f"{HERE}/compose.yml", "down", "-v", check_rc=False)
