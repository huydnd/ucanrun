"""A machine in the middle between runners and the ucanrun agent API.

It forwards every request to the server and records both directions to
/out/traffic.jsonl. Its control port switches on attacks:

  {"tamper_job": true}      flip a byte inside the next job it forwards
  {"inject": <envelope>}    answer the next poll with this job instead
  {"swap_enroll": true}     replace the server key in the next enroll answer
  {"drop_jobs": true}       swallow the jobs of the next poll

It also serves /dl/<file> from /dl, as a stand-in release server.
"""
import base64
import json
import os
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ.get("UPSTREAM", "http://server:8781")
LOG = "/out/traffic.jsonl"
mode = {}
lock = threading.Lock()


def record(entry):
    with lock:
        with open(LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/dl/"):
            p = os.path.join("/dl", os.path.basename(self.path))
            if os.path.isfile(p):
                return self._send(200, open(p, "rb").read(), "application/octet-stream")
            return self._send(404, b"")
        self.forward(b"")

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        self.forward(self.rfile.read(n))

    def forward(self, body):
        hdrs = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length", "connection")}
        req = urllib.request.Request(UPSTREAM + self.path, data=body if self.command == "POST" else None,
                                     headers=hdrs, method=self.command)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                code, out = r.status, r.read()
        except urllib.error.HTTPError as e:
            code, out = e.code, e.read()
        except Exception as e:  # upstream down
            code, out = 502, str(e).encode()
        out = self.attack(out)
        record({"path": self.path, "req_headers": hdrs, "req": body.decode("utf-8", "replace"),
                "status": code, "resp": out.decode("utf-8", "replace")})
        self._send(code, out)

    def attack(self, out):
        with lock:
            m = dict(mode)
            mode.clear()
            mode.update({k: v for k, v in m.items() if k not in self.used(m, out)})
        return self.apply(m, out)

    def used(self, m, out):
        """Attacks consumed by this response."""
        done = set()
        if self.path == "/v1/runner/poll":
            has_job = b'"payload"' in out
            if "inject" in m:
                done.add("inject")
            if m.get("tamper_job") and has_job:
                done.add("tamper_job")
            if m.get("drop_jobs") and has_job:
                done.add("drop_jobs")
        if self.path == "/v1/runner/enroll" and m.get("swap_enroll"):
            done.add("swap_enroll")
        return done

    def apply(self, m, out):
        try:
            if self.path == "/v1/runner/poll":
                if "inject" in m:
                    return json.dumps({"jobs": [m["inject"]]}).encode()
                v = json.loads(out)
                if v.get("jobs") and m.get("drop_jobs"):
                    return json.dumps({"jobs": []}).encode()
                if v.get("jobs") and m.get("tamper_job"):
                    env = v["jobs"][0]
                    job = json.loads(env["payload"])
                    raw = bytearray(base64.b64decode(job["sealed"]))
                    raw[len(raw) // 2] ^= 1
                    job["sealed"] = base64.b64encode(bytes(raw)).decode()
                    env["payload"] = json.dumps(job, separators=(",", ":"))
                    return json.dumps(v).encode()
            if self.path == "/v1/runner/enroll" and m.get("swap_enroll"):
                v = json.loads(out)
                if "server_key" in v:
                    v["server_key"] = base64.b64encode(os.urandom(32)).decode()
                    return json.dumps(v).encode()
        except Exception:
            pass
        return out


class Control(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        with lock:
            mode.update(json.loads(self.rfile.read(n) or b"{}"))
        self.send_response(204)
        self.end_headers()


if __name__ == "__main__":
    open(LOG, "w").close()
    threading.Thread(target=ThreadingHTTPServer(("0.0.0.0", 9001), Control).serve_forever, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 9000), Proxy).serve_forever()
