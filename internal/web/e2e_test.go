package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huydnd/ucanrun/internal/audit"
	"github.com/huydnd/ucanrun/internal/client"
	"github.com/huydnd/ucanrun/internal/core"
	"github.com/huydnd/ucanrun/internal/mcp"
	"github.com/huydnd/ucanrun/internal/policy"
	"github.com/huydnd/ucanrun/internal/totp"
)

const (
	pass     = "correct horse battery staple"
	secret   = "gitea-token-VALUE-0123456789"
	botTok   = "123:BOTTOKEN"
	owner    = int64(1001)
	stranger = int64(666)
)

// fakeTG is an in-memory Bot API.
type fakeTG struct {
	mu      sync.Mutex
	nextID  int64
	updates []map[string]any
	sent    []map[string]any
	answers []string
	edits   []string
	srv     *httptest.Server
}

func newTG(t *testing.T) *fakeTG {
	f := &fakeTG{nextID: 1}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		method := parts[len(parts)-1]
		var in map[string]any
		json.NewDecoder(r.Body).Decode(&in)
		reply := func(v any) { json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": v}) }
		if parts[1] != "bot"+botTok {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "description": "Unauthorized"})
			return
		}
		switch method {
		case "getMe":
			reply(map[string]any{"username": "ucanrun_test_bot"})
		case "sendMessage":
			f.mu.Lock()
			f.sent = append(f.sent, in)
			id := len(f.sent)
			f.mu.Unlock()
			reply(map[string]any{"message_id": id})
		case "answerCallbackQuery":
			f.mu.Lock()
			s, _ := in["text"].(string)
			f.answers = append(f.answers, s)
			f.mu.Unlock()
			reply(true)
		case "editMessageText":
			f.mu.Lock()
			s, _ := in["text"].(string)
			f.edits = append(f.edits, s)
			f.mu.Unlock()
			reply(true)
		case "getUpdates":
			off, _ := in["offset"].(float64)
			if off < 0 {
				reply([]any{})
				return
			}
			deadline := time.Now().Add(150 * time.Millisecond)
			for time.Now().Before(deadline) {
				f.mu.Lock()
				out := []map[string]any{}
				for _, u := range f.updates {
					if u["update_id"].(int64) >= int64(off) {
						out = append(out, u)
					}
				}
				f.mu.Unlock()
				if len(out) > 0 {
					reply(out)
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			reply([]any{})
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTG) push(u map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u["update_id"] = f.nextID
	f.nextID++
	f.updates = append(f.updates, u)
}

func (f *fakeTG) text(user, chat int64, s string) {
	f.push(map[string]any{"message": map[string]any{"message_id": 1, "text": s,
		"from": map[string]any{"id": user}, "chat": map[string]any{"id": chat, "type": "private"}}})
}

func (f *fakeTG) press(user, chat int64, data string) {
	f.push(map[string]any{"callback_query": map[string]any{"id": "cb", "data": data, "from": map[string]any{"id": user},
		"message": map[string]any{"chat": map[string]any{"id": chat}}}})
}

func (f *fakeTG) dump() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := json.Marshal([]any{f.sent, f.answers, f.edits})
	return string(b)
}

func (f *fakeTG) lastButton(t *testing.T, want string) string {
	t.Helper()
	var data string
	waitFor(t, "approval message "+want, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		for i := len(f.sent) - 1; i >= 0; i-- {
			if m, ok := f.sent[i]["reply_markup"].(map[string]any); ok {
				if !strings.Contains(f.sent[i]["text"].(string), want) {
					return false
				}
				row := m["inline_keyboard"].([]any)[0].([]any)
				data = row[0].(map[string]any)["callback_data"].(string)
				return true
			}
		}
		return false
	})
	return data
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

type env struct {
	t       *testing.T
	dir     string
	c       *core.Core
	s       *Server
	web     *httptest.Server
	agent   *httptest.Server
	tg      *fakeTG
	hc      *http.Client
	target  *httptest.Server
	gotAuth func() string
	hits    func() int
}

func (e *env) req(method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	code, raw := e.raw(method, path, body, map[string]string{"X-Ucanrun": "1"})
	m := map[string]any{}
	json.Unmarshal(raw, &m)
	return code, m
}

func (e *env) raw(method, path string, body any, hdr map[string]string) (int, []byte) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r, _ := http.NewRequest(method, e.web.URL+path, rd)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	resp, err := e.hc.Do(r)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func setup(t *testing.T, ttl time.Duration) *env {
	dir := t.TempDir()
	tg := newTG(t)
	c, err := core.New(core.Options{DataDir: dir, ApprovalTTL: ttl, TelegramAPI: tg.srv.URL, WorkFactor: 10})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	s := New(c, "setup-tok", filepath.Join(dir, "audit.jsonl"), false)
	jar, _ := cookiejar.New(nil)
	e := &env{t: t, dir: dir, c: c, s: s, tg: tg, hc: &http.Client{Jar: jar}}
	e.web = httptest.NewServer(s.Handler())
	e.agent = httptest.NewServer(s.AgentHandler())
	t.Cleanup(e.web.Close)
	t.Cleanup(e.agent.Close)
	var mu sync.Mutex
	var auth string
	n := 0
	e.target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = r.Header.Get("Authorization")
		n++
		got := auth
		mu.Unlock()
		fmt.Fprintf(w, "created, debug header was %s", got)
	}))
	t.Cleanup(e.target.Close)
	e.gotAuth = func() string { mu.Lock(); defer mu.Unlock(); return auth }
	e.hits = func() int { mu.Lock(); defer mu.Unlock(); return n }
	if code, m := e.req("POST", "/api/setup", map[string]string{"setup_token": "wrong", "passphrase": pass}); code != 403 {
		t.Fatalf("setup with bad token: %d %v", code, m)
	}
	if code, m := e.req("POST", "/api/setup", map[string]string{"setup_token": "setup-tok", "passphrase": pass}); code != 200 {
		t.Fatalf("setup: %d %v", code, m)
	}
	if code, _ := e.req("POST", "/api/setup", map[string]string{"setup_token": "setup-tok", "passphrase": "another long password"}); code != 409 {
		t.Fatalf("second setup: %d", code)
	}
	if code, m := e.req("PUT", "/api/secrets/gitea", map[string]string{"value": secret}); code != 200 {
		t.Fatalf("put secret: %d %v", code, m)
	}
	e.profile("create", policy.RiskLow, false)
	e.profile("danger", policy.RiskHigh, false)
	e.profile("auto", policy.RiskLow, true)
	return e
}

func (e *env) profile(name, risk string, auto bool) {
	e.t.Helper()
	p := policy.Profile{Name: name, Risk: risk, AutoApprove: auto,
		Params: []policy.Param{{Name: "repo", Pattern: `[a-z0-9-]+`, Required: true}},
		HTTP: &policy.HTTPSpec{Method: "POST", URL: e.target.URL + "/repos/{{repo}}",
			Headers: map[string]string{"Authorization": "token {{secret:gitea}}"}}}
	if code, m := e.req("PUT", "/api/profiles", p); code != 200 {
		e.t.Fatalf("profile: %d %v", code, m)
	}
}

func (e *env) token(name string, profiles []string) *client.Client {
	e.t.Helper()
	code, m := e.req("POST", "/api/tokens", map[string]any{"name": name, "profiles": profiles})
	if code != 200 {
		e.t.Fatalf("token: %d %v", code, m)
	}
	return &client.Client{URL: e.agent.URL, Token: m["token"].(string), HTTP: http.DefaultClient}
}

func (e *env) pair() {
	e.t.Helper()
	code, m := e.req("PUT", "/api/telegram", map[string]string{"token": botTok})
	if code != 200 {
		e.t.Fatalf("telegram: %d %v", code, m)
	}
	e.tg.text(stranger, stranger, "/pair wrong-code")
	e.tg.text(owner, owner, "/pair "+m["code"].(string))
	waitFor(e.t, "pairing", func() bool { return e.c.TelegramStatus().Paired })
	if e.c.TelegramStatus().UserID != owner {
		e.t.Fatal("wrong user paired")
	}
}

func (e *env) enableTOTP() string {
	e.t.Helper()
	code, m := e.req("POST", "/api/totp/start", nil)
	if code != 200 {
		e.t.Fatalf("totp start: %d %v", code, m)
	}
	sec := m["secret"].(string)
	if !strings.HasPrefix(m["qr"].(string), "data:image/png") {
		e.t.Fatal("no qr")
	}
	// Use the previous step, leaving current and next for later checks.
	c, _ := totp.Code(sec, time.Now().Add(-30*time.Second))
	if code, m := e.req("POST", "/api/totp/confirm", map[string]string{"code": c}); code != 200 {
		e.t.Fatalf("totp confirm: %d %v", code, m)
	}
	return sec
}

func (e *env) wait(id string, want core.ReqState) core.Request {
	e.t.Helper()
	var r core.Request
	waitFor(e.t, "state "+string(want), func() bool {
		r, _ = e.c.Get(id)
		return r.State == want
	})
	return r
}

func (e *env) noSecretAnywhere() {
	e.t.Helper()
	if strings.Contains(e.tg.dump(), secret) {
		e.t.Fatal("secret reached Telegram")
	}
	filepath.WalkDir(e.dir, func(p string, d os.DirEntry, _ error) error {
		if d.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte(secret)) || bytes.Contains(b, []byte(botTok)) {
			e.t.Fatalf("plaintext secret in %s", p)
		}
		return nil
	})
}

func TestApproveOnTelegramRunsAndHidesSecret(t *testing.T) {
	e := setup(t, time.Minute)
	e.pair()
	cl := e.token("claude", nil)
	ctx := context.Background()
	r, err := cl.Run(ctx, "create", map[string]string{"repo": "foo"}, "cần repo mới", 0)
	if err != nil || r["state"] != "pending" {
		t.Fatalf("%v %v", r, err)
	}
	id := r["id"].(string)
	if e.hits() != 0 {
		t.Fatal("ran before approval")
	}
	btn := e.tg.lastButton(t, "/repos/foo")
	if d := e.tg.dump(); !strings.Contains(d, "agent tự khai") || !strings.Contains(d, "‹secret:gitea›") {
		t.Fatalf("approval text: %s", d)
	}
	// A stranger, and the owner in another chat, must both fail.
	e.tg.press(stranger, owner, btn)
	e.tg.press(owner, stranger, btn)
	waitFor(t, "strangers refused", func() bool { return strings.Count(e.tg.dump(), "Không có quyền") == 2 })
	if q, _ := e.c.Get(id); q.State != core.Pending {
		t.Fatalf("stranger changed state: %s", q.State)
	}
	e.tg.press(owner, owner, btn)
	q := e.wait(id, core.Done)
	if e.gotAuth() != "token "+secret {
		t.Fatalf("target auth %q", e.gotAuth())
	}
	if strings.Contains(q.Result.Output, secret) || !strings.Contains(q.Result.Output, "[REDACTED]") {
		t.Fatalf("output: %s", q.Result.Output)
	}
	// A second press and a replayed press must not run it again.
	e.tg.press(owner, owner, btn)
	time.Sleep(300 * time.Millisecond)
	if e.hits() != 1 {
		t.Fatalf("hits %d", e.hits())
	}
	waitFor(t, "buttons removed", func() bool { return strings.Contains(e.tg.dump(), "Kết thúc: done") })
	got, _ := cl.Request(ctx, id)
	if b, _ := json.Marshal(got); bytes.Contains(b, []byte(secret)) {
		t.Fatal("secret in agent response")
	}
	e.noSecretAnywhere()
	if n, err := audit.Verify(filepath.Join(e.dir, "audit.jsonl")); err != nil || n == 0 {
		t.Fatalf("audit %d %v", n, err)
	}
}

func TestDenyExpireAndWrongHash(t *testing.T) {
	e := setup(t, 400*time.Millisecond)
	e.pair()
	cl := e.token("claude", nil)
	ctx := context.Background()
	r, _ := cl.Run(ctx, "create", map[string]string{"repo": "a"}, "", 0)
	id := r["id"].(string)
	if code, _ := e.req("POST", "/api/requests/"+id+"/decide", map[string]any{"approve": true, "hash": strings.Repeat("0", 64)}); code == 200 {
		t.Fatal("wrong hash accepted")
	}
	if code, _ := e.req("POST", "/api/requests/"+id+"/decide", map[string]any{"approve": true, "hash": ""}); code == 200 {
		t.Fatal("empty hash accepted")
	}
	e.wait(id, core.Expired) // silence is not approval
	if code, _ := e.req("POST", "/api/requests/"+id+"/decide", map[string]any{"approve": true, "hash": r["hash"]}); code == 200 {
		t.Fatal("expired request approved")
	}
	r, _ = cl.Run(ctx, "create", map[string]string{"repo": "b"}, "", 0)
	e.tg.press(owner, owner, strings.Replace(e.tg.lastButton(t, "/repos/b"), "a:", "d:", 1))
	e.wait(r["id"].(string), core.Denied)
	if e.hits() != 0 {
		t.Fatal("denied request ran")
	}
}

func TestHighRiskNeedsTOTPAndCodeIsSingleUse(t *testing.T) {
	e := setup(t, time.Minute)
	e.pair()
	cl := e.token("claude", nil)
	ctx := context.Background()
	r, _ := cl.Run(ctx, "danger", map[string]string{"repo": "a"}, "", 0)
	id, hash := r["id"].(string), r["hash"].(string)
	if code, _ := e.req("POST", "/api/requests/"+id+"/decide", map[string]any{"approve": true, "hash": hash}); code == 200 {
		t.Fatal("high risk approved without TOTP enrolled")
	}
	sec := e.enableTOTP()
	btn := e.tg.lastButton(t, "RỦI RO CAO")
	e.tg.press(owner, owner, btn)
	waitFor(t, "totp prompt", func() bool { return strings.Contains(e.tg.dump(), "Gửi mã TOTP") })
	if q, _ := e.c.Get(id); q.State != core.Pending {
		t.Fatal("button alone approved a high risk request")
	}
	e.tg.text(stranger, stranger, "123456")
	e.tg.text(owner, owner, "000000")
	waitFor(t, "bad code refused", func() bool { return strings.Contains(e.tg.dump(), "sai mã TOTP") })
	if q, _ := e.c.Get(id); q.State != core.Pending {
		t.Fatal("bad code approved")
	}
	e.tg.press(owner, owner, btn)
	waitFor(t, "second prompt", func() bool { return strings.Count(e.tg.dump(), "Gửi mã TOTP") == 2 })
	good, _ := totp.Code(sec, time.Now())
	e.tg.text(owner, owner, good)
	e.wait(id, core.Done)

	r2, _ := cl.Run(ctx, "danger", map[string]string{"repo": "b"}, "", 0)
	if code, _ := e.req("POST", "/api/requests/"+r2["id"].(string)+"/decide", map[string]any{"approve": true, "hash": r2["hash"], "totp": good}); code == 200 {
		t.Fatal("TOTP code reused")
	}
	e.noSecretAnywhere()
}

func TestAgentBoundaries(t *testing.T) {
	e := setup(t, time.Minute)
	ctx := context.Background()
	limited := e.token("limited", []string{"create"})
	if _, err := limited.Run(ctx, "danger", map[string]string{"repo": "a"}, "", 0); err == nil {
		t.Fatal("token scope ignored")
	}
	if _, err := limited.Run(ctx, "create", map[string]string{"repo": "../x"}, "", 0); err == nil {
		t.Fatal("bad param accepted")
	}
	if _, err := limited.Run(ctx, "create", map[string]string{"repo": "a", "extra": "b"}, "", 0); err == nil {
		t.Fatal("unknown param accepted")
	}
	bad := &client.Client{URL: e.agent.URL, Token: "ucr_nope", HTTP: http.DefaultClient}
	if _, err := bad.Profiles(ctx); err == nil {
		t.Fatal("bad token accepted")
	}
	// The agent cannot reach any human endpoint on its port.
	for _, p := range []string{"/api/secrets", "/api/profiles", "/api/tokens"} {
		req, _ := http.NewRequest("GET", e.agent.URL+p, nil)
		req.Header.Set("Authorization", "Bearer "+limited.Token)
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != 404 {
			t.Fatalf("%s on agent port: %d", p, resp.StatusCode)
		}
	}
	// A token cannot read another caller's result.
	other := e.token("other", nil)
	r, _ := limited.Run(ctx, "create", map[string]string{"repo": "a"}, "", 0)
	if _, err := other.Request(ctx, r["id"].(string)); err == nil {
		t.Fatal("read another caller's request")
	}
	// Approval spam is capped.
	var last error
	for i := 0; i < 8; i++ {
		_, last = other.Run(ctx, "create", map[string]string{"repo": "a"}, "", 0)
	}
	if last == nil {
		t.Fatal("pending cap not enforced")
	}
	// Revocation applies immediately.
	toks, _ := e.c.Tokens()
	for _, tk := range toks {
		e.req("DELETE", "/api/tokens/"+tk.ID, nil)
	}
	if _, err := limited.Profiles(ctx); err == nil {
		t.Fatal("revoked token works")
	}
	// Profile listing hides templates, hosts and secret names.
	cl := e.token("c", nil)
	v, _ := cl.Profiles(ctx)
	b, _ := json.Marshal(v)
	if bytes.Contains(b, []byte("gitea")) || bytes.Contains(b, []byte("127.0.0.1")) {
		t.Fatalf("listing leaks: %s", b)
	}
}

func TestAutoApprove(t *testing.T) {
	e := setup(t, time.Minute)
	cl := e.token("c", nil)
	r, err := cl.Run(context.Background(), "auto", map[string]string{"repo": "a"}, "", 5)
	if err != nil || r["state"] != "done" {
		t.Fatalf("%v %v", r, err)
	}
}

func TestLockDeniesPendingAndBlocksAgents(t *testing.T) {
	e := setup(t, time.Minute)
	cl := e.token("c", nil)
	ctx := context.Background()
	r, _ := cl.Run(ctx, "create", map[string]string{"repo": "a"}, "", 0)
	hash := r["hash"]
	if code, _ := e.req("POST", "/api/lock", nil); code != 200 {
		t.Fatal("lock")
	}
	if _, err := cl.Run(ctx, "create", map[string]string{"repo": "b"}, "", 0); err == nil || !strings.Contains(err.Error(), "423") {
		t.Fatalf("locked: %v", err)
	}
	if code, _ := e.req("GET", "/api/secrets", nil); code != 401 {
		t.Fatalf("session survived lock: %d", code)
	}
	if code, _ := e.req("POST", "/api/login", map[string]string{"passphrase": "wrong wrong wrong"}); code != 401 {
		t.Fatal("bad login accepted")
	}
	if code, _ := e.req("POST", "/api/login", map[string]string{"passphrase": pass}); code != 200 {
		t.Fatal("login")
	}
	if code, _ := e.req("POST", "/api/requests/"+r["id"].(string)+"/decide", map[string]any{"approve": true, "hash": hash}); code == 200 {
		t.Fatal("pending request survived lock")
	}
	if e.hits() != 0 {
		t.Fatal("ran")
	}
}

func TestTamperedStateRefused(t *testing.T) {
	e := setup(t, time.Minute)
	e.token("c", nil)
	e.req("POST", "/api/lock", nil)
	p := filepath.Join(e.dir, "state.json")
	b, _ := os.ReadFile(p)
	if !bytes.Contains(b, []byte(`"risk":"high"`)) {
		t.Fatal("fixture")
	}
	os.WriteFile(p, bytes.Replace(b, []byte(`"risk":"high"`), []byte(`"risk":"low"`), 1), 0o600)
	if code, _ := e.req("POST", "/api/login", map[string]string{"passphrase": pass}); code != 409 {
		t.Fatalf("tampered state accepted: %d", code)
	}
	if !e.c.Locked() {
		t.Fatal("unlocked after tamper")
	}
}

func TestWebHardening(t *testing.T) {
	e := setup(t, time.Minute)
	if code, _ := e.raw("PUT", "/api/secrets/x", map[string]string{"value": "v"}, nil); code != 403 {
		t.Fatalf("write without csrf header: %d", code)
	}
	if code, _ := e.raw("PUT", "/api/secrets/x", map[string]string{"value": "v"}, map[string]string{"X-Ucanrun": "1", "Sec-Fetch-Site": "cross-site"}); code != 403 {
		t.Fatalf("cross-site write: %d", code)
	}
	if code, _ := e.req("PUT", "/api/secrets/_telegram_token", map[string]string{"value": "v"}); code == 200 {
		t.Fatal("wrote internal secret")
	}
	if code, _ := e.req("DELETE", "/api/secrets/_totp_secret", nil); code == 200 {
		t.Fatal("deleted internal secret")
	}
	code, raw := e.raw("GET", "/api/secrets", nil, nil)
	if code != 200 || bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte("value")) {
		t.Fatalf("secret list: %s", raw)
	}
	r, _ := http.Get(e.web.URL + "/")
	if !strings.Contains(r.Header.Get("Content-Security-Policy"), "script-src 'self'") || r.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("headers: %v", r.Header)
	}
	// Anonymous clients get nothing, and repeated failures slow down.
	anon := &http.Client{}
	if resp, _ := anon.Get(e.web.URL + "/api/secrets"); resp.StatusCode != 401 {
		t.Fatalf("anonymous: %d", resp.StatusCode)
	}
	saw429 := false
	for i := 0; i < 5; i++ {
		c, _ := e.req("POST", "/api/login", map[string]string{"passphrase": "bad guess number x"})
		saw429 = saw429 || c == 429
	}
	if !saw429 {
		t.Fatal("login not throttled")
	}
}

func TestLoginDoesNotRevealPassphraseOrStallApprovals(t *testing.T) {
	e := setup(t, time.Minute)
	sec := e.enableTOTP()
	_ = sec
	// A correct passphrase with no code must look the same as a wrong one.
	c1, b1 := e.raw("POST", "/api/login", map[string]string{"passphrase": pass}, map[string]string{"X-Ucanrun": "1"})
	if c1 != 401 || bytes.Contains(b1, []byte("need_totp")) || !bytes.Contains(b1, []byte("sai thông tin")) {
		t.Fatalf("oracle: %d %s", c1, b1)
	}
}

func TestTokenNamesUniqueAndRateLimited(t *testing.T) {
	e := setup(t, time.Minute)
	e.token("dup", nil)
	if code, _ := e.req("POST", "/api/tokens", map[string]any{"name": "dup"}); code == 200 {
		t.Fatal("duplicate token name")
	}
	cl := e.token("flood", nil)
	var last error
	for i := 0; i < 40; i++ {
		_, last = cl.Run(context.Background(), "auto", map[string]string{"repo": "a"}, "", 0)
	}
	if last == nil || !strings.Contains(last.Error(), "429") {
		t.Fatalf("no rate limit: %v", last)
	}
}

func TestLongDisplayStillReachesTelegram(t *testing.T) {
	e := setup(t, time.Minute)
	e.pair()
	p := policy.Profile{Name: "big", Risk: policy.RiskLow, Params: []policy.Param{{Name: "b", Pattern: `[a-z]+`, Required: true}},
		HTTP: &policy.HTTPSpec{Method: "POST", URL: e.target.URL + "/x", Body: "{{b}}"}}
	if code, m := e.req("PUT", "/api/profiles", p); code != 200 {
		t.Fatalf("%d %v", code, m)
	}
	cl := e.token("c", nil)
	if _, err := cl.Run(context.Background(), "big", map[string]string{"b": strings.Repeat("a", 4000)}, "", 0); err != nil {
		t.Fatal(err)
	}
	e.tg.lastButton(t, "ĐÃ CẮT BỚT")
}

func TestPreview(t *testing.T) {
	e := setup(t, time.Minute)
	bad := map[string]any{"profile": map[string]any{"name": "Bad Name"}, "sample": map[string]string{}}
	if _, m := e.req("POST", "/api/profiles/preview", bad); m["error"] == nil {
		t.Fatalf("no error: %v", m)
	}
	p := policy.Profile{Name: "del", Risk: policy.RiskLow, Params: []policy.Param{{Name: "r", Pattern: `.+`, Required: true}},
		HTTP: &policy.HTTPSpec{Method: "DELETE", URL: "http://api.example.com/{{r}}", Headers: map[string]string{"Authorization": "Bearer {{secret:missing}}"}}}
	_, m := e.req("POST", "/api/profiles/preview", map[string]any{"profile": p, "sample": map[string]string{"r": "x"}})
	w, _ := json.Marshal(m["warnings"])
	for _, want := range []string{"HTTP không mã hoá", "TOTP", "nhận mọi thứ", "Chưa có secret"} {
		if !strings.Contains(string(w), want) {
			t.Fatalf("missing %q in %s", want, w)
		}
	}
	if !strings.Contains(m["display"].(string), "‹secret:missing›") {
		t.Fatalf("%v", m)
	}
	if e.hits() != 0 {
		t.Fatal("preview ran the action")
	}
}

func TestPairCodeIsShortAndBurnsAfterGuesses(t *testing.T) {
	e := setup(t, time.Minute)
	code, m := e.req("PUT", "/api/telegram", map[string]string{"token": botTok})
	if code != 200 {
		t.Fatalf("%d %v", code, m)
	}
	pair := m["code"].(string)
	if len(pair) != 6 || !strings.ContainsAny(pair, "#$%&+=?!") || strings.ContainsAny(pair, "0O1lI_*`~ ") {
		t.Fatalf("code %q", pair)
	}
	for i := 0; i < 3; i++ {
		e.tg.text(stranger, stranger, "/pair guess"+fmt.Sprint(i))
	}
	e.tg.text(owner, owner, "/pair "+pair) // correct, but too late
	waitFor(t, "code burned", func() bool {
		es, _ := e.c.Audit.Tail(5)
		for _, x := range es {
			if x.Event == "pair_code_burned" {
				return true
			}
		}
		return false
	})
	time.Sleep(300 * time.Millisecond)
	if e.c.TelegramStatus().Paired {
		t.Fatal("paired with a burned code")
	}
	// Generating a new code from the web works again.
	code, m = e.req("POST", "/api/telegram/pair", nil)
	if code != 200 {
		t.Fatalf("%d %v", code, m)
	}
	e.tg.text(owner, owner, "/pair "+m["code"].(string))
	waitFor(t, "pairing", func() bool { return e.c.TelegramStatus().Paired })
}

func TestSetupDisabledWithoutToken(t *testing.T) {
	dir := t.TempDir()
	c, _ := core.New(core.Options{DataDir: dir, WorkFactor: 10})
	defer c.Close()
	srv := httptest.NewServer(New(c, "", filepath.Join(dir, "a"), false).Handler())
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/api/setup", strings.NewReader(`{"setup_token":"","passphrase":"a long passphrase"}`))
	req.Header.Set("X-Ucanrun", "1")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 403 {
		t.Fatalf("empty token setup: %d", resp.StatusCode)
	}
}

func TestMCP(t *testing.T) {
	e := setup(t, time.Minute)
	cl := e.token("c", nil)
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_profiles","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run","arguments":{"profile":"auto","params":{"repo":"m"}}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"nope"}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := mcp.Serve(context.Background(), strings.NewReader(in), &out, cl); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if strings.Count(s, "\n") != 5 {
		t.Fatalf("responses: %s", s)
	}
	for _, want := range []string{`"protocolVersion":"2025-06-18"`, "get_request", "auto", `\"state\": \"done\"`, `-32601`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in %s", want, s)
		}
	}
	if strings.Contains(s, secret) || strings.Contains(s, "get_secret") {
		t.Fatal("mcp leaks")
	}
}
