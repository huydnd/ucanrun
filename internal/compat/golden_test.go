// Package compat writes fixtures that pin the Go behaviour the Rust port must
// match: a real data directory, and tables of policy results. Run with
// UCANRUN_WRITE_GOLDEN=<dir>.
package compat

import (
	"encoding/base32"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ucanrun/internal/audit"
	"ucanrun/internal/core"
	"ucanrun/internal/policy"
	"ucanrun/internal/totp"
)

const pass = "golden passphrase 123"

func write(t *testing.T, path string, v any) {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWriteGolden(t *testing.T) {
	out := os.Getenv("UCANRUN_WRITE_GOLDEN")
	if out == "" {
		t.Skip("set UCANRUN_WRITE_GOLDEN to write fixtures")
	}
	data := filepath.Join(out, "datadir")
	os.MkdirAll(data, 0o700)
	c, err := core.New(core.Options{DataDir: data, WorkFactor: 10, Lang: "vi"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Setup([]byte(pass)); err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{"github_token": "ghp_golden_value_123", "multi": "line one\nline two\n", "unicode": "mật-khẩu-✓"}
	for k, v := range secrets {
		if err := c.Vault.Put(k, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	c.SetSecretMeta("github_token", policy.SecretMeta{Description: "Token GitHub <cá nhân> & đọc repo", Hosts: []string{"api.github.com", "*.example.com"}})
	conn := policy.Connection{Name: "github", Title: "GitHub", BaseURL: "https://api.github.com", Auth: policy.Auth{Type: "bearer", Secret: "github_token"}, Headers: map[string]string{"Accept": "application/vnd.github+json"}}
	if err := c.PutConnection(conn); err != nil {
		t.Fatal(err)
	}
	if err := c.PutProfile(policy.Profile{Name: "github-whoami", Description: "Xem tài khoản", Risk: "low", Connection: "github", HTTP: &policy.HTTPSpec{Method: "GET", URL: "/user"}}); err != nil {
		t.Fatal(err)
	}
	tok, err := c.CreateToken("claude", nil)
	if err != nil {
		t.Fatal(err)
	}
	sec, _, _ := c.TOTPStart()
	code, _ := totp.Code(sec, time.Now().Add(-30*time.Second))
	recovery, err := c.TOTPConfirm(code)
	if err != nil {
		t.Fatal(err)
	}
	c.Audit.Append("golden_event", "tester <a&b>", map[string]any{"z": 1, "a": "x<y>&z", "nested": map[string]any{"k": []any{1, "two", true}}, "vi": "tiếng Việt", "unicode": "  line"})
	key, _ := c.Vault.MACKey()
	c.Lock("golden")
	c.Close()
	n, err := audit.Verify(filepath.Join(data, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(out, "expected.json"), map[string]any{
		"passphrase": pass, "secrets": secrets, "token": tok, "totp_secret": sec, "recovery_codes": recovery,
		"mac_key_hex": encodeHex(key), "audit_entries": n, "profiles": []string{"github-whoami"}, "connections": []string{"github"},
	})

	// TOTP vectors
	var vectors []map[string]any
	key32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, ts := range []int64{59, 1111111109, 1234567890, 2000000000, 1800000000} {
		code, _ := totp.Code(key32, time.Unix(ts, 0))
		vectors = append(vectors, map[string]any{"secret": key32, "unix": ts, "code": code})
	}
	write(t, filepath.Join(out, "totp.json"), vectors)

	write(t, filepath.Join(out, "policy.json"), policyCases())
}

func encodeHex(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2], out[i*2+1] = h[c>>4], h[c&15]
	}
	return string(out)
}

type result struct {
	OK      bool              `json:"ok"`
	Error   string            `json:"error,omitempty"`
	URL     string            `json:"url,omitempty"`
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	Argv    []string          `json:"argv,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Display string            `json:"display,omitempty"`
	Secrets []string          `json:"secrets,omitempty"`
	Risk    string            `json:"risk,omitempty"`
	Choices []string          `json:"choices,omitempty"`
}

func render(p policy.Profile, params map[string]string) result {
	if err := p.Validate(); err != nil {
		return result{Error: err.Error()}
	}
	a, err := p.Render(params)
	if err != nil {
		return result{Error: err.Error()}
	}
	r := result{OK: true, Display: a.Display(), Secrets: a.Secrets(), Risk: p.Risk, Choices: p.SecretChoices}
	if a.HTTP != nil {
		r.URL, r.Method, r.Headers, r.Body = a.HTTP.URL, a.HTTP.Method, a.HTTP.Headers, a.HTTP.Body
	}
	if a.Exec != nil {
		r.Argv, r.Env = a.Exec.Argv, a.Exec.Env
	}
	return r
}

func policyCases() map[string]any {
	str := func(s string) *string { return &s }
	_ = str
	type renderCase struct {
		Name    string            `json:"name"`
		Profile policy.Profile    `json:"profile"`
		Params  map[string]string `json:"params"`
		Want    result            `json:"want"`
	}
	base := func() policy.Profile {
		return policy.Profile{Name: "create-repo", Risk: "low",
			Params: []policy.Param{{Name: "name", Pattern: `[a-z0-9-]+`, Required: true}, {Name: "note", Pattern: `.*`}},
			HTTP: &policy.HTTPSpec{Method: "POST", URL: "https://git.example/api/repos/{{name}}",
				Headers: map[string]string{"Authorization": "token {{secret:gitea}}", "Content-Type": "application/json"},
				Body:    `{"note":"{{note}}"}`}}
	}
	var rc []renderCase
	add := func(name string, p policy.Profile, params map[string]string) {
		rc = append(rc, renderCase{Name: name, Profile: p, Params: params, Want: render(p, params)})
	}
	add("ok", base(), map[string]string{"name": "foo", "note": `x","admin":"true`})
	add("missing", base(), map[string]string{})
	add("bad pattern", base(), map[string]string{"name": "../admin"})
	add("unknown param", base(), map[string]string{"name": "a", "x": "y"})
	add("template in value", base(), map[string]string{"name": "a", "note": "{{secret:other}}"})
	add("bidi", base(), map[string]string{"name": "a", "note": "a‮b"})
	add("newline", base(), map[string]string{"name": "a", "note": "a\nb"})
	for n, mut := range map[string]func(*policy.Profile){
		"host template":   func(p *policy.Profile) { p.HTTP.URL = "https://{{name}}/x" },
		"host suffix":     func(p *policy.Profile) { p.HTTP.URL = "https://git.example{{name}}/x" },
		"secret in url":   func(p *policy.Profile) { p.HTTP.URL = "https://git.example/?t={{secret:gitea}}" },
		"undeclared":      func(p *policy.Profile) { p.HTTP.Body = "{{ghost}}" },
		"internal secret": func(p *policy.Profile) { p.HTTP.Headers["X"] = "{{secret:_telegram_token}}" },
		"high auto":       func(p *policy.Profile) { p.Risk = "high"; p.AutoApprove = true },
		"no pattern":      func(p *policy.Profile) { p.Params[0].Pattern = "" },
		"unused param":    func(p *policy.Profile) { p.HTTP.Body = "" },
		"bad method":      func(p *policy.Profile) { p.HTTP.Method = "TRACE" },
		"bad name":        func(p *policy.Profile) { p.Name = "Bad Name" },
	} {
		p := base()
		mut(&p)
		add(n, p, map[string]string{"name": "a"})
	}
	q := policy.Profile{Name: "q", Risk: "low", Params: []policy.Param{{Name: "a", Pattern: `.+`, Required: true}},
		HTTP: &policy.HTTPSpec{Method: "GET", URL: "https://api.example/v1/repos/{{a}}/info?owner={{a}}&x=1"}}
	for _, v := range []string{"..", ".", "x&admin=true", "x#frag", "a b/c", "ü%20", "@evil.example"} {
		add("url escape "+v, q, map[string]string{"a": v})
	}
	form := policy.Profile{Name: "f", Risk: "low", Params: []policy.Param{{Name: "n", Pattern: `.*`}},
		HTTP: &policy.HTTPSpec{Method: "POST", URL: "https://a.example/x", Body: "x={{n}}", Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}}}
	add("form escape", form, map[string]string{"n": "1&role=admin é"})
	ex := policy.Profile{Name: "e", Risk: "high", Params: []policy.Param{{Name: "u", Pattern: `.+`, Required: true}},
		Exec: &policy.ExecSpec{Argv: []string{"/usr/bin/git", "clone", "{{u}}", "--depth={{u}}"}, Env: map[string]string{"TOKEN": "{{secret:s}}"}, Stdin: "{{secret:p}}", Files: map[string]string{"id_key": "{{secret:k}}"}}}
	add("exec ok", ex, map[string]string{"u": "https://x.example/r"})
	add("exec option injection", ex, map[string]string{"u": "--upload-pack=x"})
	for n, mut := range map[string]func(*policy.ExecSpec){
		"shell":        func(e *policy.ExecSpec) { e.Argv = []string{"/bin/sh", "-c", "{{u}}"} },
		"busybox":      func(e *policy.ExecSpec) { e.Argv[0] = "/bin/busybox" },
		"relative":     func(e *policy.ExecSpec) { e.Argv[0] = "git" },
		"secret argv":  func(e *policy.ExecSpec) { e.Argv = append(e.Argv, "{{secret:s}}") },
		"ld preload":   func(e *policy.ExecSpec) { e.Env = map[string]string{"LD_PRELOAD": "x"} },
		"path env":     func(e *policy.ExecSpec) { e.Env = map[string]string{"PATH": "x"} },
		"file escape":  func(e *policy.ExecSpec) { e.Files = map[string]string{"../x": "{{secret:k}}"} },
		"param file":   func(e *policy.ExecSpec) { e.Files = map[string]string{"k": "{{u}}"} },
	} {
		p := ex
		e := *ex.Exec
		e.Argv = append([]string{}, ex.Exec.Argv...)
		mut(&e)
		p.Exec = &e
		add("exec "+n, p, map[string]string{"u": "x"})
	}
	choice := policy.Profile{Name: "c", Risk: "low", SecretChoices: []string{"a", "b"}, HTTP: &policy.HTTPSpec{Method: "GET", URL: "https://x.example/", Headers: map[string]string{"A": "{{secret:choice}}"}}}
	add("choice ok", choice, nil)
	cauto := choice
	cauto.AutoApprove = true
	add("choice auto", cauto, nil)

	// Resolve against connections
	conns := map[string]policy.Connection{"gh": {Name: "gh", BaseURL: "https://api.github.com/", Auth: policy.Auth{Type: "bearer", Secret: "github_token"}, Headers: map[string]string{"Accept": "application/json"}},
		"pick": {Name: "pick", BaseURL: "https://a.example/v1", Auth: policy.Auth{Type: "header", Header: "X-Api-Key", Choices: []string{"x", "y"}}}}
	type resolveCase struct {
		Name        string                       `json:"name"`
		Profile     policy.Profile               `json:"profile"`
		Connections map[string]policy.Connection `json:"connections"`
		Params      map[string]string            `json:"params"`
		Want        result                       `json:"want"`
	}
	var rs []resolveCase
	addR := func(name string, p policy.Profile, params map[string]string) {
		var w result
		if err := p.Validate(); err != nil {
			w = result{Error: err.Error()}
		} else if r, err := policy.Resolve(p, conns); err != nil {
			w = result{Error: err.Error()}
		} else {
			w = render(r, params)
		}
		rs = append(rs, resolveCase{name, p, conns, params, w})
	}
	cp := func(url string, h map[string]string) policy.Profile {
		return policy.Profile{Name: "p", Risk: "low", Connection: "gh", Params: []policy.Param{{Name: "a", Pattern: `.+`, Required: true}}, HTTP: &policy.HTTPSpec{Method: "GET", URL: url, Headers: h}}
	}
	addR("ok", cp("/repos/{{a}}", nil), map[string]string{"a": "x"})
	addR("protocol relative", cp("//evil.example/{{a}}", nil), map[string]string{"a": "x"})
	addR("absolute", cp("https://evil.example/{{a}}", nil), map[string]string{"a": "x"})
	addR("auth override", cp("/x/{{a}}", map[string]string{"authorization": "Bearer {{secret:other}}"}), map[string]string{"a": "x"})
	addR("at sign", cp("/{{a}}", nil), map[string]string{"a": "@evil.example"})
	pk := cp("/me/{{a}}", nil)
	pk.Connection = "pick"
	addR("choices", pk, map[string]string{"a": "x"})
	gone := cp("/x/{{a}}", nil)
	gone.Connection = "ghost"
	addR("unknown connection", gone, map[string]string{"a": "x"})

	// Connection validation
	type connCase struct {
		Name  string            `json:"name"`
		Conn  policy.Connection `json:"conn"`
		Error string            `json:"error,omitempty"`
	}
	var cc []connCase
	for n, c := range map[string]policy.Connection{
		"ok":           {Name: "a", BaseURL: "https://a.example/v1", Auth: policy.Auth{Type: "bearer", Secret: "s"}},
		"template":     {Name: "a", BaseURL: "https://{{x}}.example", Auth: policy.Auth{Type: "none"}},
		"query":        {Name: "a", BaseURL: "https://a.example/?k=v", Auth: policy.Auth{Type: "none"}},
		"userinfo":     {Name: "a", BaseURL: "https://u:p@a.example", Auth: policy.Auth{Type: "none"}},
		"no secret":    {Name: "a", BaseURL: "https://a.example", Auth: policy.Auth{Type: "bearer"}},
		"both":         {Name: "a", BaseURL: "https://a.example", Auth: policy.Auth{Type: "bearer", Secret: "s", Choices: []string{"t"}}},
		"internal":     {Name: "a", BaseURL: "https://a.example", Auth: policy.Auth{Type: "bearer", Secret: "_totp_secret"}},
		"header name":  {Name: "a", BaseURL: "https://a.example", Auth: policy.Auth{Type: "header", Header: "Bad Header", Secret: "s"}},
		"header value": {Name: "a", BaseURL: "https://a.example", Auth: policy.Auth{Type: "none"}, Headers: map[string]string{"X": "{{secret:s}}"}},
		"name":         {Name: "Bad", BaseURL: "https://a.example", Auth: policy.Auth{Type: "none"}},
		"bad type":     {Name: "a", BaseURL: "https://a.example", Auth: policy.Auth{Type: "basic", Secret: "s"}},
	} {
		e := ""
		if err := c.Validate(); err != nil {
			e = err.Error()
		}
		cc = append(cc, connCase{n, c, e})
	}

	// Agent calls
	meta := map[string]policy.SecretMeta{"gh": {Description: "GitHub", Hosts: []string{"api.github.com"}}, "wild": {Hosts: []string{"*.example.com"}},
		"cmd": {AllowCommands: true}, "none": {Description: "no hosts"}, "port": {Hosts: []string{"localhost:8080"}}}
	type callCase struct {
		Name string                       `json:"name"`
		Call policy.Call                  `json:"call"`
		Meta map[string]policy.SecretMeta `json:"meta"`
		Want result                       `json:"want"`
	}
	var calls []callCase
	addC := func(name string, c policy.Call) {
		var w result
		if p, err := policy.FromCall(c, meta); err != nil {
			w = result{Error: err.Error()}
		} else {
			w = render(p, nil)
		}
		calls = append(calls, callCase{name, c, meta, w})
	}
	hc := func(url string, h map[string]string, body string) policy.Call {
		return policy.Call{HTTP: &policy.HTTPSpec{Method: "GET", URL: url, Headers: h, Body: body}}
	}
	auth := map[string]string{"Authorization": "Bearer {{secret:gh}}"}
	addC("ok", hc("https://api.github.com/user", auth, ""))
	addC("wildcard", hc("https://a.b.example.com/x", map[string]string{"X": "{{secret:wild}}"}, ""))
	addC("port ok", hc("http://localhost:8080/x", map[string]string{"X": "{{secret:port}}"}, ""))
	for n, c := range map[string]policy.Call{
		"other host": hc("https://evil.example/x", auth, ""), "lookalike": hc("https://api.github.com.evil.example/x", auth, ""),
		"suffix": hc("https://evilapi.github.com/x", auth, ""), "userinfo": hc("https://api.github.com@evil.example/x", auth, ""),
		"other port": hc("https://api.github.com:8443/x", auth, ""), "in url": hc("https://api.github.com/x?t={{secret:gh}}", nil, ""),
		"in body": hc("https://api.github.com/gists", nil, `{"t":"{{secret:gh}}"}`), "body with header": hc("https://api.github.com/gists", auth, `{"c":"{{secret:gh}}"}`),
		"unknown": hc("https://api.github.com/x", map[string]string{"A": "{{secret:nope}}"}, ""), "no hosts": hc("https://api.github.com/x", map[string]string{"A": "{{secret:none}}"}, ""),
		"apex": hc("https://example.com/x", map[string]string{"X": "{{secret:wild}}"}, ""), "param": hc("https://api.github.com/x", map[string]string{"A": "{{x}}"}, ""),
		"no secret": hc("https://api.github.com/x", nil, ""), "relative": hc("/x", auth, ""), "upper host": hc("https://API.GITHUB.COM/x", auth, ""),
		"exec ok":      {Exec: &policy.ExecSpec{Argv: []string{"/usr/bin/git", "ls-remote"}, Env: map[string]string{"T": "{{secret:cmd}}"}}},
		"exec denied":  {Exec: &policy.ExecSpec{Argv: []string{"/usr/bin/git"}, Env: map[string]string{"T": "{{secret:gh}}"}}},
		"exec argv":    {Exec: &policy.ExecSpec{Argv: []string{"/usr/bin/git", "{{secret:cmd}}"}}},
		"both":         {HTTP: &policy.HTTPSpec{Method: "GET", URL: "https://api.github.com/"}, Exec: &policy.ExecSpec{Argv: []string{"/bin/true"}}},
	} {
		addC(n, c)
	}

	// Redaction
	type redactCase struct {
		Input   string   `json:"input"`
		Secrets []string `json:"secrets"`
		Want    string   `json:"want"`
	}
	var red []redactCase
	for _, rc := range []redactCase{
		{Input: "tok ghp_abcdef123 b64 Z2hwX2FiY2RlZjEyMw== hex 6768705f616263646566313233 q ghp_abcdef123", Secrets: []string{"ghp_abcdef123"}},
		{Input: "short abc stays", Secrets: []string{"abc"}},
		{Input: "url a%2Fb%3Dc and a/b=c and json \"a\\\"b\"", Secrets: []string{"a/b=c", "a\"b"}},
		{Input: "upper 6768705F616263646566313233", Secrets: []string{"ghp_abcdef123"}},
	} {
		var bs [][]byte
		for _, s := range rc.Secrets {
			bs = append(bs, []byte(s))
		}
		rc.Want = policy.Redact(rc.Input, bs)
		red = append(red, rc)
	}

	// Secret notes validation
	type metaCase struct {
		Meta  policy.SecretMeta `json:"meta"`
		Error string            `json:"error,omitempty"`
	}
	var mc []metaCase
	for _, m := range []policy.SecretMeta{{Hosts: []string{"https://a.com"}}, {Hosts: []string{"*"}}, {Hosts: []string{"A.COM"}}, {Hosts: []string{"a b.com"}},
		{Description: "a‮b"}, {Description: "GitHub", Hosts: []string{"api.github.com", "*.example.com", "localhost:8080"}}} {
		e := ""
		if err := m.Validate(); err != nil {
			e = err.Error()
		}
		mc = append(mc, metaCase{m, e})
	}

	return map[string]any{"render": rc, "resolve": rs, "connections": cc, "calls": calls, "redact": red, "secret_meta": mc}
}
