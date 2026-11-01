package policy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

func httpProfile() *Profile {
	return &Profile{
		Name: "create-repo", Risk: RiskLow,
		Params: []Param{{Name: "name", Pattern: `[a-z0-9-]+`, Required: true}, {Name: "note", Pattern: `.*`}},
		HTTP: &HTTPSpec{Method: "POST", URL: "https://git.example/api/repos/{{name}}",
			Headers: map[string]string{"Authorization": "token {{secret:gitea}}", "Content-Type": "application/json"},
			Body:    `{"note":"{{note}}"}`},
	}
}

func TestValidateRejectsExfiltrationShapes(t *testing.T) {
	bad := map[string]func(*Profile){
		"host template":   func(p *Profile) { p.HTTP.URL = "https://{{name}}/x" },
		"host suffix":     func(p *Profile) { p.HTTP.URL = "https://git.example{{name}}/x" },
		"scheme":          func(p *Profile) { p.HTTP.URL = "{{name}}" },
		"secret in url":   func(p *Profile) { p.HTTP.URL = "https://git.example/?t={{secret:gitea}}" },
		"undeclared":      func(p *Profile) { p.HTTP.Body = "{{ghost}}" },
		"internal secret": func(p *Profile) { p.HTTP.Headers["X"] = "{{secret:_telegram_token}}" },
		"high auto":       func(p *Profile) { p.Risk = RiskHigh; p.AutoApprove = true },
		"both":            func(p *Profile) { p.Exec = &ExecSpec{Argv: []string{"/bin/true"}} },
		"no pattern":      func(p *Profile) { p.Params[0].Pattern = "" },
		"shell":           func(p *Profile) { p.HTTP = nil; p.Exec = &ExecSpec{Argv: []string{"/bin/sh", "-c", "{{name}}"}} },
		"secret in argv":  func(p *Profile) { p.HTTP = nil; p.Exec = &ExecSpec{Argv: []string{"/bin/x", "{{secret:a}}"}} },
		"templated argv0": func(p *Profile) { p.HTTP = nil; p.Exec = &ExecSpec{Argv: []string{"{{name}}"}} },
		"relative argv0":  func(p *Profile) { p.HTTP = nil; p.Exec = &ExecSpec{Argv: []string{"git"}} },
	}
	for name, mutate := range bad {
		p := httpProfile()
		mutate(p)
		if p.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := httpProfile().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParamChecksAndEscaping(t *testing.T) {
	p := httpProfile()
	for _, in := range []map[string]string{
		{},
		{"name": "../admin"},
		{"name": "a\nb"},
		{"name": "ok", "extra": "x"},
	} {
		if _, err := p.Render(in); err == nil {
			t.Errorf("%v accepted", in)
		}
	}
	p.Params[0].Pattern = `.+`
	a, err := p.Render(map[string]string{"name": "a/../b", "note": `x","admin":"true`})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(a.HTTP.URL, "a%2F..%2Fb") {
		t.Fatalf("path not escaped: %s", a.HTTP.URL)
	}
	if !strings.Contains(a.HTTP.Body, `x\",\"admin\":\"true`) {
		t.Fatalf("json not escaped: %s", a.HTTP.Body)
	}
}

func TestParamCannotInjectSecretReference(t *testing.T) {
	p := httpProfile()
	if _, err := p.Render(map[string]string{"name": "x", "note": "{{secret:other}}"}); err == nil {
		t.Fatal("template in param value accepted")
	}
	// Split across a literal brace, the value alone has no "{{".
	p.HTTP.Body = "{{{note}}secret:other}}"
	if _, err := p.Render(map[string]string{"name": "x", "note": "{"}); err == nil {
		t.Fatal("secret assembled from a param and literal text")
	}
}

func TestDisplayNeverExpandsSecrets(t *testing.T) {
	a, _ := httpProfile().Render(map[string]string{"name": "x"})
	d := a.Display()
	if !strings.Contains(d, "‹secret:gitea›") || strings.Contains(d, "{{") {
		t.Fatalf("display: %s", d)
	}
}

func TestHashBindsEverything(t *testing.T) {
	p := httpProfile()
	a, _ := p.Render(map[string]string{"name": "x"})
	b, _ := p.Render(map[string]string{"name": "y"})
	h := Hash(p, a, "agent")
	if h == Hash(p, b, "agent") || h == Hash(p, a, "other") {
		t.Fatal("hash collision on differing inputs")
	}
}

func TestRunHTTPRedactsAndKeepsSecretFromRedirect(t *testing.T) {
	const secret = "not a real value, test only"
	var leaked bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer evil.Close()
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, evil.URL, http.StatusFound)
			return
		}
		io.WriteString(w, "echo "+gotAuth+" b64="+base64.StdEncoding.EncodeToString([]byte(secret)))
	}))
	defer srv.Close()
	get := func(string) ([]byte, error) { return []byte(secret), nil }
	a := &Action{TimeoutSec: 5, HTTP: &HTTPSpec{Method: "GET", URL: srv.URL + "/x", Headers: map[string]string{"Authorization": "token {{secret:s}}"}}}
	r := Run(context.Background(), a, get)
	if !r.OK || gotAuth != "token "+secret {
		t.Fatalf("%+v auth=%q", r, gotAuth)
	}
	if strings.Contains(r.Output, secret) || strings.Contains(r.Output, base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatalf("leak: %s", r.Output)
	}
	a.HTTP.URL = srv.URL + "/redir"
	Run(context.Background(), a, get)
	if leaked {
		t.Fatal("followed redirect")
	}
}

func TestRunExec(t *testing.T) {
	get := func(string) ([]byte, error) { return []byte("supersecretvalue"), nil }
	printenv, err := exec.LookPath("printenv")
	if err != nil {
		t.Skip("printenv not installed")
	}
	a := &Action{TimeoutSec: 5, Exec: &ExecSpec{Argv: []string{printenv, "T"}, Env: map[string]string{"T": "{{secret:s}}"}}}
	r := Run(context.Background(), a, get)
	if !r.OK || strings.Contains(r.Output, "supersecretvalue") || !strings.Contains(r.Output, "[REDACTED]") {
		t.Fatalf("%+v", r)
	}
	a = &Action{TimeoutSec: 1, Exec: &ExecSpec{Argv: []string{"/bin/sleep", "20"}}}
	if r := Run(context.Background(), a, get); r.OK || !strings.Contains(r.Output, "timed out") {
		t.Fatalf("%+v", r)
	}
}

func TestRunExecReportsMissingBinary(t *testing.T) {
	a := &Action{TimeoutSec: 5, Exec: &ExecSpec{Argv: []string{"/no/such/tool"}}}
	r := Run(context.Background(), a, nil)
	if r.OK || r.Exit != -1 || !strings.Contains(r.Output, "could not start") {
		t.Fatalf("%+v", r)
	}
}

func TestRunMissingSecretDoesNotExecute(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()
	a := &Action{TimeoutSec: 5, HTTP: &HTTPSpec{Method: "GET", URL: srv.URL, Headers: map[string]string{"A": "{{secret:s}}"}}}
	r := Run(context.Background(), a, func(string) ([]byte, error) { return nil, errors.New("no") })
	if r.OK || called {
		t.Fatal("ran without secret")
	}
}
