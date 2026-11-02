package core

import (
	"errors"
	"slices"
	"testing"

	"ucanrun/internal/policy"
)

func healthItem(t *testing.T, c *Core, key string) HealthItem {
	t.Helper()
	items, err := c.Health()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range items {
		if i.Key == key {
			return i
		}
	}
	t.Fatalf("no health item %q", key)
	return HealthItem{}
}

func post(name, secret string, auto bool) policy.Profile {
	return policy.Profile{Name: name, Risk: policy.RiskLow, AutoApprove: auto,
		HTTP: &policy.HTTPSpec{Method: "POST", URL: "https://example.com/x",
			Headers: map[string]string{"Authorization": "Bearer {{secret:" + secret + "}}"}}}
}

func TestHealthLocked(t *testing.T) {
	c := newTestCore(t)
	c.Lock("test")
	if _, err := c.Health(); !errors.Is(err, ErrLocked) {
		t.Fatalf("got %v", err)
	}
}

func TestHealthTOTPOff(t *testing.T) {
	c := newTestCore(t)
	if i := healthItem(t, c, "totp"); i.Level != "bad" {
		t.Fatalf("totp: %+v", i)
	}
	items, _ := c.Health()
	for _, i := range items {
		if i.Key == "recovery" {
			t.Fatal("recovery shown while TOTP is off")
		}
	}
}

func TestHealthRecovery(t *testing.T) {
	c := newTestCore(t)
	c.st.TOTPEnabled = true
	for n, want := range map[int]string{0: "bad", 2: "warn", 3: "ok"} {
		c.st.RecoveryHashes = make([]string, n)
		if i := healthItem(t, c, "recovery"); i.Level != want {
			t.Fatalf("%d codes: %+v", n, i)
		}
	}
}

func TestHealthSecrets(t *testing.T) {
	c := newTestCore(t)
	if err := c.Vault.Put("orphan", []byte("hunter2-value")); err != nil {
		t.Fatal(err)
	}
	if err := c.Vault.Put("used", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := c.PutProfile(post("a", "used", false)); err != nil {
		t.Fatal(err)
	}
	if err := c.PutProfile(post("b", "gone", false)); err != nil {
		t.Fatal(err)
	}
	if i := healthItem(t, c, "unused_secrets"); i.Level != "warn" || !slices.Equal(i.Names, []string{"orphan"}) {
		t.Fatalf("unused: %+v", i)
	}
	if i := healthItem(t, c, "missing_secrets"); i.Level != "bad" || !slices.Equal(i.Names, []string{"gone"}) {
		t.Fatalf("missing: %+v", i)
	}
}

func TestHealthSecretChoicesAreUsed(t *testing.T) {
	c := newTestCore(t)
	if err := c.Vault.Put("alt", []byte("v")); err != nil {
		t.Fatal(err)
	}
	p := post("pick", policy.ChoiceRef, false)
	p.SecretChoices = []string{"alt"}
	if err := c.PutProfile(p); err != nil {
		t.Fatal(err)
	}
	if i := healthItem(t, c, "unused_secrets"); i.Level != "ok" {
		t.Fatalf("unused: %+v", i)
	}
	if i := healthItem(t, c, "missing_secrets"); i.Level != "ok" {
		t.Fatalf("missing: %+v", i)
	}
}

func TestHealthAutoWrite(t *testing.T) {
	c := newTestCore(t)
	if err := c.Vault.Put("s", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := c.PutProfile(post("writer", "s", true)); err != nil {
		t.Fatal(err)
	}
	read := post("reader", "s", true)
	read.HTTP.Method = "GET"
	if err := c.PutProfile(read); err != nil {
		t.Fatal(err)
	}
	if i := healthItem(t, c, "auto_write"); i.Level != "warn" || !slices.Equal(i.Names, []string{"writer"}) {
		t.Fatalf("auto_write: %+v", i)
	}
	if i := healthItem(t, c, "lint"); !slices.Contains(i.Names, "writer") {
		t.Fatalf("lint: %+v", i)
	}
}

func TestHealthUnscopedTokens(t *testing.T) {
	c := newTestCore(t)
	if _, err := c.CreateToken("wide", nil); err != nil {
		t.Fatal(err)
	}
	items, _ := c.Health()
	for _, i := range items {
		if i.Key == "unscoped_tokens" {
			t.Fatal("shown with fewer than two profiles")
		}
	}
	for _, n := range []string{"a", "b"} {
		if err := c.PutProfile(post(n, "s", false)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.CreateToken("narrow", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if i := healthItem(t, c, "unscoped_tokens"); i.Level != "warn" || !slices.Equal(i.Names, []string{"wide"}) {
		t.Fatalf("unscoped: %+v", i)
	}
}

func TestHealthExecAndAudit(t *testing.T) {
	c := newTestCore(t)
	if i := healthItem(t, c, "exec"); i.Level != "ok" {
		t.Fatalf("exec: %+v", i)
	}
	c.opt.AllowExec = true
	if i := healthItem(t, c, "exec"); i.Level != "warn" {
		t.Fatalf("exec: %+v", i)
	}
	if i := healthItem(t, c, "audit"); i.Level != "ok" {
		t.Fatalf("audit: %+v", i)
	}
	c.auditCut = true
	if i := healthItem(t, c, "audit"); i.Level != "bad" {
		t.Fatalf("audit: %+v", i)
	}
}
