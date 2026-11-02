package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"ucanrun/internal/policy"
	"ucanrun/internal/vault"
)

const testPass = "correct horse battery staple"

func newTestCore(t *testing.T) *Core {
	t.Helper()
	c, err := New(Options{DataDir: t.TempDir(), WorkFactor: 10})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if err := c.Setup([]byte(testPass)); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestStateVersioningAndMigration(t *testing.T) {
	c := newTestCore(t)
	if c.st.Version != currentStateVersion {
		t.Fatalf("setup version: got %d, want %d", c.st.Version, currentStateVersion)
	}
	k, err := c.Vault.MACKey()
	if err != nil {
		t.Fatal(err)
	}
	c.Lock("test")

	// 1. Old state without a version field counts as 0 and migrates to current.
	oldData := []byte(`{"profiles":{"p":{"name":"p","risk":"low"}},"tokens":{},"telegram":{"user_id":42,"chat_id":42},"totp_enabled":false,"last_totp_step":0}`)
	raw, err := json.Marshal(signedFile{MAC: mac(k, oldData), Data: oldData})
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.AtomicWrite(c.statePath(), raw); err != nil {
		t.Fatal(err)
	}
	if err := c.Login([]byte(testPass), ""); err != nil {
		t.Fatalf("login with v0 state: %v", err)
	}
	if c.st.Version != currentStateVersion {
		t.Fatalf("migrated version: got %d, want %d", c.st.Version, currentStateVersion)
	}
	if c.st.Telegram.UserID != 42 || c.st.Profiles["p"].Name != "p" {
		t.Fatalf("migrated data lost: %+v", c.st)
	}
	// Migrated state is persisted on the next normal save.
	if err := c.DeleteProfile("p"); err != nil {
		t.Fatal(err)
	}
	diskRaw, err := os.ReadFile(c.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(diskRaw, []byte(`"version":1`)) {
		t.Fatalf("saved state missing version 1: %s", diskRaw)
	}

	// 2. Tampered old state is refused before migration runs.
	c.Lock("test")
	migrated := false
	origMig := stateMigrations[0]
	stateMigrations[0] = func(st *State) error {
		migrated = true
		return origMig(st)
	}
	defer func() { stateMigrations[0] = origMig }()

	tamperedData := bytes.Replace(oldData, []byte(`"low"`), []byte(`"high"`), 1)
	badRaw, _ := json.Marshal(signedFile{MAC: mac(k, oldData), Data: tamperedData})
	if err := vault.AtomicWrite(c.statePath(), badRaw); err != nil {
		t.Fatal(err)
	}
	if err := c.Login([]byte(testPass), ""); !errors.Is(err, ErrTampered) {
		t.Fatalf("tampered v0 login: got %v, want ErrTampered", err)
	}
	if migrated {
		t.Fatal("migration ran on unauthenticated state")
	}
	if !c.Locked() || !c.Vault.Locked() {
		t.Fatal("vault unlocked after tampered state")
	}

	// 3. Newer state is refused with ErrStateTooNew and leaves the vault locked.
	future := &State{
		Version:  currentStateVersion + 1,
		Profiles: map[string]policy.Profile{},
		Tokens:   map[string]Token{},
	}
	if err := saveState(c.statePath(), future, k); err != nil {
		t.Fatal(err)
	}
	futureBytes, _ := os.ReadFile(c.statePath())
	if err := c.Login([]byte(testPass), ""); !errors.Is(err, ErrStateTooNew) {
		t.Fatalf("future state login: got %v, want ErrStateTooNew", err)
	}
	if !c.Locked() || !c.Vault.Locked() {
		t.Fatal("vault unlocked after ErrStateTooNew")
	}
	afterBytes, _ := os.ReadFile(c.statePath())
	if !bytes.Equal(futureBytes, afterBytes) {
		t.Fatal("newer state file was modified by old binary")
	}
}

func TestAuditTruncationDetection(t *testing.T) {
	c := newTestCore(t)
	if _, err := c.CreateToken("agent1", nil); err != nil {
		t.Fatal(err)
	}
	c.Lock("test")

	// Normal Lock and Login is not flagged.
	if err := c.Login([]byte(testPass), ""); err != nil {
		t.Fatalf("normal login: %v", err)
	}
	if c.AuditTruncated() {
		t.Fatal("normal lock and login flagged as truncated")
	}

	c.Lock("test")
	anchoredCount, _ := c.Audit.Head()
	if anchoredCount < 3 {
		t.Fatalf("expected at least 3 audit entries, got %d", anchoredCount)
	}

	// Cut the last line of the audit file after Lock.
	b, err := os.ReadFile(c.auditPath())
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	cut := append(bytes.Join(lines[:len(lines)-1], []byte("\n")), '\n')
	if err := os.WriteFile(c.auditPath(), cut, 0o600); err != nil {
		t.Fatal(err)
	}

	// Next Login succeeds (does not lock owner out) but flags truncation and logs audit_truncated.
	if err := c.Login([]byte(testPass), ""); err != nil {
		t.Fatalf("login after truncation failed: %v", err)
	}
	if c.Locked() {
		t.Fatal("owner locked out after audit truncation")
	}
	if !c.AuditTruncated() {
		t.Fatal("audit truncation not detected")
	}
	es, err := c.Audit.Tail(10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range es {
		if e.Event == "audit_truncated" {
			found = true
			if got, ok := e.Fields["count"].(float64); !ok || int(got) != anchoredCount {
				t.Fatalf("audit_truncated count: got %v, want %d", e.Fields["count"], anchoredCount)
			}
		}
	}
	if !found {
		t.Fatalf("audit_truncated event not found in %+v", es)
	}
}
