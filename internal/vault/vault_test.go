package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newV(t *testing.T) *Vault {
	v := New(t.TempDir())
	v.WorkFactor = 10
	if err := v.Init([]byte("correct horse battery")); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRoundTripAndLock(t *testing.T) {
	v := newV(t)
	if err := v.Put("gitea", []byte("s3cret")); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get("gitea")
	if err != nil || string(got) != "s3cret" {
		t.Fatalf("get: %q %v", got, err)
	}
	v.Lock()
	if _, err := v.Get("gitea"); !errors.Is(err, ErrLocked) {
		t.Fatalf("want locked, got %v", err)
	}
	if err := v.Put("while-locked", []byte("x")); err != nil {
		t.Fatalf("put while locked: %v", err)
	}
	if err := v.Unlock([]byte("wrong passphrase!")); !errors.Is(err, ErrBadPass) {
		t.Fatalf("want bad pass, got %v", err)
	}
	if err := v.Unlock([]byte("correct horse battery")); err != nil {
		t.Fatal(err)
	}
	if got, _ := v.Get("while-locked"); string(got) != "x" {
		t.Fatal("secret added while locked unreadable")
	}
}

func TestNoPlaintextOnDisk(t *testing.T) {
	v := newV(t)
	val := []byte("PLAINTEXT-MARKER-123")
	if err := v.Put("x", val); err != nil {
		t.Fatal(err)
	}
	filepath.WalkDir(v.dir, func(p string, d os.DirEntry, _ error) error {
		if d.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, val) || bytes.Contains(b, []byte("AGE-SECRET-KEY")) {
			t.Fatalf("plaintext in %s", p)
		}
		fi, _ := d.Info()
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o", p, fi.Mode().Perm())
		}
		return nil
	})
}

func TestNames(t *testing.T) {
	v := newV(t)
	for _, n := range []string{"../evil", "a/b", "", ".hidden"} {
		if err := v.Put(n, []byte("x")); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("%q accepted: %v", n, err)
		}
		if _, err := v.Get(n); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("%q get accepted: %v", n, err)
		}
	}
	v.Put("_internal", []byte("x"))
	v.Put("visible", []byte("x"))
	l, _ := v.List()
	if len(l) != 1 || l[0].Name != "visible" {
		t.Fatalf("list: %+v", l)
	}
}

func TestChangePassphrase(t *testing.T) {
	v := newV(t)
	v.Put("x", []byte("y"))
	if err := v.ChangePassphrase([]byte("correct horse battery"), []byte("new passphrase here")); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if err := v.Unlock([]byte("correct horse battery")); err == nil {
		t.Fatal("old passphrase still works")
	}
	if err := v.Unlock([]byte("new passphrase here")); err != nil {
		t.Fatal(err)
	}
	if got, _ := v.Get("x"); string(got) != "y" {
		t.Fatal("secret lost")
	}
}

func TestMACKeyStable(t *testing.T) {
	v := newV(t)
	a, _ := v.MACKey()
	v.Lock()
	if _, err := v.MACKey(); !errors.Is(err, ErrLocked) {
		t.Fatal("mac key while locked")
	}
	v.Unlock([]byte("correct horse battery"))
	b, _ := v.MACKey()
	if !bytes.Equal(a, b) {
		t.Fatal("mac key changed")
	}
}
