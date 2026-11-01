// Package vault stores secrets as individual age-encrypted files.
//
// A random X25519 identity decrypts the secrets; the identity itself is
// encrypted with the master passphrase (age scrypt). Adding a secret needs only
// the public recipient, so it works while the vault is locked. Reading one needs
// the identity, which exists only in memory after Unlock.
package vault

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
)

var (
	ErrLocked      = errors.New("vault locked")
	ErrBadPass     = errors.New("wrong passphrase")
	ErrExists      = errors.New("vault already initialized")
	ErrNotFound    = errors.New("secret not found")
	ErrInvalidName = errors.New("invalid secret name")
	nameRe         = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)
)

// MaxSecretSize bounds a single secret value.
const MaxSecretSize = 64 << 10

type Meta struct {
	Name    string    `json:"name"`
	Updated time.Time `json:"updated"`
}

type Vault struct {
	dir string
	// WorkFactor is the scrypt log2(N). Zero means the age default.
	WorkFactor int

	mu       sync.RWMutex
	identity *age.X25519Identity
}

func New(dir string) *Vault { return &Vault{dir: dir} }

func (v *Vault) identityPath() string  { return filepath.Join(v.dir, "identity.age") }
func (v *Vault) recipientPath() string { return filepath.Join(v.dir, "recipient.txt") }
func (v *Vault) secretPath(n string) string {
	return filepath.Join(v.dir, "secrets", n+".age")
}

func ValidName(n string) bool { return nameRe.MatchString(n) }

func (v *Vault) Initialized() bool {
	_, err := os.Stat(v.identityPath())
	return err == nil
}

func (v *Vault) Locked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.identity == nil
}

// Init creates a new vault. The identity stays loaded, so the vault is unlocked.
func (v *Vault) Init(pass []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.Initialized() {
		return ErrExists
	}
	if err := os.MkdirAll(filepath.Join(v.dir, "secrets"), 0o700); err != nil {
		return err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	if err := v.writeIdentity(id, pass); err != nil {
		return err
	}
	if err := atomicWrite(v.recipientPath(), []byte(id.Recipient().String()+"\n")); err != nil {
		return err
	}
	v.identity = id
	return nil
}

func (v *Vault) writeIdentity(id *age.X25519Identity, pass []byte) error {
	r, err := age.NewScryptRecipient(string(pass))
	if err != nil {
		return err
	}
	if v.WorkFactor > 0 {
		r.SetWorkFactor(v.WorkFactor)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, id.String()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return atomicWrite(v.identityPath(), buf.Bytes())
}

func (v *Vault) loadIdentity(pass []byte) (*age.X25519Identity, error) {
	f, err := os.Open(v.identityPath())
	if err != nil {
		return nil, err
	}
	defer f.Close()
	si, err := age.NewScryptIdentity(string(pass))
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(f, si)
	if err != nil {
		return nil, ErrBadPass
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, ErrBadPass
	}
	return age.ParseX25519Identity(strings.TrimSpace(string(b)))
}

func (v *Vault) Unlock(pass []byte) error {
	id, err := v.loadIdentity(pass)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.identity = id
	v.mu.Unlock()
	return nil
}

// Verify checks a passphrase without changing the lock state.
func (v *Vault) Verify(pass []byte) error {
	_, err := v.loadIdentity(pass)
	return err
}

func (v *Vault) Lock() {
	v.mu.Lock()
	v.identity = nil
	v.mu.Unlock()
}

// ChangePassphrase re-wraps the identity. Secret files are untouched.
func (v *Vault) ChangePassphrase(oldPass, newPass []byte) error {
	id, err := v.loadIdentity(oldPass)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.writeIdentity(id, newPass)
}

// MACKey derives the key that authenticates server state.
func (v *Vault) MACKey() ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.identity == nil {
		return nil, ErrLocked
	}
	return hkdf.Key(sha256.New, []byte(v.identity.String()), nil, "ucanrun state mac v1", 32)
}

// Put encrypts a secret. It needs only the recipient, so it works while locked.
func (v *Vault) Put(name string, value []byte) error {
	if !ValidName(name) {
		return ErrInvalidName
	}
	if len(value) == 0 || len(value) > MaxSecretSize {
		return fmt.Errorf("secret size must be 1..%d bytes", MaxSecretSize)
	}
	raw, err := os.ReadFile(v.recipientPath())
	if err != nil {
		return err
	}
	rcpt, err := age.ParseX25519Recipient(strings.TrimSpace(string(raw)))
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rcpt)
	if err != nil {
		return err
	}
	if _, err := w.Write(value); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return atomicWrite(v.secretPath(name), buf.Bytes())
}

func (v *Vault) Get(name string) ([]byte, error) {
	if !ValidName(name) {
		return nil, ErrInvalidName
	}
	v.mu.RLock()
	id := v.identity
	v.mu.RUnlock()
	if id == nil {
		return nil, ErrLocked
	}
	f, err := os.Open(v.secretPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, id)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", name, err)
	}
	return io.ReadAll(r)
}

func (v *Vault) Delete(name string) error {
	if !ValidName(name) {
		return ErrInvalidName
	}
	err := os.Remove(v.secretPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	return err
}

// List returns secret metadata. Names starting with "_" are internal.
func (v *Vault) List() ([]Meta, error) {
	ents, err := os.ReadDir(filepath.Join(v.dir, "secrets"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Meta{}
	for _, e := range ents {
		n, ok := strings.CutSuffix(e.Name(), ".age")
		if !ok || strings.HasPrefix(n, "_") {
			continue
		}
		m := Meta{Name: n}
		if fi, err := e.Info(); err == nil {
			m.Updated = fi.ModTime().UTC()
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%x.tmp", path, suffix)
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// AtomicWrite exposes the private file writer to other packages.
func AtomicWrite(path string, data []byte) error { return atomicWrite(path, data) }
