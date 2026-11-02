package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"time"

	"ucanrun/internal/policy"
	"ucanrun/internal/vault"
)

// Token authorizes an agent. Only the SHA-256 of the value is stored.
type Token struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Hash     string    `json:"hash"`
	Profiles []string  `json:"profiles,omitempty"` // empty means all profiles
	Created  time.Time `json:"created"`
}

type TelegramCfg struct {
	UserID int64 `json:"user_id"`
	ChatID int64 `json:"chat_id"`
}

// State is authenticated with a key derived from the vault identity, so someone
// who can write the data directory but lacks the passphrase cannot add a profile
// or a token.
type State struct {
	Profiles     map[string]policy.Profile `json:"profiles"`
	Tokens       map[string]Token          `json:"tokens"`
	Telegram     TelegramCfg               `json:"telegram"`
	TOTPEnabled  bool                      `json:"totp_enabled"`
	LastTOTPStep int64                     `json:"last_totp_step"`
	// RecoveryHashes are SHA-256 of single-use recovery codes. The codes carry
	// 50 random bits, so a fast hash is enough.
	RecoveryHashes []string `json:"recovery_hashes,omitempty"`
}

type signedFile struct {
	MAC  string          `json:"mac"`
	Data json.RawMessage `json:"data"`
}

func mac(key, data []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}

func saveState(path string, st *State, key []byte) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(signedFile{MAC: mac(key, data), Data: data})
	if err != nil {
		return err
	}
	return vault.AtomicWrite(path, raw)
}

var ErrTampered = errors.New("state file failed authentication")

func loadState(path string, key []byte) (*State, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrTampered // Setup always writes it, so absence is not normal
	}
	if err != nil {
		return nil, err
	}
	var f signedFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, ErrTampered
	}
	if !hmac.Equal([]byte(f.MAC), []byte(mac(key, f.Data))) {
		return nil, ErrTampered
	}
	st := &State{}
	if err := json.Unmarshal(f.Data, st); err != nil {
		return nil, err
	}
	if st.Profiles == nil {
		st.Profiles = map[string]policy.Profile{}
	}
	if st.Tokens == nil {
		st.Tokens = map[string]Token{}
	}
	return st, nil
}
