// Package core ties the vault, policy, approval channels and audit log together.
package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"ucanrun/internal/audit"
	"ucanrun/internal/policy"
	"ucanrun/internal/telegram"
	"ucanrun/internal/totp"
	"ucanrun/internal/vault"
)

const (
	secretTelegram = "_telegram_token"
	secretTOTP     = "_totp_secret"
	MinPassphrase  = 12
	maxPending     = 5
	rateWindow     = 10 * time.Minute
	rateMax        = 30
	maxDisplay     = 3000
	maxPairFails   = 3
	pairTTL        = 3 * time.Minute
	pairLetters    = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
	pairSymbols    = "#$%&+=?!"
	maxHistory     = 200
)

var (
	ErrLocked     = errors.New("vault locked")
	ErrNotFound   = errors.New("not found")
	ErrForbidden  = errors.New("forbidden")
	ErrBusy       = errors.New("too many pending requests")
	ErrLoginBusy  = errors.New("login in progress")
	ErrExecOff    = errors.New("chạy lệnh đang tắt, đặt UCANRUN_ENABLE_EXEC=1 và dùng image exec")
	ErrBadTOTP    = errors.New("sai mã TOTP")
	ErrNeedTOTP   = errors.New("cần mã TOTP")
	ErrDecided    = errors.New("yêu cầu đã được xử lý hoặc hết hạn")
	ErrHashChange = errors.New("yêu cầu không khớp")
)

type ReqState string

const (
	Pending ReqState = "pending"
	Denied  ReqState = "denied"
	Expired ReqState = "expired"
	Running ReqState = "running"
	Done    ReqState = "done"
	Failed  ReqState = "failed"
)

type Request struct {
	ID        string            `json:"id"`
	Profile   string            `json:"profile"`
	Params    map[string]string `json:"params,omitempty"`
	Caller    string            `json:"caller"`
	Reason    string            `json:"reason,omitempty"`
	Risk      string            `json:"risk"`
	Hash      string            `json:"hash"`
	Display   string            `json:"display"`
	State     ReqState          `json:"state"`
	Created   time.Time         `json:"created"`
	Expires   time.Time         `json:"expires"`
	DecidedBy string            `json:"decided_by,omitempty"`
	Choices   []string          `json:"choices,omitempty"`
	Secret    string            `json:"secret,omitempty"`
	Result    *policy.Result    `json:"result,omitempty"`

	action *policy.Action
	done   chan struct{}
}

type Options struct {
	DataDir     string
	ApprovalTTL time.Duration
	TelegramAPI string // override for tests
	WorkFactor  int
	// AllowExec permits profiles that run programs. Off by default: the default
	// image only calls APIs.
	AllowExec bool
	// Lang is "vi" or "en" for Telegram messages. Empty means English.
	Lang string
	Now  func() time.Time
}

type Core struct {
	opt   Options
	Vault *vault.Vault
	Audit *audit.Log

	mu        sync.Mutex
	st        *State // nil while locked
	auditCut  bool
	reqs      map[string]*Request
	order     []string
	bot       *telegram.Bot
	botStop   context.CancelFunc
	pairCode  string
	pairTill  time.Time
	pairFails int
	loginMu   sync.Mutex
	recent    map[string][]time.Time
	baseCtx   context.Context
	cancel    context.CancelFunc
}

func New(opt Options) (*Core, error) {
	if opt.ApprovalTTL == 0 {
		opt.ApprovalTTL = 2 * time.Minute
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	v := vault.New(filepath.Join(opt.DataDir, "vault"))
	v.WorkFactor = opt.WorkFactor
	if err := vault.AtomicWrite(filepath.Join(opt.DataDir, ".keep"), nil); err != nil {
		return nil, err
	}
	l, err := audit.Open(filepath.Join(opt.DataDir, "audit.jsonl"))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Core{opt: opt, Vault: v, Audit: l, reqs: map[string]*Request{}, recent: map[string][]time.Time{}, baseCtx: ctx, cancel: cancel}
	go c.expiryLoop(ctx)
	return c, nil
}

func (c *Core) Close() {
	c.cancel()
	c.Lock("shutdown")
}

func (c *Core) statePath() string { return filepath.Join(c.opt.DataDir, "state.json") }
func (c *Core) auditPath() string { return filepath.Join(c.opt.DataDir, "audit.jsonl") }

func (c *Core) AuditTruncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.auditCut
}

func (c *Core) log(event, actor string, f map[string]any) {
	if err := c.Audit.Append(event, actor, f); err != nil {
		slog.Error("audit append", "err", err)
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// saveLocked anchors the current audit head in state; entries written after the
// last save are not covered until the next save or Lock.
func (c *Core) saveLocked() error {
	k, err := c.Vault.MACKey()
	if err != nil {
		return ErrLocked
	}
	c.st.AuditCount, c.st.AuditHash = c.Audit.Head()
	return saveState(c.statePath(), c.st, k)
}

// Setup creates the vault and first state.
func (c *Core) Setup(pass []byte) error {
	if len(pass) < MinPassphrase {
		return fmt.Errorf("mật khẩu chính cần ít nhất %d ký tự", MinPassphrase)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.Vault.Init(pass); err != nil {
		return err
	}
	c.st = &State{Version: currentStateVersion, Profiles: map[string]policy.Profile{}, Tokens: map[string]Token{}}
	if err := c.saveLocked(); err != nil {
		return err
	}
	c.log("setup", "web", nil)
	return nil
}

func (c *Core) Locked() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st == nil
}

// Login verifies the passphrase and, once enrolled, TOTP. If the vault was
// locked it unlocks, and stays locked again when TOTP fails.
func (c *Core) Login(pass []byte, code string) error {
	// scrypt takes a second and 256 MiB. One at a time, and outside c.mu, so
	// anonymous logins can neither exhaust memory nor stall approvals.
	if !c.loginMu.TryLock() {
		return ErrLoginBusy
	}
	defer c.loginMu.Unlock()
	id, err := c.Vault.Open(pass)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	wasLocked := c.st == nil
	var auditCount int
	var auditHash string
	if wasLocked {
		c.Vault.Adopt(id)
		k, err := c.Vault.MACKey()
		if err == nil {
			c.st, err = loadState(c.statePath(), k)
		}
		if err != nil {
			c.st = nil
			c.Vault.Lock()
			c.log("state_tamper", "web", nil)
			return err
		}
		auditCount, auditHash = c.st.AuditCount, c.st.AuditHash
	}
	if c.st.TOTPEnabled {
		if err := c.checkSecondFactorLocked(code); err != nil {
			if wasLocked {
				c.st = nil
				c.Vault.Lock()
			}
			c.log("login_failed", "web", map[string]any{"why": "totp"})
			return err
		}
	}
	if wasLocked {
		if ok, err := audit.Contains(c.auditPath(), auditCount, auditHash); err != nil || !ok {
			c.auditCut = true
			c.log("audit_truncated", "web", map[string]any{"count": auditCount})
		}
		c.startBotLocked()
	}
	c.log("login", "web", nil)
	return nil
}

// checkSecondFactorLocked accepts a TOTP code or a single-use recovery code.
func (c *Core) checkSecondFactorLocked(code string) error {
	if len(code) == 6 {
		return c.checkTOTPLocked(code)
	}
	if c.useRecoveryLocked(code) {
		c.log("recovery_code_used", "web", map[string]any{"left": len(c.st.RecoveryHashes)})
		return c.saveLocked()
	}
	if code == "" {
		return ErrNeedTOTP
	}
	return ErrBadTOTP
}

const recoveryAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

func normalizeRecovery(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(s))
}

func hashRecovery(s string) string {
	h := sha256.Sum256([]byte("ucanrun recovery v1:" + normalizeRecovery(s)))
	return hex.EncodeToString(h[:])
}

// newRecoveryCodes returns eight codes shown once, and their hashes.
func newRecoveryCodes() (plain, hashes []string, err error) {
	for range 8 {
		b := make([]byte, 10)
		for i := range b {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(recoveryAlphabet))))
			if err != nil {
				return nil, nil, err
			}
			b[i] = recoveryAlphabet[n.Int64()]
		}
		code := string(b[:5]) + "-" + string(b[5:])
		plain, hashes = append(plain, code), append(hashes, hashRecovery(code))
	}
	return plain, hashes, nil
}

func (c *Core) useRecoveryLocked(code string) bool {
	if len(normalizeRecovery(code)) != 10 {
		return false
	}
	h := hashRecovery(code)
	for i, v := range c.st.RecoveryHashes {
		if subtle.ConstantTimeCompare([]byte(v), []byte(h)) == 1 {
			c.st.RecoveryHashes = append(c.st.RecoveryHashes[:i:i], c.st.RecoveryHashes[i+1:]...)
			return true
		}
	}
	return false
}

// RecoveryLeft reports how many unused recovery codes remain.
func (c *Core) RecoveryLeft() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return 0
	}
	return len(c.st.RecoveryHashes)
}

// NewRecoveryCodes replaces all codes. A TOTP code proves the phone is in hand.
func (c *Core) NewRecoveryCodes(code string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return nil, ErrLocked
	}
	if !c.st.TOTPEnabled {
		return nil, errors.New("chưa bật TOTP")
	}
	if err := c.checkTOTPLocked(code); err != nil {
		return nil, err
	}
	plain, hashes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	c.st.RecoveryHashes = hashes
	c.log("recovery_codes_created", "web", nil)
	return plain, c.saveLocked()
}

// TOTPReset turns TOTP off so a new phone can enroll. It needs the passphrase and
// a current TOTP or recovery code, so a stolen session alone cannot do it.
func (c *Core) TOTPReset(pass []byte, code string) error {
	if !c.loginMu.TryLock() {
		return ErrLoginBusy
	}
	defer c.loginMu.Unlock()
	if err := c.Vault.Verify(pass); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return ErrLocked
	}
	if err := c.checkSecondFactorLocked(code); err != nil {
		return err
	}
	c.st.TOTPEnabled, c.st.RecoveryHashes, c.st.LastTOTPStep = false, nil, 0
	c.log("totp_reset", "web", nil)
	return c.saveLocked()
}

func (c *Core) checkTOTPLocked(code string) error {
	if code == "" {
		return ErrNeedTOTP
	}
	sec, err := c.Vault.Get(secretTOTP)
	if err != nil {
		return err
	}
	step := totp.Verify(string(sec), code, c.opt.Now(), c.st.LastTOTPStep)
	if step == 0 {
		return ErrBadTOTP
	}
	c.st.LastTOTPStep = step
	return c.saveLocked()
}

// Lock wipes the key from memory and denies everything in flight.
func (c *Core) Lock(actor string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return
	}
	for _, r := range c.reqs {
		if r.State == Pending {
			c.finishLocked(r, Denied, "lock")
		}
	}
	c.stopBotLocked()
	c.log("lock", actor, nil)
	if err := c.saveLocked(); err != nil {
		slog.Error("state save", "err", err)
	}
	c.st = nil
	c.Vault.Lock()
}

func (c *Core) stopBotLocked() {
	if c.botStop != nil {
		c.botStop()
		c.botStop = nil
	}
	c.bot = nil
}

func (c *Core) startBotLocked() {
	c.stopBotLocked()
	tok, err := c.Vault.Get(secretTelegram)
	if err != nil {
		return
	}
	bot := telegram.New(telegram.Config{BaseURL: c.opt.TelegramAPI, Token: string(tok),
		UserID: c.st.Telegram.UserID, ChatID: c.st.Telegram.ChatID, Translate: c.Translate}, c)
	ctx, cancel := context.WithCancel(c.baseCtx)
	c.bot, c.botStop = bot, cancel
	go bot.Run(ctx)
}

// --- Telegram configuration ---

type TelegramStatus struct {
	Configured bool  `json:"configured"`
	Paired     bool  `json:"paired"`
	UserID     int64 `json:"user_id,omitempty"`
}

func (c *Core) TelegramStatus() TelegramStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return TelegramStatus{}
	}
	return TelegramStatus{Configured: c.bot != nil, Paired: c.st.Telegram.UserID != 0, UserID: c.st.Telegram.UserID}
}

// SetTelegramToken checks the token, stores it encrypted, and returns the bot
// name and a pairing code. Changing the bot clears the pairing.
func (c *Core) SetTelegramToken(ctx context.Context, token string) (string, string, error) {
	u, err := telegram.New(telegram.Config{BaseURL: c.opt.TelegramAPI, Token: token}, nil).Check(ctx)
	if err != nil {
		return "", "", errors.New("token Telegram không hợp lệ hoặc không kết nối được")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return "", "", ErrLocked
	}
	if err := c.Vault.Put(secretTelegram, []byte(token)); err != nil {
		return "", "", err
	}
	c.st.Telegram = TelegramCfg{}
	if err := c.saveLocked(); err != nil {
		return "", "", err
	}
	c.pairCode, c.pairTill, c.pairFails = newPairCode(), c.opt.Now().Add(pairTTL), 0
	c.startBotLocked()
	c.log("telegram_set", "web", map[string]any{"bot": u})
	return u, c.pairCode, nil
}

// newPairCode returns six characters with one symbol at a random position. The
// alphabet skips lookalikes and characters Telegram treats as formatting.
func newPairCode() string {
	pick := func(set string) byte {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			panic(err)
		}
		return set[n.Int64()]
	}
	all := pairLetters + pairSymbols
	code := make([]byte, 6)
	for i := range code {
		code[i] = pick(all)
	}
	pos, err := rand.Int(rand.Reader, big.NewInt(6))
	if err != nil {
		panic(err)
	}
	code[pos.Int64()] = pick(pairSymbols)
	return string(code)
}

func (c *Core) NewPairCode() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bot == nil {
		return "", errors.New("chưa cấu hình bot")
	}
	c.pairCode, c.pairTill, c.pairFails = newPairCode(), c.opt.Now().Add(pairTTL), 0
	return c.pairCode, nil
}

// Pair implements telegram.Handler. The code is single use.
func (c *Core) Pair(code string, userID, chatID int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil || c.pairCode == "" || c.opt.Now().After(c.pairTill) {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(code), []byte(c.pairCode)) != 1 {
		// Six characters are only safe with very few guesses, and anyone on
		// Telegram can message the bot.
		if c.pairFails++; c.pairFails >= maxPairFails {
			c.pairCode = ""
			c.log("pair_code_burned", "telegram", nil)
		}
		return false
	}
	c.pairCode = ""
	c.st.Telegram = TelegramCfg{UserID: userID, ChatID: chatID}
	if err := c.saveLocked(); err != nil {
		return false
	}
	c.log("telegram_paired", "telegram", map[string]any{"user": userID})
	return true
}

// --- TOTP enrollment ---

func (c *Core) TOTPStart() (secret, uri string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return "", "", ErrLocked
	}
	if c.st.TOTPEnabled {
		return "", "", errors.New("TOTP đã bật")
	}
	if secret, err = totp.Generate(); err != nil {
		return
	}
	if err = c.Vault.Put(secretTOTP, []byte(secret)); err != nil {
		return
	}
	return secret, totp.URI(secret, "owner"), nil
}

// TOTPConfirm finishes enrollment and returns recovery codes, shown once.
func (c *Core) TOTPConfirm(code string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return nil, ErrLocked
	}
	if err := c.checkTOTPLocked(code); err != nil {
		return nil, err
	}
	plain, hashes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	c.st.TOTPEnabled, c.st.RecoveryHashes = true, hashes
	c.log("totp_enabled", "web", nil)
	return plain, c.saveLocked()
}

func (c *Core) TOTPEnabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st != nil && c.st.TOTPEnabled
}

// --- Profiles and tokens ---

func (c *Core) Profiles() ([]policy.Profile, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return nil, ErrLocked
	}
	out := make([]policy.Profile, 0, len(c.st.Profiles))
	for _, p := range c.st.Profiles {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ExecEnabled reports whether profiles may run programs.
func (c *Core) ExecEnabled() bool { return c.opt.AllowExec }

func (c *Core) PutProfile(p policy.Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.Exec != nil && !c.opt.AllowExec {
		return ErrExecOff
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return ErrLocked
	}
	c.st.Profiles[p.Name] = p
	c.log("profile_put", "web", map[string]any{"name": p.Name, "risk": p.Risk})
	return c.saveLocked()
}

func (c *Core) DeleteProfile(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return ErrLocked
	}
	delete(c.st.Profiles, name)
	c.log("profile_delete", "web", map[string]any{"name": name})
	return c.saveLocked()
}

func (c *Core) Tokens() ([]Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return nil, ErrLocked
	}
	out := make([]Token, 0, len(c.st.Tokens))
	for _, t := range c.st.Tokens {
		t.Hash = ""
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

// CreateToken returns the value once; only its hash is kept.
func (c *Core) CreateToken(name string, profiles []string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return "", errors.New("tên token không hợp lệ")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return "", ErrLocked
	}
	for _, t := range c.st.Tokens {
		if t.Name == name {
			return "", errors.New("tên token đã tồn tại") // the name is the caller identity
		}
	}
	val := "ucr_" + randHex(32)
	s := sha256.Sum256([]byte(val))
	id := randHex(4)
	c.st.Tokens[id] = Token{ID: id, Name: name, Hash: hex.EncodeToString(s[:]), Profiles: profiles, Created: c.opt.Now().UTC()}
	c.log("token_create", "web", map[string]any{"id": id, "name": name})
	return val, c.saveLocked()
}

func (c *Core) RevokeToken(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return ErrLocked
	}
	delete(c.st.Tokens, id)
	c.log("token_revoke", "web", map[string]any{"id": id})
	return c.saveLocked()
}

// Authenticate resolves a bearer token to its record.
func (c *Core) Authenticate(val string) (Token, error) {
	s := sha256.Sum256([]byte(val))
	h := hex.EncodeToString(s[:])
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return Token{}, ErrLocked
	}
	for _, t := range c.st.Tokens {
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(h)) == 1 {
			return t, nil
		}
	}
	return Token{}, ErrForbidden
}

func allowed(t Token, profile string) bool {
	if len(t.Profiles) == 0 {
		return true
	}
	for _, p := range t.Profiles {
		if p == profile {
			return true
		}
	}
	return false
}

// ProfilesFor lists what a token may see, without templates or hosts.
func (c *Core) ProfilesFor(t Token) ([]policy.Profile, error) {
	all, err := c.Profiles()
	if err != nil {
		return nil, err
	}
	out := []policy.Profile{}
	for _, p := range all {
		if allowed(t, p.Name) {
			out = append(out, policy.Profile{Name: p.Name, Description: p.Description, Risk: p.Risk, Params: p.Params, AutoApprove: p.AutoApprove})
		}
	}
	return out, nil
}

// --- Requests ---

func cleanReason(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == 0x0a || r == 0x20 {
			return ' '
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

func (r Request) public() Request {
	r.action, r.done = nil, nil
	return r
}

// Submit validates a request and either starts it or queues it for approval.
func (c *Core) Submit(t Token, profile string, params map[string]string, reason string) (Request, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return Request{}, ErrLocked
	}
	if !allowed(t, profile) {
		c.log("request_forbidden", t.Name, map[string]any{"profile": profile})
		return Request{}, ErrForbidden
	}
	p, ok := c.st.Profiles[profile]
	if !ok {
		return Request{}, ErrNotFound
	}
	if p.Exec != nil && !c.opt.AllowExec {
		return Request{}, ErrExecOff
	}
	a, err := p.Render(params)
	if err != nil {
		return Request{}, err
	}
	pending := 0
	for _, r := range c.reqs {
		if r.State == Pending && r.Caller == t.Name {
			pending++
		}
	}
	if pending >= maxPending {
		return Request{}, ErrBusy
	}
	now := c.opt.Now()
	kept := c.recent[t.Name][:0]
	for _, at := range c.recent[t.Name] {
		if now.Sub(at) < rateWindow {
			kept = append(kept, at)
		}
	}
	if len(kept) >= rateMax {
		c.recent[t.Name] = kept
		return Request{}, ErrBusy // floods train a human to approve without reading
	}
	c.recent[t.Name] = append(kept, now)
	r := &Request{ID: randHex(6), Profile: profile, Params: params, Caller: t.Name,
		Reason: cleanReason(reason), Risk: p.Risk, Hash: policy.Hash(&p, a, t.Name), Display: a.Display(),
		Choices: p.SecretChoices, State: Pending, Created: now, Expires: now.Add(c.opt.ApprovalTTL), action: a, done: make(chan struct{})}
	c.reqs[r.ID] = r
	c.order = append(c.order, r.ID)
	c.trimLocked()
	// Nothing runs unless it was recorded first.
	if err := c.Audit.Append("request", t.Name, map[string]any{"id": r.ID, "profile": profile, "params": params, "hash": r.Hash, "reason": r.Reason}); err != nil {
		slog.Error("audit append", "err", err)
		c.finishLocked(r, Failed, "audit")
		return Request{}, errors.New("cannot record the request")
	}
	if p.AutoApprove {
		c.startLocked(r, "auto")
		return r.public(), nil
	}
	if bot := c.bot; bot != nil && c.st.Telegram.UserID != 0 {
		id, short, text, choices := r.ID, r.Hash[:16], approvalText(r, c.opt.Lang == "vi"), r.Choices
		go func() {
			if err := bot.Notify(c.baseCtx, id, short, text, choices); err != nil {
				slog.Warn("telegram notify", "err", err)
				c.log("notify_failed", "telegram", map[string]any{"id": id})
			}
		}()
	}
	return r.public(), nil
}

func approvalText(r *Request, vi bool) string {
	l := map[string]string{"head": "Approval request", "high": "⚠️ HIGH RISK, needs TOTP", "agent": "Agent", "exp": "Expires in", "sec": "seconds", "cmd": "Command to run", "cut": "… [SHORTENED, read it all on the web before approving]",
		"why": "Reason (stated by the agent, unverified)", "pick": "Tap the secret to use this time.", "code": "Code"}
	if vi {
		l = map[string]string{"head": "Yêu cầu chạy lệnh", "high": "⚠️ RỦI RO CAO, cần TOTP", "agent": "Agent", "exp": "Hết hạn sau", "sec": "giây", "cmd": "Lệnh sẽ chạy", "cut": "… [ĐÃ CẮT BỚT, xem đủ trên web trước khi duyệt]",
			"why": "Lý do (agent tự khai, chưa kiểm chứng)", "pick": "Bấm tên secret muốn dùng cho lần này.", "code": "Mã"}
	}
	var b strings.Builder
	head := l["head"]
	if r.Risk == policy.RiskHigh {
		head = l["high"]
	}
	// Telegram drops messages over 4096 characters, which would leave the
	// request invisible. Say so plainly when text is cut.
	shown := r.Display
	if rs := []rune(shown); len(rs) > maxDisplay {
		shown = string(rs[:maxDisplay]) + "\n" + l["cut"]
	}
	fmt.Fprintf(&b, "%s\n\nProfile: %s\n%s: %s\n%s: %.0f %s\n\n%s:\n%s\n", head, r.Profile, l["agent"], r.Caller, l["exp"], r.Expires.Sub(r.Created).Seconds(), l["sec"], l["cmd"], shown)
	if r.Reason != "" {
		fmt.Fprintf(&b, "\n%s: %s\n", l["why"], r.Reason)
	}
	if len(r.Choices) > 0 {
		fmt.Fprintf(&b, "\n%s\n", l["pick"])
	}
	fmt.Fprintf(&b, "\n%s: %s", l["code"], r.Hash[:8])
	return b.String()
}

func (c *Core) trimLocked() {
	for len(c.order) > maxHistory {
		id := c.order[0]
		if r := c.reqs[id]; r != nil && (r.State == Pending || r.State == Running) {
			break
		}
		c.order = c.order[1:]
		delete(c.reqs, id)
	}
}

func (c *Core) finishLocked(r *Request, s ReqState, by string) {
	r.State, r.DecidedBy = s, by
	close(r.done)
	c.log("request_"+string(s), by, map[string]any{"id": r.ID, "hash": r.Hash})
	if bot := c.bot; bot != nil {
		label, usedLabel, codeLabel := "Finished", "Secret used", "Code"
		if c.opt.Lang == "vi" {
			label, usedLabel, codeLabel = "Kết thúc", "Secret đã dùng", "Mã"
		}
		used := ""
		if r.Secret != "" {
			used = "\n" + usedLabel + ": " + r.Secret
		}
		id, text := r.ID, fmt.Sprintf("%s: %s (%s)\nProfile: %s%s\n%s: %s", label, s, by, r.Profile, used, codeLabel, r.Hash[:8])
		go bot.Finish(c.baseCtx, id, text)
	}
}

func (c *Core) NeedsTOTP(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.reqs[id]
	return ok && r.Risk == policy.RiskHigh
}

// SecretAt maps a Telegram button index to a secret name.
func (c *Core) SecretAt(id string, i int) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.reqs[id]
	if !ok || i < 0 || i >= len(r.Choices) {
		return "", false
	}
	return r.Choices[i], true
}

// Decide applies one human decision. hash may be a prefix of at least 16 hex
// characters, because Telegram callback data is limited to 64 bytes.
func (c *Core) Decide(id, hash string, approve bool, actor, code, secret string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.reqs[id]
	if !ok {
		return "", ErrDecided
	}
	if len(hash) < 16 || !strings.HasPrefix(r.Hash, hash) {
		c.log("decide_hash_mismatch", actor, map[string]any{"id": id})
		return "", ErrHashChange
	}
	if r.State != Pending || !c.opt.Now().Before(r.Expires) {
		return "", ErrDecided
	}
	if !approve {
		c.finishLocked(r, Denied, actor)
		return "Đã từ chối", nil
	}
	if len(r.Choices) > 0 {
		ok := false
		for _, n := range r.Choices {
			ok = ok || n == secret
		}
		if !ok {
			return "", errors.New("hãy chọn một secret trong danh sách")
		}
		if v, err := c.Vault.Get(secret); err != nil {
			return "", fmt.Errorf("kho chưa có secret %q", secret)
		} else {
			clear(v)
		}
	}
	if r.Risk == policy.RiskHigh {
		if !c.st.TOTPEnabled {
			return "", errors.New("chưa bật TOTP nên chưa duyệt được yêu cầu rủi ro cao")
		}
		if err := c.checkTOTPLocked(code); err != nil {
			c.log("decide_totp_failed", actor, map[string]any{"id": id})
			return "", err
		}
	}
	if len(r.Choices) > 0 {
		r.action, r.Secret = r.action.WithChoice(secret), secret
		c.log("secret_chosen", actor, map[string]any{"id": r.ID, "secret": secret})
	}
	c.startLocked(r, actor)
	return "Đã duyệt", nil
}

func (c *Core) startLocked(r *Request, by string) {
	r.State, r.DecidedBy = Running, by
	c.log("request_approved", by, map[string]any{"id": r.ID, "hash": r.Hash})
	go c.execute(r)
}

func (c *Core) execute(r *Request) {
	res := policy.Run(c.baseCtx, r.action, func(n string) ([]byte, error) {
		if strings.HasPrefix(n, "_") {
			return nil, ErrForbidden
		}
		return c.Vault.Get(n)
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	r.Result = &res
	s := Done
	if !res.OK {
		s = Failed
	}
	sum := sha256.Sum256([]byte(res.Output))
	by := r.DecidedBy
	c.finishLocked(r, s, by)
	c.log("result", by, map[string]any{"id": r.ID, "exit": res.Exit, "bytes": len(res.Output), "sha256": hex.EncodeToString(sum[:8])})
}

func (c *Core) expiryLoop(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			c.ExpireNow()
		}
	}
}

// ExpireNow denies overdue requests; silence is never approval.
func (c *Core) ExpireNow() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.opt.Now()
	for _, r := range c.reqs {
		if r.State == Pending && !now.Before(r.Expires) {
			c.finishLocked(r, Expired, "ttl")
		}
	}
}

// Get returns a snapshot. Wait blocks until a final state or the context ends.
func (c *Core) Get(id string) (Request, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.reqs[id]
	if !ok {
		return Request{}, false
	}
	return r.public(), true
}

func (c *Core) Wait(ctx context.Context, id string) (Request, bool) {
	c.mu.Lock()
	r, ok := c.reqs[id]
	c.mu.Unlock()
	if !ok {
		return Request{}, false
	}
	select {
	case <-r.done:
	case <-ctx.Done():
	}
	return c.Get(id)
}

func (c *Core) Requests() []Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Request, 0, len(c.reqs))
	for i := len(c.order) - 1; i >= 0; i-- {
		if r, ok := c.reqs[c.order[i]]; ok {
			out = append(out, r.public())
		}
	}
	return out
}

// Preview validates a draft and renders it with sample values, using the same
// code path as a real request. It runs nothing.
type Preview struct {
	Error    string   `json:"error,omitempty"`
	Display  string   `json:"display,omitempty"`
	Warnings []string `json:"warnings"`
}

func (c *Core) Preview(p policy.Profile, sample map[string]string) Preview {
	out := Preview{Warnings: []string{}}
	if err := p.Validate(); err != nil {
		out.Error = err.Error()
		return out
	}
	if p.Exec != nil && !c.opt.AllowExec {
		out.Error = ErrExecOff.Error()
		return out
	}
	out.Warnings = append(out.Warnings, p.Lint()...)
	a, err := p.Render(sample)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Display = a.Display()
	have := map[string]bool{}
	if l, err := c.Vault.List(); err == nil {
		for _, m := range l {
			have[m.Name] = true
		}
	}
	for _, n := range a.Secrets() {
		if !have[n] {
			out.Warnings = append(out.Warnings, "Chưa có secret \""+n+"\" trong kho, lệnh sẽ không chạy được.")
		}
	}
	return out
}
