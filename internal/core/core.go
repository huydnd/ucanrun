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
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/huydnd/ucanrun/internal/audit"
	"github.com/huydnd/ucanrun/internal/policy"
	"github.com/huydnd/ucanrun/internal/telegram"
	"github.com/huydnd/ucanrun/internal/totp"
	"github.com/huydnd/ucanrun/internal/vault"
)

const (
	secretTelegram = "_telegram_token"
	secretTOTP     = "_totp_secret"
	MinPassphrase  = 12
	maxPending     = 5
	maxHistory     = 200
)

var (
	ErrLocked     = errors.New("vault locked")
	ErrNotFound   = errors.New("not found")
	ErrForbidden  = errors.New("forbidden")
	ErrBusy       = errors.New("too many pending requests")
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
	Result    *policy.Result    `json:"result,omitempty"`

	action *policy.Action
	done   chan struct{}
}

type Options struct {
	DataDir     string
	ApprovalTTL time.Duration
	TelegramAPI string // override for tests
	WorkFactor  int
	Now         func() time.Time
}

type Core struct {
	opt   Options
	Vault *vault.Vault
	Audit *audit.Log

	mu       sync.Mutex
	st       *State // nil while locked
	reqs     map[string]*Request
	order    []string
	bot      *telegram.Bot
	botStop  context.CancelFunc
	pairCode string
	pairTill time.Time
	baseCtx  context.Context
	cancel   context.CancelFunc
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
	c := &Core{opt: opt, Vault: v, Audit: l, reqs: map[string]*Request{}, baseCtx: ctx, cancel: cancel}
	go c.expiryLoop(ctx)
	return c, nil
}

func (c *Core) Close() {
	c.cancel()
	c.Lock("shutdown")
}

func (c *Core) statePath() string { return filepath.Join(c.opt.DataDir, "state.json") }

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

func (c *Core) saveLocked() error {
	k, err := c.Vault.MACKey()
	if err != nil {
		return ErrLocked
	}
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
	c.st = &State{Profiles: map[string]policy.Profile{}, Tokens: map[string]Token{}}
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
	c.mu.Lock()
	defer c.mu.Unlock()
	wasLocked := c.st == nil
	if wasLocked {
		if err := c.Vault.Unlock(pass); err != nil {
			return err
		}
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
	} else if err := c.Vault.Verify(pass); err != nil {
		return err
	}
	if c.st.TOTPEnabled {
		if err := c.checkTOTPLocked(code); err != nil {
			if wasLocked {
				c.st = nil
				c.Vault.Lock()
			}
			c.log("login_failed", "web", map[string]any{"why": "totp"})
			return err
		}
	}
	if wasLocked {
		c.startBotLocked()
	}
	c.log("login", "web", nil)
	return nil
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
	c.st = nil
	c.Vault.Lock()
	c.log("lock", actor, nil)
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
		UserID: c.st.Telegram.UserID, ChatID: c.st.Telegram.ChatID}, c)
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
	c.pairCode, c.pairTill = randHex(8), c.opt.Now().Add(10*time.Minute)
	c.startBotLocked()
	c.log("telegram_set", "web", map[string]any{"bot": u})
	return u, c.pairCode, nil
}

func (c *Core) NewPairCode() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bot == nil {
		return "", errors.New("chưa cấu hình bot")
	}
	c.pairCode, c.pairTill = randHex(8), c.opt.Now().Add(10*time.Minute)
	return c.pairCode, nil
}

// Pair implements telegram.Handler. The code is single use.
func (c *Core) Pair(code string, userID, chatID int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil || c.pairCode == "" || c.opt.Now().After(c.pairTill) ||
		subtle.ConstantTimeCompare([]byte(code), []byte(c.pairCode)) != 1 {
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
	return secret, totp.URI(secret, "huydnd"), nil
}

func (c *Core) TOTPConfirm(code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return ErrLocked
	}
	if err := c.checkTOTPLocked(code); err != nil {
		return err
	}
	c.st.TOTPEnabled = true
	c.log("totp_enabled", "web", nil)
	return c.saveLocked()
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

func (c *Core) PutProfile(p policy.Profile) error {
	if err := p.Validate(); err != nil {
		return err
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
	r := &Request{ID: randHex(6), Profile: profile, Params: params, Caller: t.Name,
		Reason: cleanReason(reason), Risk: p.Risk, Hash: policy.Hash(&p, a, t.Name), Display: a.Display(),
		State: Pending, Created: now, Expires: now.Add(c.opt.ApprovalTTL), action: a, done: make(chan struct{})}
	c.reqs[r.ID] = r
	c.order = append(c.order, r.ID)
	c.trimLocked()
	c.log("request", t.Name, map[string]any{"id": r.ID, "profile": profile, "params": params, "hash": r.Hash, "reason": r.Reason})
	if p.AutoApprove {
		c.startLocked(r, "auto")
		return r.public(), nil
	}
	if bot := c.bot; bot != nil && c.st.Telegram.UserID != 0 {
		id, short, text := r.ID, r.Hash[:16], approvalText(r)
		go func() {
			if err := bot.Notify(c.baseCtx, id, short, text); err != nil {
				slog.Warn("telegram notify", "err", err)
			}
		}()
	}
	return r.public(), nil
}

func approvalText(r *Request) string {
	var b strings.Builder
	head := "Yêu cầu chạy lệnh"
	if r.Risk == policy.RiskHigh {
		head = "⚠️ RỦI RO CAO, cần TOTP"
	}
	fmt.Fprintf(&b, "%s\n\nProfile: %s\nAgent: %s\nHết hạn sau: %.0f giây\n\nLệnh sẽ chạy:\n%s\n", head, r.Profile, r.Caller, r.Expires.Sub(r.Created).Seconds(), r.Display)
	if r.Reason != "" {
		fmt.Fprintf(&b, "\nLý do (agent tự khai, chưa kiểm chứng): %s\n", r.Reason)
	}
	fmt.Fprintf(&b, "\nMã: %s", r.Hash[:8])
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
		id, text := r.ID, fmt.Sprintf("Kết thúc: %s (%s)\nProfile: %s\nMã: %s", s, by, r.Profile, r.Hash[:8])
		go bot.Finish(c.baseCtx, id, text)
	}
}

func (c *Core) NeedsTOTP(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.reqs[id]
	return ok && r.Risk == policy.RiskHigh
}

// Decide applies one human decision. hash may be a prefix of at least 16 hex
// characters, because Telegram callback data is limited to 64 bytes.
func (c *Core) Decide(id, hash string, approve bool, actor, code string) (string, error) {
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
	if r.Risk == policy.RiskHigh {
		if !c.st.TOTPEnabled {
			return "", errors.New("chưa bật TOTP nên chưa duyệt được yêu cầu rủi ro cao")
		}
		if err := c.checkTOTPLocked(code); err != nil {
			c.log("decide_totp_failed", actor, map[string]any{"id": id})
			return "", err
		}
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
