// Package web serves the human UI and the agent API on separate listeners, so
// that the UI can be published without exposing the agent port.
package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"

	"ucanrun/internal/audit"
	"ucanrun/internal/core"
	"ucanrun/internal/policy"
	"ucanrun/internal/vault"
)

func init() { mime.AddExtensionType(".webmanifest", "application/manifest+json") }

//go:embed static
var staticFS embed.FS

const (
	cookieName  = "ucr_session"
	sessionIdle = 30 * time.Minute
	sessionMax  = 12 * time.Hour
	maxBody     = 256 << 10
)

type session struct{ created, seen time.Time }

type Server struct {
	C            *core.Core
	SecureCookie bool
	SetupToken   string
	AuditPath    string
	GateToken    string
	CatalogDir   string

	mu       sync.Mutex
	sessions map[string]*session
	fails    int
	blocked  time.Time
}

func New(c *core.Core, setupToken, auditPath string, secure bool) *Server {
	return &Server{C: c, SetupToken: setupToken, AuditPath: auditPath, SecureCookie: secure, sessions: map[string]*session{}}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	switch {
	case errors.Is(err, core.ErrLocked), errors.Is(err, vault.ErrLocked):
		code = http.StatusLocked
	case errors.Is(err, core.ErrForbidden):
		code = http.StatusForbidden
	case errors.Is(err, core.ErrNotFound), errors.Is(err, vault.ErrNotFound):
		code = http.StatusNotFound
	case errors.Is(err, core.ErrBusy), errors.Is(err, core.ErrLoginBusy):
		code = http.StatusTooManyRequests
	}
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func read(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "JSON không hợp lệ"})
		return false
	}
	return true
}

func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if s.SecureCookie {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// csrf blocks cross-site writes: a custom header cannot be sent cross-origin
// without a CORS preflight, and this server never answers one.
func csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			site := r.Header.Get("Sec-Fetch-Site")
			if r.Header.Get("X-Ucanrun") != "1" || (site != "" && site != "same-origin") {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func hashTok(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

func (s *Server) newSession(w http.ResponseWriter) {
	b := make([]byte, 32)
	rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	now := time.Now()
	s.mu.Lock()
	s.sessions[hashTok(tok)] = &session{created: now, seen: now}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true,
		Secure: s.SecureCookie, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionMax.Seconds())})
}

func (s *Server) authed(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	k := hashTok(c.Value)
	s.mu.Lock()
	defer s.mu.Unlock()
	se, ok := s.sessions[k]
	if !ok {
		return false
	}
	now := time.Now()
	if now.Sub(se.seen) > sessionIdle || now.Sub(se.created) > sessionMax {
		delete(s.sessions, k)
		return false
	}
	se.seen = now
	return true
}

func (s *Server) clearSessions() {
	s.mu.Lock()
	s.sessions = map[string]*session{}
	s.mu.Unlock()
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) || s.C.Locked() {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "chưa đăng nhập"})
			return
		}
		h(w, r)
	}
}

// throttle applies one global backoff, because behind a proxy every client
// shares an address and the attacker controls forwarded headers.
func (s *Server) throttled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Now().Before(s.blocked)
}

func (s *Server) recordLogin(ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok {
		s.fails, s.blocked = 0, time.Time{}
		return
	}
	s.fails++
	if s.fails >= 3 {
		d := time.Second << min(s.fails-3, 6)
		s.blocked = time.Now().Add(d)
	}
}

// Handler returns the human UI.
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	sub, _ := fs.Sub(staticFS, "static")
	m.HandleFunc("GET /catalog.json", s.catalog)
	m.Handle("GET /", http.FileServerFS(sub))
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]bool{"ok": true}) })
	m.HandleFunc("GET /api/status", s.status)
	m.HandleFunc("POST /api/setup", s.setup)
	m.HandleFunc("POST /api/login", s.login)
	m.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(cookieName); err == nil {
			s.mu.Lock()
			delete(s.sessions, hashTok(c.Value))
			s.mu.Unlock()
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	m.HandleFunc("POST /api/lock", s.auth(func(w http.ResponseWriter, _ *http.Request) {
		s.C.Lock("web")
		s.clearSessions()
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
	m.HandleFunc("POST /api/passphrase", s.auth(s.passphrase))
	m.HandleFunc("GET /api/secrets", s.auth(s.listSecrets))
	m.HandleFunc("PUT /api/secrets/{name}", s.auth(s.putSecret))
	m.HandleFunc("DELETE /api/secrets/{name}", s.auth(s.deleteSecret))
	m.HandleFunc("GET /api/profiles", s.auth(func(w http.ResponseWriter, _ *http.Request) {
		p, err := s.C.Profiles()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, p)
	}))
	m.HandleFunc("PUT /api/profiles", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var p policy.Profile
		if !read(w, r, &p) {
			return
		}
		if err := s.C.PutProfile(p); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, p)
	}))
	m.HandleFunc("POST /api/profiles/preview", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Profile policy.Profile    `json:"profile"`
			Sample  map[string]string `json:"sample"`
		}
		if !read(w, r, &in) {
			return
		}
		writeJSON(w, 200, s.C.Preview(in.Profile, in.Sample))
	}))
	m.HandleFunc("POST /api/profiles/{name}/test", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Params map[string]string `json:"params"`
			TOTP   string            `json:"totp"`
			Secret string            `json:"secret"`
		}
		if !read(w, r, &in) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		q, err := s.C.TestRun(ctx, r.PathValue("name"), in.Params, in.TOTP, in.Secret)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, q)
	}))
	m.HandleFunc("DELETE /api/profiles/{name}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		if err := s.C.DeleteProfile(r.PathValue("name")); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
	m.HandleFunc("GET /api/tokens", s.auth(func(w http.ResponseWriter, _ *http.Request) {
		t, err := s.C.Tokens()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, t)
	}))
	m.HandleFunc("POST /api/tokens", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Name     string   `json:"name"`
			Profiles []string `json:"profiles"`
		}
		if !read(w, r, &in) {
			return
		}
		v, err := s.C.CreateToken(in.Name, in.Profiles)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"token": v})
	}))
	m.HandleFunc("DELETE /api/tokens/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		if err := s.C.RevokeToken(r.PathValue("id")); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
	m.HandleFunc("GET /api/requests", s.auth(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.C.Requests()) }))
	m.HandleFunc("POST /api/requests/{id}/decide", s.auth(s.decide))
	m.HandleFunc("GET /api/audit", s.auth(s.auditLog))
	m.HandleFunc("GET /api/health", s.auth(s.health))
	m.HandleFunc("PUT /api/telegram", s.auth(s.setTelegram))
	m.HandleFunc("POST /api/telegram/pair", s.auth(func(w http.ResponseWriter, _ *http.Request) {
		c, err := s.C.NewPairCode()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"code": c})
	}))
	m.HandleFunc("POST /api/totp/start", s.auth(s.totpStart))
	m.HandleFunc("POST /api/totp/confirm", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Code string `json:"code"`
		}
		if !read(w, r, &in) {
			return
		}
		codes, err := s.C.TOTPConfirm(in.Code)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"recovery_codes": codes})
	}))
	m.HandleFunc("POST /api/totp/recovery", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Code string `json:"code"`
		}
		if !read(w, r, &in) {
			return
		}
		codes, err := s.C.NewRecoveryCodes(in.Code)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"recovery_codes": codes})
	}))
	m.HandleFunc("POST /api/totp/reset", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Passphrase string `json:"passphrase"`
			Code       string `json:"code"`
		}
		if !read(w, r, &in) {
			return
		}
		if s.throttled() {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "thử lại sau ít giây"})
			return
		}
		if err := s.C.TOTPReset([]byte(in.Passphrase), in.Code); err != nil {
			s.recordLogin(false)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sai mật khẩu hoặc mã"})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
	return s.gate(s.secure(csrf(m)))
}

type catalogEntry struct {
	Group   string         `json:"group"`
	GroupEn string         `json:"group_en,omitempty"`
	Title   string         `json:"title"`
	TitleEn string         `json:"title_en,omitempty"`
	Hint    string         `json:"hint"`
	HintEn  string         `json:"hint_en,omitempty"`
	Secrets []string       `json:"secrets"`
	Custom  bool           `json:"custom,omitempty"`
	Profile policy.Profile `json:"profile"`
}

func (s *Server) catalog(w http.ResponseWriter, _ *http.Request) {
	raw, _ := staticFS.ReadFile("static/catalog.json")
	var base []catalogEntry
	_ = json.Unmarshal(raw, &base)
	out := make([]catalogEntry, 0, len(base))
	seen := make(map[string]bool, len(base))
	for _, e := range base {
		if e.Secrets == nil {
			e.Secrets = []string{}
		}
		seen[e.Profile.Name] = true
		out = append(out, e)
	}
	if s.CatalogDir != "" {
		entries, err := os.ReadDir(s.CatalogDir)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				slog.Warn("reading catalog dir", "dir", s.CatalogDir, "reason", err)
			}
		} else {
			for _, d := range entries {
				if !strings.HasSuffix(d.Name(), ".json") || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
					continue
				}
				info, err := d.Info()
				if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
					continue
				}
				b, err := os.ReadFile(filepath.Join(s.CatalogDir, d.Name()))
				if err != nil || len(b) > 1<<20 {
					continue
				}
				var extra []catalogEntry
				if err := json.Unmarshal(b, &extra); err != nil {
					slog.Warn("skipping catalog file", "file", d.Name(), "reason", err)
					continue
				}
				for _, e := range extra {
					if err := e.Profile.Validate(); err != nil {
						slog.Warn("skipping catalog entry", "file", d.Name(), "profile", e.Profile.Name, "reason", err)
						continue
					}
					if seen[e.Profile.Name] {
						slog.Warn("skipping duplicate catalog entry", "file", d.Name(), "profile", e.Profile.Name, "reason", "duplicate profile name")
						continue
					}
					if e.Secrets == nil {
						e.Secrets = []string{}
					}
					seen[e.Profile.Name] = true
					out = append(out, e)
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"initialized": s.C.Vault.Initialized(), "locked": s.C.Locked(), "authed": s.authed(r) && !s.C.Locked()}
	if out["authed"] == true {
		out["telegram"] = s.C.TelegramStatus()
		out["totp"] = s.C.TOTPEnabled()
		out["exec"] = s.C.ExecEnabled()
		out["recovery_left"] = s.C.RecoveryLeft()
	}
	writeJSON(w, 200, out)
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SetupToken string `json:"setup_token"`
		Passphrase string `json:"passphrase"`
	}
	if !read(w, r, &in) {
		return
	}
	if s.C.Vault.Initialized() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "đã khởi tạo"})
		return
	}
	if s.SetupToken == "" || subtle.ConstantTimeCompare([]byte(in.SetupToken), []byte(s.SetupToken)) != 1 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "sai setup token"})
		return
	}
	if err := s.C.Setup([]byte(in.Passphrase)); err != nil {
		fail(w, err)
		return
	}
	s.newSession(w)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Passphrase string `json:"passphrase"`
		TOTP       string `json:"totp"`
	}
	if !read(w, r, &in) {
		return
	}
	if s.throttled() {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "thử lại sau ít giây"})
		return
	}
	if len(in.Passphrase) > 1024 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sai thông tin đăng nhập"})
		return
	}
	err := s.C.Login([]byte(in.Passphrase), in.TOTP)
	if errors.Is(err, core.ErrLoginBusy) {
		fail(w, err)
		return
	}
	if err != nil {
		s.recordLogin(false)
		if errors.Is(err, core.ErrStateTooNew) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "dữ liệu tạo bởi bản mới hơn, hãy nâng cấp ucanrun"})
			return
		}
		if errors.Is(err, core.ErrTampered) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "file trạng thái không qua được kiểm tra toàn vẹn"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sai thông tin đăng nhập"})
		return
	}
	s.recordLogin(true)
	s.newSession(w)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) passphrase(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if !read(w, r, &in) {
		return
	}
	if len(in.New) < core.MinPassphrase {
		writeJSON(w, 400, map[string]string{"error": "mật khẩu mới quá ngắn"})
		return
	}
	if err := s.C.Vault.ChangePassphrase([]byte(in.Old), []byte(in.New)); err != nil {
		writeJSON(w, 400, map[string]string{"error": "mật khẩu cũ không đúng"})
		return
	}
	s.C.Audit.Append("passphrase_changed", "web", nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) listSecrets(w http.ResponseWriter, _ *http.Request) {
	l, err := s.C.Vault.List()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, l)
}

// putSecret is write-only by design: no endpoint ever returns a secret value.
func (s *Server) putSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if strings.HasPrefix(name, "_") {
		fail(w, vault.ErrInvalidName)
		return
	}
	var in struct {
		Value string `json:"value"`
	}
	if !read(w, r, &in) {
		return
	}
	if err := s.C.Vault.Put(name, []byte(in.Value)); err != nil {
		fail(w, err)
		return
	}
	s.C.Audit.Append("secret_put", "web", map[string]any{"name": name})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if strings.HasPrefix(name, "_") {
		fail(w, vault.ErrInvalidName)
		return
	}
	if err := s.C.Vault.Delete(name); err != nil {
		fail(w, err)
		return
	}
	s.C.Audit.Append("secret_delete", "web", map[string]any{"name": name})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Approve bool   `json:"approve"`
		Hash    string `json:"hash"`
		TOTP    string `json:"totp"`
		Secret  string `json:"secret"`
	}
	if !read(w, r, &in) {
		return
	}
	msg, err := s.C.Decide(r.PathValue("id"), in.Hash, in.Approve, "web", in.TOTP, in.Secret)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"message": msg})
}

func (s *Server) auditLog(w http.ResponseWriter, _ *http.Request) {
	es, err := s.C.Audit.Tail(200)
	if err != nil {
		fail(w, err)
		return
	}
	n, verr := audit.Verify(s.AuditPath)
	writeJSON(w, 200, map[string]any{"entries": es, "valid_entries": n, "chain_ok": verr == nil, "truncated": s.C.AuditTruncated()})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	items, err := s.C.Health()
	if err != nil {
		fail(w, err)
		return
	}
	gate := core.HealthItem{Key: "gate", Level: "ok", Message: "Có mã truy cập chặn trước trang đăng nhập."}
	if s.GateToken == "" {
		gate = core.HealthItem{Key: "gate", Level: "bad", Message: "Cổng mã truy cập đang tắt, ai tới được địa chỉ này cũng thấy trang đăng nhập."}
	}
	https := core.HealthItem{Key: "https", Level: "ok", Message: "Cookie phiên chỉ đi qua HTTPS."}
	if !s.SecureCookie {
		https = core.HealthItem{Key: "https", Level: "warn", Message: "Cookie phiên chưa đặt Secure. Đặt UCANRUN_PUBLIC_URL với địa chỉ https."}
	}
	writeJSON(w, 200, append(items, gate, https))
}

func (s *Server) setTelegram(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if !read(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	bot, code, err := s.C.SetTelegramToken(ctx, strings.TrimSpace(in.Token))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"bot": bot, "code": code})
}

func (s *Server) totpStart(w http.ResponseWriter, _ *http.Request) {
	secret, uri, err := s.C.TOTPStart()
	if err != nil {
		fail(w, err)
		return
	}
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"secret": secret, "qr": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)})
}

// AgentHandler returns the API for agents. It has no way to read a secret.
func (s *Server) AgentHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]bool{"ok": true}) })
	bearer := func(h func(http.ResponseWriter, *http.Request, core.Token)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing token"})
				return
			}
			t, err := s.C.Authenticate(tok)
			if err != nil {
				fail(w, err)
				return
			}
			h(w, r, t)
		}
	}
	m.HandleFunc("GET /v1/profiles", bearer(func(w http.ResponseWriter, _ *http.Request, t core.Token) {
		p, err := s.C.ProfilesFor(t)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, p)
	}))
	m.HandleFunc("POST /v1/requests", bearer(func(w http.ResponseWriter, r *http.Request, t core.Token) {
		var in struct {
			Profile string            `json:"profile"`
			Params  map[string]string `json:"params"`
			Reason  string            `json:"reason"`
			WaitSec int               `json:"wait_sec"`
		}
		if !read(w, r, &in) {
			return
		}
		q, err := s.C.Submit(t, in.Profile, in.Params, in.Reason)
		if err != nil {
			fail(w, err)
			return
		}
		if in.WaitSec > 0 {
			ctx, cancel := context.WithTimeout(r.Context(), time.Duration(min(in.WaitSec, 110))*time.Second)
			defer cancel()
			q, _ = s.C.Wait(ctx, q.ID)
		}
		writeJSON(w, 200, q)
	}))
	m.HandleFunc("GET /v1/requests/{id}", bearer(func(w http.ResponseWriter, r *http.Request, t core.Token) {
		q, ok := s.C.Get(r.PathValue("id"))
		if !ok || q.Caller != t.Name {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, q)
	}))
	return m
}
