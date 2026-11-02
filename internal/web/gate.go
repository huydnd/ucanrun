package web

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"net/http"
	"time"
)

//go:embed gate.html
var gatePage []byte

const (
	gateCookie = "ucr_gate"
	gateMaxAge = 30 * 24 * time.Hour
)

// gateValue derives the cookie from the token, so the browser never stores the
// token itself and changing the token signs everyone out.
func gateValue(tok string) string {
	s := sha256.Sum256([]byte("ucanrun gate v1:" + tok))
	return hex.EncodeToString(s[:])
}

func (s *Server) gateOpen(r *http.Request) bool {
	c, err := r.Cookie(gateCookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(gateValue(s.GateToken))) == 1
}

// gate is an outer fence for the public UI. Without the access code nothing
// answers except the health check, so strangers cannot reach the login form or
// learn anything about the vault. It adds to the passphrase and TOTP.
func (s *Server) gate(next http.Handler) http.Handler {
	if s.GateToken == "" {
		return next
	}
	deny := func(w http.ResponseWriter, code int) {
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		w.WriteHeader(code)
		w.Write(gatePage)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || s.gateOpen(r) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/gate" {
			deny(w, http.StatusUnauthorized)
			return
		}
		if s.throttled() {
			deny(w, http.StatusTooManyRequests)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		code := r.PostFormValue("code")
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			deny(w, http.StatusForbidden)
			return
		}
		if subtle.ConstantTimeCompare([]byte(gateValue(code)), []byte(gateValue(s.GateToken))) != 1 {
			s.recordLogin(false)
			deny(w, http.StatusUnauthorized)
			return
		}
		s.recordLogin(true)
		http.SetCookie(w, &http.Cookie{Name: gateCookie, Value: gateValue(s.GateToken), Path: "/", HttpOnly: true,
			Secure: s.SecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: int(gateMaxAge.Seconds())})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}
