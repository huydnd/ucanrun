// Package totp implements RFC 6238 with SHA-1, 30s steps and 6 digits.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const step = 30

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

func Generate() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return enc.EncodeToString(b), nil
}

func URI(secret, account string) string {
	v := url.Values{"secret": {secret}, "issuer": {"ucanrun"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/ucanrun:" + url.PathEscape(account) + "?" + v.Encode()
}

func code(key []byte, counter int64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(counter))
	m := hmac.New(sha1.New, key)
	m.Write(b[:])
	h := m.Sum(nil)
	o := h[len(h)-1] & 0x0f
	n := binary.BigEndian.Uint32(h[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1000000)
}

// Code returns the code for time t. Exposed for tests and the CLI.
func Code(secret string, t time.Time) (string, error) {
	key, err := enc.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	return code(key, t.Unix()/step), nil
}

// Verify accepts the current step +/-1 and only steps newer than last, which
// makes every code single-use. It returns the matched step, or 0 on failure.
func Verify(secret, input string, t time.Time, last int64) int64 {
	key, err := enc.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(input) != 6 {
		return 0
	}
	cur := t.Unix() / step
	var match int64
	for c := cur - 1; c <= cur+1; c++ {
		if subtle.ConstantTimeCompare([]byte(code(key, c)), []byte(input)) == 1 && c > last {
			match = c
		}
	}
	return match
}
