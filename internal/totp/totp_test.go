package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

func TestRFC6238Vectors(t *testing.T) {
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	// RFC 6238 appendix B, truncated from 8 to 6 digits.
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"} {
		got, err := Code(s, time.Unix(ts, 0))
		if err != nil || got != want {
			t.Fatalf("%d: got %s want %s (%v)", ts, got, want, err)
		}
	}
}

func TestVerifyRejectsReplayAndDrift(t *testing.T) {
	s, _ := Generate()
	now := time.Unix(1800000000, 0)
	c, _ := Code(s, now)
	m := Verify(s, c, now, 0)
	if m == 0 {
		t.Fatal("valid code rejected")
	}
	if Verify(s, c, now, m) != 0 {
		t.Fatal("replay accepted")
	}
	if Verify(s, c, now.Add(5*time.Minute), 0) != 0 {
		t.Fatal("old code accepted")
	}
	if Verify(s, "000", now, 0) != 0 {
		t.Fatal("short code accepted")
	}
}
