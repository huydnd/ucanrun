package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	l, _ := Open(p)
	for _, e := range []string{"one", "two", "three"} {
		if err := l.Append(e, "x", map[string]any{"n": 1}); err != nil {
			t.Fatal(err)
		}
	}
	l2, _ := Open(p) // continues the chain after restart
	l2.Append("four", "x", nil)
	if n, err := Verify(p); err != nil || n != 4 {
		t.Fatalf("verify %d %v", n, err)
	}
	b, _ := os.ReadFile(p)
	os.WriteFile(p, bytes.Replace(b, []byte("two"), []byte("TWO"), 1), 0o600)
	if _, err := Verify(p); err == nil {
		t.Fatal("tamper not detected")
	}
	lines := bytes.SplitAfter(b, []byte("\n"))
	os.WriteFile(p, append(append([]byte{}, lines[0]...), lines[2]...), 0o600)
	if _, err := Verify(p); err == nil {
		t.Fatal("deletion not detected")
	}
}
