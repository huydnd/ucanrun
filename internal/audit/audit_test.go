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

func TestHeadAndContains(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if c, h := l.Head(); c != 0 || h != "" {
		t.Fatalf("empty head: %d %q", c, h)
	}
	if ok, err := Contains(p, 0, ""); err != nil || !ok {
		t.Fatalf("count 0 on missing file: %v %v", ok, err)
	}
	if ok, err := Contains(p, 1, "abc"); err != nil || ok {
		t.Fatalf("count 1 on missing file: %v %v", ok, err)
	}

	if err := l.Append("one", "x", nil); err != nil {
		t.Fatal(err)
	}
	c1, h1 := l.Head()
	if c1 != 1 || h1 == "" {
		t.Fatalf("head after 1: %d %q", c1, h1)
	}
	if err := l.Append("two", "x", nil); err != nil {
		t.Fatal(err)
	}
	c2, h2 := l.Head()
	if c2 != 2 || h2 == "" || h2 == h1 {
		t.Fatalf("head after 2: %d %q", c2, h2)
	}

	l2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if c, h := l2.Head(); c != c2 || h != h2 {
		t.Fatalf("reopened head: got (%d, %q), want (%d, %q)", c, h, c2, h2)
	}

	if ok, err := Contains(p, 0, "ignored"); err != nil || !ok {
		t.Fatalf("count 0: %v %v", ok, err)
	}
	if ok, err := Contains(p, 1, h1); err != nil || !ok {
		t.Fatalf("contains 1: %v %v", ok, err)
	}
	if ok, err := Contains(p, 2, h2); err != nil || !ok {
		t.Fatalf("contains 2: %v %v", ok, err)
	}
	if ok, err := Contains(p, 2, h1); err != nil || ok {
		t.Fatalf("wrong hash: %v %v", ok, err)
	}
	if ok, err := Contains(p, 3, h2); err != nil || ok {
		t.Fatalf("out of range count: %v %v", ok, err)
	}

	b, _ := os.ReadFile(p)
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	os.WriteFile(p, append(lines[0], '\n'), 0o600)
	if ok, err := Contains(p, 2, h2); err != nil || ok {
		t.Fatalf("truncated entry still reported present: %v %v", ok, err)
	}
	if ok, err := Contains(p, 1, h1); err != nil || !ok {
		t.Fatalf("remaining entry missing: %v %v", ok, err)
	}
}
