// Package audit is an append-only JSONL log with a SHA-256 hash chain, so that
// editing or removing a past line is detectable. Never log secret values.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

type Entry struct {
	Time   time.Time      `json:"time"`
	Event  string         `json:"event"`
	Actor  string         `json:"actor,omitempty"`
	Fields map[string]any `json:"fields,omitempty"`
	Prev   string         `json:"prev"`
	Hash   string         `json:"hash"`
}

type Log struct {
	path  string
	mu    sync.Mutex
	count int
	last  string
}

func Open(path string) (*Log, error) {
	l := &Log{path: path}
	entries, err := readAll(path)
	if err != nil {
		return nil, err
	}
	if n := len(entries); n > 0 {
		l.count = n
		l.last = entries[n-1].Hash
	}
	return l, nil
}

func (l *Log) Head() (count int, hash string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count, l.last
}

func hashOf(e Entry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (l *Log) Append(event, actor string, fields map[string]any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Entry{Time: time.Now().UTC(), Event: event, Actor: actor, Fields: fields, Prev: l.last}
	e.Hash = hashOf(e)
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	l.count++
	l.last = e.Hash
	return nil
}

func readAll(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 1<<20)
	for s.Scan() {
		var e Entry
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("line %d: %w", len(out)+1, err)
		}
		out = append(out, e)
	}
	return out, s.Err()
}

// Tail returns the newest n entries, newest first.
func (l *Log) Tail(n int) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	es, err := readAll(l.path)
	if err != nil {
		return nil, err
	}
	out := []Entry{}
	for i := len(es) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, es[i])
	}
	return out, nil
}

// Verify walks the chain and returns the number of valid entries.
func Verify(path string) (int, error) {
	es, err := readAll(path)
	if err != nil {
		return 0, err
	}
	prev := ""
	for i, e := range es {
		if e.Prev != prev || hashOf(e) != e.Hash {
			return i, fmt.Errorf("chain broken at entry %d", i+1)
		}
		prev = e.Hash
	}
	return len(es), nil
}

// Contains reports whether 1-based entry number count exists with the given hash.
func Contains(path string, count int, hash string) (bool, error) {
	if count == 0 {
		return true, nil
	}
	es, err := readAll(path)
	if err != nil {
		return false, err
	}
	if count < 0 || len(es) < count {
		return false, nil
	}
	return es[count-1].Hash == hash, nil
}
