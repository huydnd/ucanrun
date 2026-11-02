package policy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	maxRead   = 1 << 20
	maxOutput = 64 << 10
)

type Result struct {
	OK     bool   `json:"ok"`
	Exit   int    `json:"exit"`
	Output string `json:"output"`
}

// Redact removes secret values and common encodings of them.
func Redact(s string, secrets [][]byte) string {
	var forms []string
	for _, v := range secrets {
		if len(v) < 4 {
			continue
		}
		t := string(v)
		forms = append(forms, t, strings.TrimSpace(t),
			base64.StdEncoding.EncodeToString(v), base64.RawStdEncoding.EncodeToString(v),
			base64.URLEncoding.EncodeToString(v), base64.RawURLEncoding.EncodeToString(v),
			hex.EncodeToString(v), strings.ToUpper(hex.EncodeToString(v)), url.QueryEscape(t), url.PathEscape(t))
		if b, err := json.Marshal(t); err == nil {
			forms = append(forms, string(b[1:len(b)-1]))
		}
	}
	sort.Slice(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	for _, f := range forms {
		if f != "" {
			s = strings.ReplaceAll(s, f, "[REDACTED]")
		}
	}
	return s
}

func clip(s string) string {
	if len(s) > maxOutput {
		return s[:maxOutput] + "\n[output truncated]"
	}
	return s
}

// Run executes the action. Secrets are resolved here, after approval, and every
// fetched value is redacted from the result.
func Run(ctx context.Context, a *Action, getSecret func(string) ([]byte, error)) Result {
	values := map[string][]byte{}
	for _, n := range a.Secrets() {
		v, err := getSecret(n)
		if err != nil {
			return Result{Exit: -1, Output: fmt.Sprintf("secret %q unavailable", n)}
		}
		values[n] = v
	}
	defer func() {
		for _, v := range values {
			clear(v)
		}
	}()
	get := func(n string) string { return string(values[n]) }
	var list [][]byte
	for _, v := range values {
		list = append(list, v)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(a.TimeoutSec)*time.Second)
	defer cancel()

	var r Result
	if a.HTTP != nil {
		r = runHTTP(ctx, a.HTTP, get)
	} else {
		r = runExec(ctx, a.Exec, get)
	}
	r.Output = clip(Redact(r.Output, list))
	return r
}

var httpClient = &http.Client{
	// A redirect could carry the Authorization header somewhere unapproved.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func runHTTP(ctx context.Context, h *HTTPSpec, get func(string) string) Result {
	var body io.Reader
	if h.Body != "" {
		body = strings.NewReader(Expand(h.Body, get))
	}
	req, err := http.NewRequestWithContext(ctx, h.Method, h.URL, body)
	if err != nil {
		return Result{Exit: -1, Output: "bad request"}
	}
	for k, v := range h.Headers {
		req.Header.Set(k, Expand(v, get))
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// url.Error holds only the URL, which contains no secret by construction.
		return Result{Exit: -1, Output: err.Error()}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	return Result{
		OK:     resp.StatusCode >= 200 && resp.StatusCode < 300,
		Exit:   resp.StatusCode,
		Output: fmt.Sprintf("HTTP %d\n%s", resp.StatusCode, b),
	}
}

type capped struct {
	b bytes.Buffer
}

func (c *capped) Write(p []byte) (int, error) {
	if room := maxRead - c.b.Len(); room > 0 {
		c.b.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

func runExec(ctx context.Context, e *ExecSpec, get func(string) string) Result {
	// A private HOME stops one run from planting config for the next.
	home, err := os.MkdirTemp("", "ucr-run-")
	if err != nil {
		return Result{Exit: -1, Output: "could not prepare a working directory"}
	}
	defer os.RemoveAll(home)
	cmd := exec.CommandContext(ctx, e.Argv[0], e.Argv[1:]...)
	cmd.Dir = home
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + home, "GIT_TERMINAL_PROMPT=0"}
	for k, v := range e.Env {
		cmd.Env = append(cmd.Env, k+"="+Expand(v, get))
	}
	var out capped
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	err = cmd.Run()
	r := Result{OK: err == nil, Output: out.b.String()}
	if cmd.ProcessState != nil {
		r.Exit = cmd.ProcessState.ExitCode()
	} else {
		r.Exit = -1
		r.Output = "could not start: " + err.Error()
	}
	if ctx.Err() != nil {
		r.Output += "\n[timed out]"
		r.OK = false
	}
	return r
}
