// Package client is the agent side of the API, used by `ucr run`, `ucr doctor`, and `ucr mcp`.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Client struct {
	URL, Token string
	HTTP       *http.Client
}

type Check struct {
	Name   string
	OK     bool
	Detail string
}

// FromEnv reads UCANRUN_URL and UCANRUN_TOKEN, then ~/.config/ucanrun/token.
func FromEnv() (*Client, error) {
	c := &Client{URL: os.Getenv("UCANRUN_URL"), Token: strings.TrimSpace(os.Getenv("UCANRUN_TOKEN")), HTTP: &http.Client{Timeout: 130 * time.Second}}
	if c.URL == "" {
		c.URL = "http://127.0.0.1:8781"
	}
	if c.Token == "" {
		home, _ := os.UserHomeDir()
		b, err := os.ReadFile(filepath.Join(home, ".config", "ucanrun", "token"))
		if err != nil {
			return nil, errors.New("no agent token: set UCANRUN_TOKEN or ~/.config/ucanrun/token")
		}
		c.Token = strings.TrimSpace(string(b))
		if c.Token == "" {
			return nil, errors.New("no agent token: set UCANRUN_TOKEN or ~/.config/ucanrun/token")
		}
	}
	return c, nil
}

// Doctor checks the agent token, server health, and profile access.
func (c *Client) Doctor(ctx context.Context) []Check {
	var checks []Check
	tok := ""
	base := "http://127.0.0.1:8781"
	var hc *http.Client
	if c != nil {
		tok = strings.TrimSpace(c.Token)
		if u := strings.TrimRight(c.URL, "/"); u != "" {
			base = u
		}
		hc = c.HTTP
	}
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}

	if tok == "" {
		checks = append(checks, Check{Name: "token", OK: false, Detail: "no agent token: set UCANRUN_TOKEN or ~/.config/ucanrun/token"})
	} else {
		checks = append(checks, Check{Name: "token", OK: true, Detail: "token found"})
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
	if err != nil {
		checks = append(checks, Check{Name: "healthz", OK: false, Detail: err.Error()})
	} else if resp, err := hc.Do(req); err != nil {
		checks = append(checks, Check{Name: "healthz", OK: false, Detail: err.Error()})
	} else {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			checks = append(checks, Check{Name: "healthz", OK: false, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)})
		} else {
			checks = append(checks, Check{Name: "healthz", OK: true, Detail: "200 OK"})
		}
	}

	if tok == "" {
		checks = append(checks, Check{Name: "profiles", OK: false, Detail: "no agent token"})
		return checks
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/profiles", nil)
	if err != nil {
		checks = append(checks, Check{Name: "profiles", OK: false, Detail: err.Error()})
		return checks
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := hc.Do(req)
	if err != nil {
		checks = append(checks, Check{Name: "profiles", OK: false, Detail: err.Error()})
		return checks
	}
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<21))
	resp.Body.Close()
	if readErr != nil {
		checks = append(checks, Check{Name: "profiles", OK: false, Detail: readErr.Error()})
		return checks
	}
	switch resp.StatusCode {
	case http.StatusOK:
		var list []any
		if err := json.Unmarshal(raw, &list); err != nil {
			checks = append(checks, Check{Name: "profiles", OK: false, Detail: err.Error()})
		} else {
			checks = append(checks, Check{Name: "profiles", OK: true, Detail: fmt.Sprintf("%d profiles", len(list))})
		}
	case http.StatusLocked:
		checks = append(checks, Check{Name: "profiles", OK: false, Detail: "vault locked, sign in on the web"})
	case http.StatusForbidden:
		checks = append(checks, Check{Name: "profiles", OK: false, Detail: "token rejected"})
	default:
		checks = append(checks, Check{Name: "profiles", OK: false, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)})
	}
	return checks
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.URL, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<21))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(raw, &e)
		return fmt.Errorf("ucanrun: %s (HTTP %d)", e.Error, resp.StatusCode)
	}
	return json.Unmarshal(raw, out)
}

// Raw calls return decoded JSON, so MCP can pass results through unchanged.
func (c *Client) Profiles(ctx context.Context) (any, error) {
	var v any
	return v, c.do(ctx, "GET", "/v1/profiles", nil, &v)
}

func (c *Client) Run(ctx context.Context, profile string, params map[string]string, reason string, wait int) (map[string]any, error) {
	v := map[string]any{}
	err := c.do(ctx, "POST", "/v1/requests", map[string]any{"profile": profile, "params": params, "reason": reason, "wait_sec": wait}, &v)
	return v, err
}

func (c *Client) Request(ctx context.Context, id string) (map[string]any, error) {
	v := map[string]any{}
	return v, c.do(ctx, "GET", "/v1/requests/"+id, nil, &v)
}
