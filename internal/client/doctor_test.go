package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDoctor(t *testing.T) {
	const secretToken = "ucr_super_secret_test_token_123456"

	t.Run("all ok", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/healthz":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"ok":true}`))
			case "/v1/profiles":
				if r.Header.Get("Authorization") != "Bearer "+secretToken {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`[{"name":"p1"},{"name":"p2"}]`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		c := &Client{URL: srv.URL, Token: secretToken, HTTP: srv.Client()}
		checks := c.Doctor(context.Background())
		if len(checks) != 3 {
			t.Fatalf("got %d checks, want 3", len(checks))
		}
		for _, ch := range checks {
			if !ch.OK {
				t.Errorf("check %s failed: %s", ch.Name, ch.Detail)
			}
			if strings.Contains(ch.Detail, secretToken) || strings.Contains(ch.Detail, "super_secret") {
				t.Errorf("check %s leaked token in detail: %s", ch.Name, ch.Detail)
			}
		}
		if !strings.Contains(checks[2].Detail, "2") {
			t.Errorf("profiles detail = %q, want profile count 2", checks[2].Detail)
		}
	})

	t.Run("missing token", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		c := &Client{URL: srv.URL, HTTP: srv.Client()}
		checks := c.Doctor(context.Background())
		if len(checks) != 3 {
			t.Fatalf("got %d checks, want 3", len(checks))
		}
		if checks[0].OK {
			t.Errorf("expected token check to fail")
		}
		if !checks[1].OK {
			t.Errorf("expected healthz check to pass, got %s", checks[1].Detail)
		}
		if checks[2].OK {
			t.Errorf("expected profiles check to fail without token")
		}
	})

	t.Run("vault locked 423", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusLocked)
		}))
		defer srv.Close()

		c := &Client{URL: srv.URL, Token: secretToken, HTTP: srv.Client()}
		checks := c.Doctor(context.Background())
		if checks[2].OK || checks[2].Detail != "vault locked, sign in on the web" {
			t.Errorf("got %+v, want vault locked failure", checks[2])
		}
	})

	t.Run("token rejected 403", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()

		c := &Client{URL: srv.URL, Token: secretToken, HTTP: srv.Client()}
		checks := c.Doctor(context.Background())
		if checks[2].OK || checks[2].Detail != "token rejected" {
			t.Errorf("got %+v, want token rejected failure", checks[2])
		}
	})

	t.Run("healthz non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[]`))
		}))
		defer srv.Close()

		c := &Client{URL: srv.URL, Token: secretToken, HTTP: srv.Client()}
		checks := c.Doctor(context.Background())
		if checks[1].OK {
			t.Errorf("expected healthz check to fail")
		}
	})
}
