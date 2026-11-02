package policy

import (
	"strings"
	"testing"
)

func gh() map[string]Connection {
	return map[string]Connection{"github": {Name: "github", BaseURL: "https://api.github.com",
		Auth: Auth{Type: "bearer", Secret: "github_token"}, Headers: map[string]string{"Accept": "application/vnd.github+json"}}}
}

func TestResolveBuildsTheRequest(t *testing.T) {
	p := Profile{Name: "issue", Risk: RiskLow, Connection: "github",
		Params: []Param{{Name: "repo", Pattern: `[a-z0-9-]+`, Required: true}},
		HTTP:   &HTTPSpec{Method: "POST", URL: "/repos/me/{{repo}}/issues", Body: "{}"}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	r, err := Resolve(p, gh())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	a, err := r.Render(map[string]string{"repo": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if a.HTTP.URL != "https://api.github.com/repos/me/x/issues" || a.HTTP.Headers["Authorization"] != "Bearer {{secret:github_token}}" || a.HTTP.Headers["Accept"] == "" {
		t.Fatalf("%+v", a.HTTP)
	}
	if !strings.Contains(a.Display(), "‹secret:github_token›") {
		t.Fatal(a.Display())
	}
}

func TestResolveKeepsTheHostFixed(t *testing.T) {
	for name, path := range map[string]string{
		"absolute":     "https://evil.example/x",
		"protocol rel": "//evil.example/x",
		"no slash":     "x",
		"backslash":    "/\\evil.example",
		"param host":   "{{repo}}/x",
	} {
		p := Profile{Name: "p", Risk: RiskLow, Connection: "github", Params: []Param{{Name: "repo", Pattern: `.+`}},
			HTTP: &HTTPSpec{Method: "GET", URL: path}}
		if _, err := Resolve(p, gh()); err == nil {
			if p.Validate() == nil {
				t.Errorf("%s accepted", name)
			}
		}
	}
	// A param in the first path segment still cannot reach another host.
	p := Profile{Name: "p", Risk: RiskLow, Connection: "github", Params: []Param{{Name: "a", Pattern: `.+`, Required: true}},
		HTTP: &HTTPSpec{Method: "GET", URL: "/{{a}}"}}
	r, err := Resolve(p, gh())
	if err != nil {
		t.Fatal(err)
	}
	a, err := r.Render(map[string]string{"a": "@evil.example"})
	if err != nil || !strings.HasPrefix(a.HTTP.URL, "https://api.github.com/") {
		t.Fatalf("%v %v", a, err)
	}
}

func TestProfileCannotOverrideAuth(t *testing.T) {
	p := Profile{Name: "p", Risk: RiskLow, Connection: "github", HTTP: &HTTPSpec{Method: "GET", URL: "/x", Headers: map[string]string{"authorization": "Bearer {{secret:other}}"}}}
	if _, err := Resolve(p, gh()); err == nil {
		t.Fatal("profile replaced the connection's auth header")
	}
}

func TestConnectionValidate(t *testing.T) {
	bad := map[string]Connection{
		"template base": {Name: "a", BaseURL: "https://{{x}}.example", Auth: Auth{Type: "none"}},
		"query":         {Name: "a", BaseURL: "https://a.example/?k=v", Auth: Auth{Type: "none"}},
		"userinfo":      {Name: "a", BaseURL: "https://u:p@a.example", Auth: Auth{Type: "none"}},
		"no secret":     {Name: "a", BaseURL: "https://a.example", Auth: Auth{Type: "bearer"}},
		"both":          {Name: "a", BaseURL: "https://a.example", Auth: Auth{Type: "bearer", Secret: "s", Choices: []string{"t"}}},
		"internal":      {Name: "a", BaseURL: "https://a.example", Auth: Auth{Type: "bearer", Secret: "_totp_secret"}},
		"header name":   {Name: "a", BaseURL: "https://a.example", Auth: Auth{Type: "header", Header: "Bad Header", Secret: "s"}},
		"header value":  {Name: "a", BaseURL: "https://a.example", Auth: Auth{Type: "none"}, Headers: map[string]string{"X": "{{secret:s}}"}},
		"name":          {Name: "Bad", BaseURL: "https://a.example", Auth: Auth{Type: "none"}},
	}
	for n, c := range bad {
		if c.Validate() == nil {
			t.Errorf("%s accepted", n)
		}
	}
	ok := Connection{Name: "a", BaseURL: "https://a.example/v1", Auth: Auth{Type: "bearer", Choices: []string{"x", "y"}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	p := Profile{Name: "p", Risk: RiskLow, Connection: "a", HTTP: &HTTPSpec{Method: "GET", URL: "/me"}}
	r, err := Resolve(p, map[string]Connection{"a": ok})
	if err != nil || r.Validate() != nil || len(r.SecretChoices) != 2 || r.HTTP.URL != "https://a.example/v1/me" {
		t.Fatalf("%+v %v", r, err)
	}
}
