// Package policy defines profiles: the only actions an agent may request.
// Agents supply parameter values; humans author everything else.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const (
	RiskLow  = "low"
	RiskHigh = "high"
)

type Param struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Required    bool   `json:"required"`
	Description string `json:"description,omitempty"`
}

type HTTPSpec struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

type ExecSpec struct {
	Argv []string          `json:"argv"`
	Env  map[string]string `json:"env,omitempty"`
}

type Profile struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Risk        string    `json:"risk"`
	AutoApprove bool      `json:"auto_approve,omitempty"`
	TimeoutSec  int       `json:"timeout_sec,omitempty"`
	Params      []Param   `json:"params,omitempty"`
	HTTP        *HTTPSpec `json:"http,omitempty"`
	Exec        *ExecSpec `json:"exec,omitempty"`
}

// Action is a fully rendered request except for secret placeholders.
type Action struct {
	HTTP       *HTTPSpec `json:"http,omitempty"`
	Exec       *ExecSpec `json:"exec,omitempty"`
	TimeoutSec int       `json:"timeout_sec"`
}

var (
	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	tmplRe = regexp.MustCompile(`\{\{\s*(secret:)?([A-Za-z0-9_.-]+)\s*\}\}`)
)

func refs(s string) (params, secrets []string) {
	for _, m := range tmplRe.FindAllStringSubmatch(s, -1) {
		if m[1] != "" {
			secrets = append(secrets, m[2])
		} else {
			params = append(params, m[2])
		}
	}
	return
}

// Validate enforces the rules that keep a secret from leaving for an
// agent-chosen destination.
func (p *Profile) Validate() error {
	if !nameRe.MatchString(p.Name) {
		return errors.New("profile name must match [a-z0-9][a-z0-9_-]*")
	}
	if p.Risk != RiskLow && p.Risk != RiskHigh {
		return errors.New("risk must be low or high")
	}
	if p.AutoApprove && p.Risk == RiskHigh {
		return errors.New("a high risk profile cannot auto-approve")
	}
	if (p.HTTP == nil) == (p.Exec == nil) {
		return errors.New("exactly one of http or exec is required")
	}
	if p.TimeoutSec < 0 || p.TimeoutSec > 600 {
		return errors.New("timeout_sec must be 0..600")
	}
	declared := map[string]bool{}
	for _, q := range p.Params {
		if !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(q.Name) {
			return fmt.Errorf("bad param name %q", q.Name)
		}
		if declared[q.Name] {
			return fmt.Errorf("duplicate param %q", q.Name)
		}
		declared[q.Name] = true
		if q.Pattern == "" {
			return fmt.Errorf("param %q needs a pattern", q.Name)
		}
		if _, err := regexp.Compile(q.Pattern); err != nil {
			return fmt.Errorf("param %q: %w", q.Name, err)
		}
	}
	var texts []string
	if h := p.HTTP; h != nil {
		switch h.Method {
		case "GET", "POST", "PUT", "PATCH", "DELETE":
		default:
			return errors.New("unsupported http method")
		}
		// The scheme, host and start of the path must be literal.
		head, _, templated := strings.Cut(h.URL, "{{")
		u, err := url.Parse(head)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return errors.New("url must start with a literal http(s)://host")
		}
		if templated && !strings.Contains(strings.SplitN(head, "://", 2)[1], "/") {
			return errors.New("template is not allowed in the url host")
		}
		if _, s := refs(h.URL); len(s) > 0 {
			return errors.New("secrets are not allowed in the url")
		}
		texts = append(texts, h.URL, h.Body)
		for k, v := range h.Headers {
			if strings.Contains(k, "{{") {
				return errors.New("template is not allowed in a header name")
			}
			texts = append(texts, v)
		}
	}
	if e := p.Exec; e != nil {
		if len(e.Argv) == 0 || !strings.HasPrefix(e.Argv[0], "/") || strings.Contains(e.Argv[0], "{{") {
			return errors.New("argv[0] must be a literal absolute path")
		}
		switch e.Argv[0][strings.LastIndex(e.Argv[0], "/")+1:] {
		case "sh", "bash", "dash", "ash", "zsh", "env", "python", "python3", "perl", "ruby", "node":
			return errors.New("interpreters are not allowed, they turn params into code")
		}
		for _, a := range e.Argv {
			if _, s := refs(a); len(s) > 0 {
				return errors.New("secrets are only allowed in exec env, argv is visible in /proc")
			}
		}
		texts = append(texts, e.Argv...)
		for _, v := range e.Env {
			texts = append(texts, v)
		}
	}
	for _, t := range texts {
		ps, ss := refs(t)
		for _, n := range ps {
			if !declared[n] {
				return fmt.Errorf("undeclared param %q", n)
			}
		}
		for _, n := range ss {
			if strings.HasPrefix(n, "_") {
				return fmt.Errorf("internal secret %q cannot be used", n)
			}
		}
	}
	return nil
}

// CheckParams rejects unknown, missing or non-matching values.
func (p *Profile) CheckParams(in map[string]string) error {
	known := map[string]bool{}
	for _, q := range p.Params {
		known[q.Name] = true
		v, ok := in[q.Name]
		if !ok {
			if q.Required {
				return fmt.Errorf("missing param %q", q.Name)
			}
			continue
		}
		re, err := regexp.Compile(`^(?:` + q.Pattern + `)$`)
		if err != nil {
			return err
		}
		if len(v) > 4096 || !re.MatchString(v) {
			return fmt.Errorf("param %q does not match its pattern", q.Name)
		}
		// A value must never be able to form a template, or an agent could
		// pull an arbitrary secret into a request.
		if strings.ContainsAny(v, "{}") && (strings.Contains(v, "{{") || strings.Contains(v, "}}")) {
			return fmt.Errorf("param %q must not contain template braces", q.Name)
		}
	}
	for k := range in {
		if !known[k] {
			return fmt.Errorf("unknown param %q", k)
		}
	}
	return nil
}

func subst(s string, params map[string]string, esc func(string) string) string {
	return tmplRe.ReplaceAllStringFunc(s, func(m string) string {
		g := tmplRe.FindStringSubmatch(m)
		if g[1] != "" {
			return m // secrets resolve at execution, after approval
		}
		return esc(params[g[2]])
	})
}

func jsonEsc(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

// Render checks params and produces the immutable action.
func (p *Profile) Render(params map[string]string) (*Action, error) {
	if err := p.CheckParams(params); err != nil {
		return nil, err
	}
	raw := func(s string) string { return s }
	a := &Action{TimeoutSec: p.TimeoutSec}
	if a.TimeoutSec == 0 {
		a.TimeoutSec = 30
	}
	if h := p.HTTP; h != nil {
		out := &HTTPSpec{Method: h.Method, URL: subst(h.URL, params, url.PathEscape)}
		isJSON := false
		if len(h.Headers) > 0 {
			out.Headers = map[string]string{}
			for k, v := range h.Headers {
				out.Headers[k] = subst(v, params, raw)
				if strings.EqualFold(k, "content-type") && strings.Contains(v, "json") {
					isJSON = true
				}
			}
		}
		esc := raw
		if isJSON {
			esc = jsonEsc
		}
		out.Body = subst(h.Body, params, esc)
		a.HTTP = out
	}
	if e := p.Exec; e != nil {
		out := &ExecSpec{}
		for _, s := range e.Argv {
			out.Argv = append(out.Argv, subst(s, params, raw))
		}
		if len(e.Env) > 0 {
			out.Env = map[string]string{}
			for k, v := range e.Env {
				out.Env[k] = subst(v, params, raw)
			}
		}
		a.Exec = out
	}
	// Defence in depth: rendering must not add a secret the profile never named.
	allowed := map[string]bool{}
	for _, n := range (&Action{HTTP: p.HTTP, Exec: p.Exec}).Secrets() {
		allowed[n] = true
	}
	for _, n := range a.Secrets() {
		if !allowed[n] {
			return nil, fmt.Errorf("rendered action references undeclared secret %q", n)
		}
	}
	return a, nil
}

// Secrets lists the secret names an action uses.
func (a *Action) Secrets() []string {
	seen := map[string]bool{}
	add := func(s string) {
		_, ss := refs(s)
		for _, n := range ss {
			seen[n] = true
		}
	}
	if h := a.HTTP; h != nil {
		add(h.Body)
		for _, v := range h.Headers {
			add(v)
		}
	}
	if e := a.Exec; e != nil {
		for _, v := range e.Env {
			add(v)
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Display is the text a human approves. It comes from the rendered action, not
// from anything the agent wrote, and never contains a secret value.
func (a *Action) Display() string {
	mask := func(s string) string {
		return tmplRe.ReplaceAllString(s, "‹secret:$2›")
	}
	var b strings.Builder
	if h := a.HTTP; h != nil {
		fmt.Fprintf(&b, "%s %s", h.Method, h.URL)
		keys := make([]string, 0, len(h.Headers))
		for k := range h.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "\n%s: %s", k, mask(h.Headers[k]))
		}
		if h.Body != "" {
			fmt.Fprintf(&b, "\n\n%s", mask(h.Body))
		}
	}
	if e := a.Exec; e != nil {
		q := make([]string, len(e.Argv))
		for i, s := range e.Argv {
			q[i] = fmt.Sprintf("%q", s)
		}
		b.WriteString(strings.Join(q, " "))
		keys := make([]string, 0, len(e.Env))
		for k := range e.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "\nenv %s=%s", k, mask(e.Env[k]))
		}
	}
	return b.String()
}

// Hash binds an approval to this exact action, profile and caller.
func Hash(p *Profile, a *Action, caller string) string {
	b, _ := json.Marshal(struct {
		P *Profile
		A *Action
		C string
	}{p, a, caller})
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Expand replaces secret placeholders. Used only by the executor.
func Expand(s string, get func(string) string) string {
	return tmplRe.ReplaceAllStringFunc(s, func(m string) string {
		g := tmplRe.FindStringSubmatch(m)
		if g[1] == "" {
			return m
		}
		return get(g[2])
	})
}
