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
	"unicode"
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
	// Stdin is written to the program, for tools such as `sudo -S`.
	Stdin string `json:"stdin,omitempty"`
	// Files are created mode 0600 in the private working directory and removed
	// after the run, for tools that only read a key from a path.
	Files map[string]string `json:"files,omitempty"`
}

// ChoiceRef is the secret placeholder the approver fills in: {{secret:choice}}.
const ChoiceRef = "choice"

type Profile struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
	AutoApprove bool   `json:"auto_approve,omitempty"`
	TimeoutSec  int    `json:"timeout_sec,omitempty"`
	// SecretChoices lists what the approver may pick for {{secret:choice}}.
	SecretChoices []string `json:"secret_choices,omitempty"`
	// Connection names a Connection. HTTP.URL is then a path such as "/repos".
	Connection string    `json:"connection,omitempty"`
	Params     []Param   `json:"params,omitempty"`
	HTTP       *HTTPSpec `json:"http,omitempty"`
	Exec       *ExecSpec `json:"exec,omitempty"`
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
	if p.Connection != "" {
		// Checked in full once resolved against its connection. Here only the
		// shape is checked, using a stand-in host.
		if p.HTTP == nil || !strings.HasPrefix(p.HTTP.URL, "/") {
			return errors.New("with a connection the url is a path that starts with /")
		}
		q := *p
		h := *p.HTTP
		h.URL = "https://connection.invalid" + h.URL
		q.HTTP, q.Connection = &h, ""
		return q.Validate()
	}
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
	declared, used := map[string]bool{}, map[string]bool{}
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
		case "sh", "bash", "dash", "ash", "zsh", "env", "python", "python3", "perl", "ruby", "node",
			"busybox", "awk", "sed", "find", "xargs", "sudo", "su", "nohup", "timeout":
			return errors.New("interpreters are not allowed, they turn params into code")
		}
		for k := range e.Env {
			if !envNameRe.MatchString(k) || dangerousEnv(k) {
				return fmt.Errorf("env %q is not allowed, it changes how the program runs", k)
			}
		}
		for _, a := range e.Argv {
			if _, s := refs(a); len(s) > 0 {
				return errors.New("secrets are only allowed in exec env, argv is visible in /proc")
			}
		}
		texts = append(texts, e.Argv...)
		texts = append(texts, e.Stdin)
		for _, v := range e.Env {
			texts = append(texts, v)
		}
		for k, v := range e.Files {
			if !fileNameRe.MatchString(k) {
				return fmt.Errorf("file name %q must be a plain name", k)
			}
			if ps, _ := refs(v); len(ps) > 0 {
				return errors.New("a file may only contain secrets")
			}
			texts = append(texts, v)
		}
	}
	for _, t := range texts {
		ps, ss := refs(t)
		for _, n := range ps {
			if !declared[n] {
				return fmt.Errorf("undeclared param %q", n)
			}
			used[n] = true
		}
		for _, n := range ss {
			if strings.HasPrefix(n, "_") {
				return fmt.Errorf("internal secret %q cannot be used", n)
			}
		}
	}
	picks := false
	for _, t := range texts {
		_, ss := refs(t)
		for _, n := range ss {
			picks = picks || n == ChoiceRef
		}
	}
	if picks && len(p.SecretChoices) == 0 {
		return errors.New("secret_choices is required for {{secret:choice}}")
	}
	if !picks && len(p.SecretChoices) > 0 {
		return errors.New("secret_choices needs a {{secret:choice}} placeholder")
	}
	if picks && p.AutoApprove {
		return errors.New("a secret choice needs a human, so it cannot auto-approve")
	}
	for _, n := range p.SecretChoices {
		if strings.HasPrefix(n, "_") || n == ChoiceRef || !secretNameRe.MatchString(n) {
			return fmt.Errorf("bad secret choice %q", n)
		}
	}
	// An unused param never reaches the approver's screen, so it would be an
	// unreviewed channel from the agent into the log.
	for _, q := range p.Params {
		if !used[q.Name] {
			return fmt.Errorf("param %q is declared but never used", q.Name)
		}
	}
	return nil
}

var (
	envNameRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	fileNameRe   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)
	secretNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)
)

func dangerousEnv(k string) bool {
	u := strings.ToUpper(k)
	for _, p := range []string{"LD_", "DYLD_", "GIT_SSH", "GIT_CONFIG", "GIT_EXEC", "GIT_ASKPASS", "SSH_ASKPASS", "BASH_", "PYTHON", "NODE_", "PERL", "RUBY"} {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	switch u {
	case "PATH", "HOME", "IFS", "ENV", "SHELL", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "CURL_HOME", "TMPDIR":
		return true
	}
	return false
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
		// Control and bidi characters can make the approval text lie.
		for _, r := range v {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				return fmt.Errorf("param %q contains a control character", q.Name)
			}
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

// renderURL escapes by position: "&" and "=" are harmless in a path but split a
// query string. A "." or ".." segment is refused, because path escaping keeps
// dots and the server would resolve the traversal.
func renderURL(u string, params map[string]string) (string, error) {
	base, query, hasQuery := strings.Cut(u, "?")
	out := subst(base, params, url.PathEscape)
	if i := strings.Index(out, "://"); i >= 0 {
		for _, seg := range strings.Split(out[i+3:], "/") {
			if seg == "." || seg == ".." {
				return "", errors.New("a param may not create a . or .. path segment")
			}
		}
	}
	if hasQuery {
		out += "?" + subst(query, params, url.QueryEscape)
	}
	return out, nil
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
		u, err := renderURL(h.URL, params)
		if err != nil {
			return nil, err
		}
		out := &HTTPSpec{Method: h.Method, URL: u}
		isJSON, isForm := false, false
		if len(h.Headers) > 0 {
			out.Headers = map[string]string{}
			for k, v := range h.Headers {
				out.Headers[k] = subst(v, params, raw)
				if strings.EqualFold(k, "content-type") {
					isJSON = strings.Contains(v, "json")
					isForm = strings.Contains(v, "x-www-form-urlencoded")
				}
			}
		}
		esc := raw
		if isJSON {
			esc = jsonEsc
		} else if isForm {
			esc = url.QueryEscape
		}
		out.Body = subst(h.Body, params, esc)
		a.HTTP = out
	}
	if e := p.Exec; e != nil {
		out := &ExecSpec{}
		for _, s := range e.Argv {
			v := subst(s, params, raw)
			// "--upload-pack=..." style values would turn data into an option.
			if strings.HasPrefix(v, "-") && !strings.HasPrefix(s, "-") {
				return nil, errors.New("a param may not start a command line option")
			}
			out.Argv = append(out.Argv, v)
		}
		if len(e.Env) > 0 {
			out.Env = map[string]string{}
			for k, v := range e.Env {
				out.Env[k] = subst(v, params, raw)
			}
		}
		out.Stdin = subst(e.Stdin, params, raw)
		if len(e.Files) > 0 {
			out.Files = map[string]string{}
			for k, v := range e.Files {
				out.Files[k] = v
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
		add(e.Stdin)
		for _, v := range e.Files {
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
		s = strings.ReplaceAll(s, "{{secret:"+ChoiceRef+"}}", "‹secret bạn chọn khi duyệt›")
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
		if e.Stdin != "" {
			fmt.Fprintf(&b, "\nstdin: %s", mask(e.Stdin))
		}
		names := make([]string, 0, len(e.Files))
		for k := range e.Files {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			fmt.Fprintf(&b, "\nfile %s: %s", k, mask(e.Files[k]))
		}
	}
	return b.String()
}

// WithChoice returns a copy that uses the secret the approver picked. The agent
// never influences this: the name comes from the decision, checked against the
// profile's list.
func (a *Action) WithChoice(name string) *Action {
	r := func(s string) string {
		return strings.ReplaceAll(s, "{{secret:"+ChoiceRef+"}}", "{{secret:"+name+"}}")
	}
	m := func(in map[string]string) map[string]string {
		if in == nil {
			return nil
		}
		out := map[string]string{}
		for k, v := range in {
			out[k] = r(v)
		}
		return out
	}
	c := *a
	if a.HTTP != nil {
		h := *a.HTTP
		h.Headers, h.Body = m(h.Headers), r(h.Body)
		c.HTTP = &h
	}
	if a.Exec != nil {
		e := *a.Exec
		e.Env, e.Files, e.Stdin = m(e.Env), m(e.Files), r(e.Stdin)
		c.Exec = &e
	}
	return &c
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

// Lint returns advice for the author. Validate decides what is forbidden; this
// only points out choices that are legal but often unintended.
func (p *Profile) Lint() []string {
	var out []string
	if h := p.HTTP; h != nil {
		_, secrets := refs(strings.Join(mapValues(h.Headers), " ") + h.Body)
		if strings.HasPrefix(h.URL, "http://") && len(secrets) > 0 {
			if u, err := url.Parse(strings.SplitN(h.URL, "{{", 2)[0]); err == nil && strings.Contains(u.Hostname(), ".") {
				out = append(out, "Secret sẽ đi qua HTTP không mã hoá. Hãy dùng https cho dịch vụ bên ngoài.")
			}
		}
		if h.Method != "GET" && p.AutoApprove {
			out = append(out, "Tự chạy với phương thức ghi: agent thay đổi được dữ liệu mà không ai duyệt.")
		}
		if h.Method == "DELETE" && p.Risk != RiskHigh {
			out = append(out, "Hành động xoá nên đặt mức cần TOTP.")
		}
	}
	if p.Exec != nil {
		out = append(out, "Chạy lệnh là lựa chọn rủi ro hơn gọi API, vì chương trình đó có thể làm nhiều hơn bạn thấy.")
		if p.AutoApprove {
			out = append(out, "Chạy lệnh mà không ai duyệt là rủi ro cao.")
		}
	}
	for _, q := range p.Params {
		if q.Pattern == ".*" || q.Pattern == ".+" {
			out = append(out, "Giá trị \""+q.Name+"\" nhận mọi thứ. Hãy giới hạn kiểu dữ liệu.")
		}
	}
	return out
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
