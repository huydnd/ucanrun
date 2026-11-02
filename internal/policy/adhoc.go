package policy

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// SecretMeta is what the owner writes next to a secret: what it is for and
// where it may be sent. Agents see it; they never see the value.
type SecretMeta struct {
	Description string `json:"description,omitempty"`
	// Hosts the secret may be sent to, such as "api.github.com" or
	// "*.example.com". Empty means the secret cannot be used in agent calls.
	Hosts []string `json:"hosts,omitempty"`
	// AllowCommands lets agents use the secret in commands they write. The
	// host cannot be checked for a command, so these always need TOTP.
	AllowCommands bool `json:"allow_commands,omitempty"`
}

var hostRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(:[0-9]{1,5})?$`)

func (m *SecretMeta) Validate() error {
	if len([]rune(m.Description)) > 300 {
		return errors.New("description is limited to 300 characters")
	}
	for _, r := range m.Description {
		if unicode.IsControl(r) && r != '\n' || unicode.Is(unicode.Cf, r) {
			return errors.New("description contains a control character")
		}
	}
	if len(m.Hosts) > 20 {
		return errors.New("at most 20 hosts")
	}
	for _, h := range m.Hosts {
		if !hostRe.MatchString(h) {
			return fmt.Errorf("bad host %q, use a name such as api.example.com", h)
		}
	}
	return nil
}

func (m *SecretMeta) allowsHost(u *url.URL) bool {
	host := strings.ToLower(u.Host)
	name := strings.ToLower(u.Hostname())
	for _, h := range m.Hosts {
		if suffix, ok := strings.CutPrefix(h, "*."); ok {
			if strings.HasSuffix(name, "."+suffix) {
				return true
			}
			continue
		}
		if h == host || h == name && u.Port() == "" {
			return true
		}
	}
	return false
}

// Call is a request an agent writes itself, with {{secret:name}} where a
// secret goes. ucanrun checks it against the owner's rules, a person approves
// it, and ucanrun runs it.
type Call struct {
	HTTP *HTTPSpec `json:"http,omitempty"`
	Exec *ExecSpec `json:"exec,omitempty"`
}

// AdhocProfile labels requests built from a Call.
const AdhocProfile = "agent-call"

// FromCall turns an agent's call into a profile, enforcing where each secret
// may go. The result also passes through Validate and Render like any profile.
func FromCall(c Call, meta map[string]SecretMeta) (Profile, error) {
	p := Profile{Name: AdhocProfile, Risk: RiskLow, Description: "agent call"}
	if (c.HTTP == nil) == (c.Exec == nil) {
		return p, errors.New("a call is either http or exec")
	}
	var used []string
	if h := c.HTTP; h != nil {
		// No templates outside header values: the URL and body are the agent's
		// own text, and a secret in a body can end up stored and public.
		if strings.Contains(h.URL, "{{") || strings.Contains(h.Body, "{{") {
			return p, errors.New("secrets go in headers only, never in the url or body")
		}
		u, err := url.Parse(h.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			return p, errors.New("url must be absolute http(s) without user info")
		}
		for k, v := range h.Headers {
			if strings.Contains(k, "{{") {
				return p, errors.New("no templates in header names")
			}
			ps, ss := refs(v)
			if len(ps) > 0 {
				return p, errors.New("only {{secret:name}} templates are allowed")
			}
			for _, n := range ss {
				m, ok := meta[n]
				if !ok {
					return p, fmt.Errorf("unknown secret %q", n)
				}
				if !m.allowsHost(u) {
					return p, fmt.Errorf("secret %q may not be sent to %s", n, u.Host)
				}
				used = append(used, n)
			}
		}
		p.HTTP = h
	}
	if e := c.Exec; e != nil {
		p.Risk = RiskHigh
		texts := append([]string{e.Stdin}, e.Argv...)
		for _, v := range e.Env {
			texts = append(texts, v)
		}
		for _, v := range e.Files {
			texts = append(texts, v)
		}
		for _, t := range texts {
			ps, ss := refs(t)
			if len(ps) > 0 {
				return p, errors.New("only {{secret:name}} templates are allowed")
			}
			for _, n := range ss {
				m, ok := meta[n]
				if !ok {
					return p, fmt.Errorf("unknown secret %q", n)
				}
				if !m.AllowCommands {
					return p, fmt.Errorf("secret %q is not allowed in commands", n)
				}
				used = append(used, n)
			}
		}
		p.Exec = e
	}
	if len(used) == 0 {
		return p, errors.New("the call uses no secret, so run it yourself")
	}
	return p, p.Validate()
}
