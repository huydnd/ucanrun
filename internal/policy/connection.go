package policy

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// A Connection describes one service once: where it lives and how to sign in.
// Profiles that use it only state a method, a path and the values an agent
// fills in, so adding a service needs no code and no per-service template.
type Connection struct {
	Name    string            `json:"name"`
	Title   string            `json:"title,omitempty"`
	BaseURL string            `json:"base_url"`
	Auth    Auth              `json:"auth"`
	Headers map[string]string `json:"headers,omitempty"`
}

// Auth types put the secret in a header. Secrets never go in a URL.
type Auth struct {
	Type   string `json:"type"`             // none, bearer, token, header
	Header string `json:"header,omitempty"` // for type header
	Secret string `json:"secret,omitempty"`
	// Choices lets the approver pick the secret for each request, such as a
	// personal or a work account. Secret is then empty.
	Choices []string `json:"choices,omitempty"`
}

var headerNameRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

func (c *Connection) Validate() error {
	if !nameRe.MatchString(c.Name) {
		return errors.New("connection name must match [a-z0-9][a-z0-9_-]*")
	}
	if strings.Contains(c.BaseURL, "{{") {
		return errors.New("the base url of a connection is fixed and takes no values")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return errors.New("base url must look like https://api.example.com")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("base url must not have a query or fragment")
	}
	for k, v := range c.Headers {
		if !headerNameRe.MatchString(k) || strings.Contains(v, "{{") {
			return fmt.Errorf("header %q must be a plain name with a fixed value", k)
		}
	}
	a := c.Auth
	switch a.Type {
	case "none":
		if a.Secret != "" || len(a.Choices) > 0 {
			return errors.New("auth none takes no secret")
		}
		return nil
	case "bearer", "token":
	case "header":
		if !headerNameRe.MatchString(a.Header) {
			return errors.New("auth header needs a header name")
		}
	default:
		return errors.New("auth type must be none, bearer, token or header")
	}
	if (a.Secret == "") == (len(a.Choices) == 0) {
		return errors.New("auth needs either one secret or a list of choices")
	}
	for _, n := range append([]string{a.Secret}, a.Choices...) {
		if n == "" && a.Secret == "" {
			continue
		}
		if strings.HasPrefix(n, "_") || n == ChoiceRef || !secretNameRe.MatchString(n) {
			return fmt.Errorf("bad secret name %q", n)
		}
	}
	return nil
}

func (c *Connection) authHeader() (string, string) {
	ref := "{{secret:" + c.Auth.Secret + "}}"
	if len(c.Auth.Choices) > 0 {
		ref = "{{secret:" + ChoiceRef + "}}"
	}
	switch c.Auth.Type {
	case "bearer":
		return "Authorization", "Bearer " + ref
	case "token":
		return "Authorization", "token " + ref
	case "header":
		return c.Auth.Header, ref
	}
	return "", ""
}

// Resolve turns a profile that uses a connection into a self-contained one.
// The result goes through the normal Validate and Render, so every existing
// rule still applies. Profiles without a connection come back unchanged.
func Resolve(p Profile, conns map[string]Connection) (Profile, error) {
	if p.Connection == "" {
		return p, nil
	}
	c, ok := conns[p.Connection]
	if !ok {
		return p, fmt.Errorf("unknown connection %q", p.Connection)
	}
	if err := c.Validate(); err != nil {
		return p, err
	}
	if p.HTTP == nil || p.Exec != nil {
		return p, errors.New("a profile with a connection must be an http request")
	}
	path := p.HTTP.URL
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.Contains(path, "://") || strings.Contains(path, "\\") {
		return p, errors.New("with a connection the url is a path that starts with /")
	}
	if len(p.SecretChoices) > 0 {
		return p, errors.New("secret choices belong to the connection")
	}
	h := *p.HTTP
	h.URL = strings.TrimRight(c.BaseURL, "/") + path
	h.Headers = map[string]string{}
	for k, v := range c.Headers {
		h.Headers[k] = v
	}
	ak, av := c.authHeader()
	for k, v := range p.HTTP.Headers {
		if ak != "" && strings.EqualFold(k, ak) {
			return p, fmt.Errorf("header %q is set by the connection", k)
		}
		h.Headers[k] = v
	}
	if ak != "" {
		h.Headers[ak] = av
	}
	if len(h.Headers) == 0 {
		h.Headers = nil
	}
	out := p
	out.Connection = ""
	out.HTTP = &h
	out.SecretChoices = c.Auth.Choices
	return out, nil
}
