// Package mcp is a stdio MCP server for agents. It deliberately has no tool that
// returns a secret.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

type Backend interface {
	Profiles(ctx context.Context) (any, error)
	Run(ctx context.Context, profile string, params map[string]string, reason string, wait int) (map[string]any, error)
	Request(ctx context.Context, id string) (map[string]any, error)
	Secrets(ctx context.Context) (any, error)
	Call(ctx context.Context, call json.RawMessage, reason string, wait int) (map[string]any, error)
}

type rpc struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

var headerMap = map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}}

var tools = []map[string]any{
	{"name": "list_secrets", "description": "List the secrets you may use: name, what it is for, and the hosts it may be sent to. Values are never shown.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
	{"name": "call", "description": "Make an HTTP request that needs a secret. Put {{secret:NAME}} in a header value, for example Authorization: Bearer {{secret:github_token}}. The URL host must be one the secret allows. Secrets are not allowed in the URL or body. A human approves the exact request on Telegram, then ucanrun sends it and returns the response with secrets redacted. Waits up to 110 s.",
		"inputSchema": map[string]any{"type": "object", "required": []string{"method", "url"}, "properties": map[string]any{
			"method":  map[string]any{"type": "string", "enum": []string{"GET", "POST", "PUT", "PATCH", "DELETE"}},
			"url":     map[string]any{"type": "string"},
			"headers": headerMap,
			"body":    map[string]any{"type": "string"},
			"reason":  map[string]any{"type": "string", "description": "Short reason shown to the approver."},
		}}},
	{"name": "run_command", "description": "Run a program with secrets, only for secrets that allow commands and only when the server enables it. argv[0] is an absolute path; there is no shell. Put {{secret:NAME}} in env, stdin or files values, never in argv. Needs approval with TOTP.",
		"inputSchema": map[string]any{"type": "object", "required": []string{"argv"}, "properties": map[string]any{
			"argv":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"env":    headerMap,
			"stdin":  map[string]any{"type": "string"},
			"files":  headerMap,
			"reason": map[string]any{"type": "string"},
		}}},
	{"name": "list_profiles", "description": "List the actions you may request, with their parameters.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
	{"name": "run", "description": "Request a profile. The server holds the credentials; a human usually approves on Telegram. Waits up to 110 s, then returns state=pending and an id for get_request.",
		"inputSchema": map[string]any{"type": "object", "required": []string{"profile"}, "properties": map[string]any{
			"profile": map[string]any{"type": "string"},
			"params":  map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
			"reason":  map[string]any{"type": "string", "description": "Short reason shown to the approver."},
		}}},
	{"name": "get_request", "description": "Get the state and result of a request.",
		"inputSchema": map[string]any{"type": "object", "required": []string{"id"}, "properties": map[string]any{"id": map[string]any{"type": "string"}}}},
}

func text(v any, isErr bool) map[string]any {
	b, _ := json.MarshalIndent(v, "", "  ")
	return map[string]any{"content": []map[string]any{{"type": "text", "text": string(b)}}, "isError": isErr}
}

func call(ctx context.Context, b Backend, raw json.RawMessage) map[string]any {
	var p struct {
		Name      string `json:"name"`
		Arguments struct {
			Profile string            `json:"profile"`
			Params  map[string]string `json:"params"`
			Reason  string            `json:"reason"`
			ID      string            `json:"id"`
			Method  string            `json:"method"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
			Body    string            `json:"body"`
			Argv    []string          `json:"argv"`
			Env     map[string]string `json:"env"`
			Stdin   string            `json:"stdin"`
			Files   map[string]string `json:"files"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return text(map[string]string{"error": "bad arguments"}, true)
	}
	var v any
	var err error
	switch p.Name {
	case "list_profiles":
		v, err = b.Profiles(ctx)
	case "run":
		v, err = b.Run(ctx, p.Arguments.Profile, p.Arguments.Params, p.Arguments.Reason, 110)
	case "list_secrets":
		v, err = b.Secrets(ctx)
	case "call":
		a := p.Arguments
		raw, _ := json.Marshal(map[string]any{"http": map[string]any{"method": a.Method, "url": a.URL, "headers": a.Headers, "body": a.Body}})
		v, err = b.Call(ctx, raw, a.Reason, 110)
	case "run_command":
		a := p.Arguments
		raw, _ := json.Marshal(map[string]any{"exec": map[string]any{"argv": a.Argv, "env": a.Env, "stdin": a.Stdin, "files": a.Files}})
		v, err = b.Call(ctx, raw, a.Reason, 110)
	case "get_request":
		v, err = b.Request(ctx, p.Arguments.ID)
	default:
		err = fmt.Errorf("unknown tool %q", p.Name)
	}
	if err != nil {
		return text(map[string]string{"error": err.Error()}, true)
	}
	return text(v, false)
}

// Serve speaks newline-delimited JSON-RPC 2.0 until in closes.
func Serve(ctx context.Context, in io.Reader, out io.Writer, b Backend) error {
	s := bufio.NewScanner(in)
	s.Buffer(make([]byte, 1<<20), 1<<20)
	enc := json.NewEncoder(out)
	for s.Scan() {
		var m rpc
		if err := json.Unmarshal(s.Bytes(), &m); err != nil {
			enc.Encode(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "parse error"}})
			continue
		}
		if len(m.ID) == 0 {
			continue // notification
		}
		var result any
		var rerr map[string]any
		switch m.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			json.Unmarshal(m.Params, &p)
			if p.ProtocolVersion == "" {
				p.ProtocolVersion = "2025-06-18"
			}
			result = map[string]any{"protocolVersion": p.ProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{"name": "ucanrun", "version": "0.1.0"}}
		case "ping":
			result = map[string]any{}
		case "tools/list":
			result = map[string]any{"tools": tools}
		case "tools/call":
			result = call(ctx, b, m.Params)
		default:
			rerr = map[string]any{"code": -32601, "message": "method not found"}
		}
		resp := map[string]any{"jsonrpc": "2.0", "id": m.ID}
		if rerr != nil {
			resp["error"] = rerr
		} else {
			resp["result"] = result
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return s.Err()
}
