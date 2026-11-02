# Rust port

The Go code in `internal/` is the reference. Port behaviour, not line by line, but
keep every security rule and every error message string identical: the web UI
translates errors by matching their English text.

Fixtures from Go live in `rs/testdata/golden/`:

- `datadir/` is a real data directory (vault, `state.json`, `audit.jsonl`).
  `expected.json` holds the passphrase, secret values, token, TOTP secret,
  recovery codes and the state MAC key in hex.
- `policy.json` holds tables of inputs and the exact Go results, including
  error strings.
- `totp.json` holds TOTP vectors.

Tests must load these files and match them exactly.

## Compatibility rules

- **Vault:** same layout as `internal/vault`. `identity.age` is the X25519 identity
  string encrypted with an age scrypt recipient (the passphrase). `recipient.txt`
  holds the public recipient. `secrets/<name>.age` is the value encrypted to the
  recipient. Files are written 0600 via temp file and rename; directories 0700.
- **State MAC key:** HKDF-SHA256 with the identity string as input, no salt,
  info `ucanrun state mac v1`, 32 bytes.
- **state.json:** `{"mac": hex(HMAC-SHA256(key, data)), "data": <raw JSON>}`. Verify
  over the raw bytes of `data` exactly as stored; never re-serialize before
  checking. JSON field names are the Go `json` tags.
- **audit.jsonl:** each line is an Entry `{time, event, actor?, fields?, prev,
  hash}`. `hash` is SHA-256 hex of the entry marshalled **the way Go's
  encoding/json does** with `hash` set to `""`: struct field order as above,
  `actor` and `fields` omitted when empty, map keys sorted, HTML characters
  `<`, `>`, `&` escaped as `<`, `>`, `&`, and U+2028 and U+2029
  escaped, no spaces, time in RFC 3339 with nanoseconds and trailing zeros
  trimmed (Go RFC3339Nano), always UTC `Z`. `src/gojson.rs` implements this
  writer for `serde_json::Value`.
- **TOTP:** RFC 6238, SHA-1, 30 s, 6 digits, accept step -1..+1 and only steps
  greater than the last used one.
- **Recovery codes:** stored as SHA-256 hex of `ucanrun recovery v1:` +
  uppercase code without dashes.
- **Agent tokens:** stored as SHA-256 hex of the token string.

## Modules

| Module | Port of | Notes |
|---|---|---|
| `gojson` | Go `encoding/json` output | `fn to_string(&serde_json::Value) -> String`, sorted keys, Go escaping |
| `vault` | `internal/vault` | `Vault::new(dir)`, `init`, `unlock`, `open` (returns identity), `adopt`, `verify`, `lock`, `is_locked`, `initialized`, `put`, `get`, `delete`, `list` (hides `_` names), `change_passphrase`, `mac_key`. `work_factor` settable for tests |
| `state` | `internal/core/state.go` | `State` struct with all Go fields, `load(path, key)`, `save(path, &State, key)`, `ErrTampered`, `ErrStateTooNew`, version migration |
| `audit` | `internal/audit` | `Log::open`, `append`, `tail`, `head`, `verify(path)`, `contains(path, count, hash)` |
| `totp` | `internal/totp` | `generate`, `uri`, `code(secret, unix)`, `verify(secret, input, unix, last) -> u64` |
| `backup` | `internal/backup` | `create`, `check`, `restore`, same limits and rules, including read-only parent and startup files |
| `policy` | `internal/policy` | Profile, Param, HTTPSpec, ExecSpec, Action, Connection, Auth, SecretMeta, Call; `validate`, `render`, `display`, `secrets`, `with_choice`, `resolve`, `from_call`, `lint`, `redact`, `run` (async) |
| `web` | `internal/web` | `Server::new`, `handler` (UI, gate, CSRF, sessions), `agent_handler`, `serve` (hyper with header timeout and graceful shutdown), `load_gate_token`, `read_catalog`, `valid_entry`. Static files are embedded from `../internal/web/static` |
| `main` | `cmd/ucr` | every command, environment variable and message of the Go CLI; arguments parsed by hand |

Go's `url.PathEscape` and `url.QueryEscape` escape different sets; reproduce
them exactly (the golden URL cases check this). Go's `regexp` is RE2; the Rust
`regex` crate has the same linear-time semantics. Patterns are anchored as
`^(?:pattern)$`.

## New: secrets with several fields

A secret may hold named fields, such as a database login. Stored in the vault as
the JSON object `{"ucanrun_fields": {"host": "...", "password": "..."}}`; any
other value is a single-value secret, so existing vaults keep working.

- Template `{{secret:name.field}}` picks a field; `{{secret:name}}` on a
  multi-field secret is an error `secret "name" has fields, use {{secret:name.FIELD}}`.
  Resolution tries the exact name first, then splits at the last dot.
- `SecretMeta` gains `fields: [{name, public}]`. Public fields (host, port, user,
  database) are shown to agents with their values and may appear anywhere,
  including argv and URL. Private fields follow the normal secret rules.
- Redaction covers every private field value.

## Web and CLI differences

- Request bodies are decoded like Go's `DisallowUnknownFields` (`web/strict.rs`):
  unknown keys at any depth are refused and `null` keeps the zero value. Key
  matching is case-sensitive, unlike Go.
- The TOTP QR code is an SVG data URI instead of a PNG.
- Times in `GET /api/secrets` and `ucr list` are UTC.
- `UCANRUN_APPROVAL_TTL` takes Go duration syntax but no negative values.

## Docker

`rs/Dockerfile` builds a static musl binary; run it from the repository root,
because the UI files come from `internal/web`:
`docker build -f rs/Dockerfile .` (slim, default) or add `--target exec`.

## Style

- No `unsafe` except the small `libc` calls (prctl, setpgid, kill, rlimit).
- Errors are `Result<T, Error>` with a crate error type whose `Display` is the
  Go message.
- Comments only where the reason is not obvious.
- `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test` must pass.
