# Internals

ucanrun was first written in Go and is now Rust. The data directory format did
not change, so a data directory written by the Go version opens as is. The
fixtures in `testdata/golden/` were written by the last Go version, and the tests
must keep reading them:

- `datadir/` is a real data directory (vault, `state.json`, `audit.jsonl`).
  `expected.json` holds the throwaway passphrase, secret values, token, TOTP
  secret, recovery codes and the state MAC key in hex.
- `policy.json` holds policy inputs with their exact results, including error
  strings.
- `totp.json` holds TOTP vectors.

Error message strings are part of the interface: the web UI translates errors by
matching their English text.

## Data formats

- **Vault:** `identity.age` is the X25519 identity string encrypted with an age
  scrypt recipient (the passphrase). `recipient.txt` holds the public recipient.
  `secrets/<name>.age` is the value encrypted to the recipient. Files are written
  0600 through a temp file and rename; directories are 0700.
- **State MAC key:** HKDF-SHA256 with the identity string as input, no salt,
  info `ucanrun state mac v1`, 32 bytes.
- **state.json:** `{"mac": hex(HMAC-SHA256(key, data)), "data": <raw JSON>}`. The
  MAC is checked over the raw bytes of `data` as stored, never re-serialized.
- **audit.jsonl:** each line is `{time, event, actor?, fields?, prev, hash}`.
  `hash` is SHA-256 hex of the entry with `hash` set to `""`, serialized like Go's
  `encoding/json`: fields in that order, `actor` and `fields` left out when
  empty, map keys sorted, `<`, `>`, `&`, U+2028 and U+2029 escaped as `\u` codes,
  no spaces, time in RFC 3339 with nanoseconds and trailing zeros trimmed, UTC
  `Z`. `src/gojson.rs` is that writer.
- **TOTP:** RFC 6238, SHA-1, 30 s, 6 digits, steps -1 to +1, and only steps
  later than the last used one.
- **Recovery codes:** SHA-256 hex of `ucanrun recovery v1:` plus the uppercase
  code without dashes.
- **Agent tokens:** SHA-256 hex of the token string.

## Secrets with several fields

A secret may hold named fields, such as a database login. The vault stores the
JSON object `{"ucanrun_fields": {"host": "...", "password": "..."}}`; any other
value is a single-value secret.

- `{{secret:name.field}}` picks a field. `{{secret:name}}` on a multi-field
  secret is an error. Resolution tries the exact name first, then splits at the
  last dot.
- `SecretMeta.fields` lists `{name, public}`. Public fields are shown to agents
  with their values and may appear anywhere, including argv and URLs. Private
  fields follow the normal secret rules and are redacted from output.

## Modules

| Module | Role |
|---|---|
| `gojson` | JSON writer for audit hashes |
| `vault` | age-encrypted secrets, passphrase, MAC key |
| `state` | signed `state.json`, version migration |
| `audit` | hash-chained log |
| `totp` | codes and verification |
| `backup` | backup archives: create, check, restore |
| `policy` | profiles, connections, agent calls, rendering, redaction, running HTTP and exec actions |
| `core` | approvals, tokens, Telegram decisions, TOTP, lock |
| `telegram` | Bot API long poll and pairing |
| `web` | UI and agent APIs, access gate, CSRF, sessions; UI files are embedded from `web/static` |
| `client`, `mcp` | agent-side CLI and stdio MCP server |
| `main` | the `ucr` command |

URL escaping follows Go's `url.PathEscape` and `url.QueryEscape` (`policy/gourl.rs`);
the golden cases check it. Parameter patterns are anchored as `^(?:pattern)$`
and use the linear-time `regex` crate.

## Behaviour notes

- Request bodies refuse unknown keys at any depth (`web/strict.rs`); `null`
  keeps the default. Key matching is case-sensitive.
- The TOTP QR code is an SVG data URI.
- `UCANRUN_APPROVAL_TTL` takes Go duration syntax, such as `2m` or `90s`, and no
  negative values.
- The only `unsafe` code is small `libc` calls: prctl, setpgid, kill, rlimit,
  termios.
