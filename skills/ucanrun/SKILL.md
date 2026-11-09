---
name: ucanrun
description: Use ucanrun whenever a task needs an API token, password, SSH key, database login or any other credential. ucanrun runs the request or command with the secret after a human approves, and you never see the value. Use it before asking the user for a token or looking for one in files or environment variables.
---

# ucanrun

ucanrun holds the user's secrets. You send a request with `{{secret:NAME}}`
where a secret goes; a human approves it, usually on Telegram; ucanrun runs it
and returns the output with secret values replaced by `[REDACTED]`.

You reach it through the MCP server `ucanrun` (tools below) or the `ucr` CLI.

## Steps

1. `list_secrets` (CLI: `ucr secrets`). Each secret has a name,
   notes that say how to use it, the hosts it may be sent to, and for
   multi-field secrets its fields. Public field values are shown.
2. Pick the secret the notes describe. Do not guess names.
3. For an HTTP API, use `call`: put `{{secret:NAME}}` or
   `{{secret:NAME.FIELD}}` in a header value, for example
   `Authorization: Bearer {{secret:github_token}}`. The URL host must be one
   the secret lists. Private secrets never go in the URL or body.
4. For a program, use `run_command` with an absolute `argv[0]` and no shell.
   Private secrets go in `env`, `stdin` or `files`, never in `argv`.
5. If `list_profiles` has a fixed action that fits, prefer `run`.
6. Write a short, specific `reason`. The human decides on it.
7. The answer has `state`: `done` or `failed` with `result.output`;
   `pending` means nobody answered yet (poll `get_request` with the `id`);
   `denied` and `expired` are final.

## Rules

- Never ask the user to paste a secret value, and never search files,
  history or the environment for one.
- A `denied` request is final. Tell the user; do not resend or reword it.
- An `expired` request means nobody answered in time. Ask the user whether
  to try again; do not loop.
- `[REDACTED]` in output is expected. Do not try to recover the value.

## Errors

Every refusal has a stable `code` (in the MCP error text and the CLI as
`[code: …]`) and, when only the human can fix it, `ask_human`. Pass
`ask_human` to the user word for word.

| code | meaning | what to do |
|---|---|---|
| `missing_token`, `invalid_token` | no agent token, or it was revoked | relay `ask_human` |
| `locked` | the vault is locked | relay `ask_human`, then retry once the user says so |
| `forbidden` | the token may not use that action or workspace | relay `ask_human` |
| `no_hosts` | the secret has no allowed hosts yet | relay `ask_human` (it names the host to add) |
| `host_not_allowed` | the URL host is not one the secret lists | check the notes; if the host is right, relay `ask_human` |
| `commands_not_allowed` | the secret may not be used in commands | relay `ask_human`, or use an HTTP call instead |
| `exec_off` | the server does not run commands | use an HTTP call, or relay `ask_human` |
| `unknown_secret` | no such secret or field | call `list_secrets` again |
| `needs_field` | a multi-field secret needs `.FIELD` | use `{{secret:NAME.FIELD}}` |
| `secret_placement` | a private secret is in the URL, body or argv | move it to a header, env, stdin or file |
| `no_secret_used` | the request uses no secret | run it yourself without ucanrun |
| `rate_limited` | too many requests | wait, then try once more |
| `invalid_request` | anything else | read the message and fix the request |

`ucr` exits with 77 when only the human can fix it, 75 when trying later may
work (`locked`, `rate_limited`, `pending`, `expired`), 78 for an unknown
secret or profile, 65 for a bad request, and 1 otherwise.
