<p align="center"><img src="docs/assets/logo-wordmark.svg" alt="ucanrun" width="260"></p>

# ucanrun

A credential broker for AI agents, with a human in the loop. The command is `ucr`.

Agents never receive a secret. An agent asks to run a **profile**, you approve on Telegram or the web, and ucanrun runs the action itself and returns a redacted result.

```
Agent ── run(profile, params) ──> ucanrun ── the real command ──> you approve on Telegram
                                     │ decrypt, run, redact
Agent <──── result ──────────────────┘
```

[Tiếng Việt](docs/vi/quickstart.md)

## Why

Giving an agent a token means the token ends up in transcripts, logs and model context, and a prompt injection can send it anywhere. With ucanrun the agent has nothing to leak, and every sensitive action needs your approval.

- Single small binary, no database.
- Default image is 12 MB with no shell.
- No API or MCP tool can read a secret value.
- Approvals show the real command, not the agent's description of it.
- MCP server for Claude Code, Cursor, Codex and others.
- Works from a phone as an installable web app.

## Quick start

```bash
git clone <repo> && cd ucanrun
docker compose up -d
docker logs ucanrun
```

No config file is needed. Open `http://127.0.0.1:8780`, enter the access code from the log, and follow the Start tab. See the [quick start](docs/quickstart.md).

## Documentation

- [Quick start](docs/quickstart.md)
- [Configuration](docs/configuration.md)
- [Services and actions](docs/catalog.md)
- [Creating profiles](docs/profiles.md)
- [Root commands over SSH](docs/ssh-sudo.md)
- [Security model](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)

## Development

```bash
mise install
go test -race ./...
```

Set `UCANRUN_LIVE_TG_TOKEN` and `UCANRUN_LIVE_TG_CHAT` to run the test against the real Bot API. See [CONTRIBUTING](CONTRIBUTING.md) and [SECURITY](SECURITY.md).

## License

[MIT](LICENSE)
