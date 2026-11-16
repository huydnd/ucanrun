<p align="center"><img src="docs/assets/logo-wordmark.svg" alt="ucanrun" width="420"></p>

# ucanrun

A credential broker for AI agents, with a human in the loop. The command is `ucr`.

Your AI agent needs a GitHub token, a database password, an SSH key. Instead of handing it over, keep it in ucanrun: the agent asks, you approve on your phone, and ucanrun uses the secret for that one call. The agent never sees it.

<p align="center"><img src="docs/assets/why.svg" alt="Without ucanrun, the AI agent holds your token: it lands in chats and logs, a tricked agent can send it anywhere, and nobody checks what it runs. With ucanrun, the agent only knows the name of the secret. It asks ucanrun, which keeps the token locked away and asks you on your phone; after you tap Approve it uses the token once. The agent never sees it, you approve each use, and every use is logged." width="100%"></p>

## How it works

1. **You save a secret** with one line saying what it is for and which hosts may receive it.
2. **The agent lists secrets** over MCP: names and descriptions, never values.
3. **The agent sends a request** with `{{secret:name}}` where the secret goes.
4. **You approve** the exact request on Telegram, Discord, LINE, WhatsApp or the web, and **ucanrun runs it** and returns a redacted result.

<p align="center"><img src="docs/assets/architecture.svg" alt="How ucanrun works. One request, start to finish: 1, the agent asks to call api.github.com and names the secret github_token instead of holding it; 2, you see the real request on your phone and approve it; 3, ucanrun takes the token from its encrypted vault and sends it only to api.github.com, or hands a signed job to a runner; 4, the agent gets the answer with any copy of the token shown as REDACTED. Who holds what: the agent machine, not trusted, holds only an agent token; the ucanrun server holds the encrypted secrets, rules and audit log; you hold TOTP and passkeys and approve; runners hold their keys and an allow list and connect out." width="100%"></p>

Commands run on **runners**: `ucr runner` on another machine, which fetches approved jobs and runs only the programs its own allow list names. See [runners](docs/runners.md).

## Why

Giving an agent a token means the token ends up in transcripts, logs and model context, and a prompt injection can send it anywhere. With ucanrun the agent has nothing to leak, and every sensitive action needs your approval.

- Single small binary, no database.
- Default image is 12 MB with no shell.
- No API or MCP tool can read a secret value.
- Approvals show the real command, not the agent's description of it.
- MCP server for Claude Code, Cursor, Codex and others.
- Works from a phone as an installable web app.

## Quick start

You need Docker. No config file, no clone:

```bash
mkdir ucanrun && cd ucanrun
curl -fsSLO https://raw.githubusercontent.com/huydnd/ucanrun/main/compose.yml
docker compose up -d
docker logs ucanrun
```

The log prints two codes:

```
ucanrun is not set up yet. Setup token: 3f9c…
Access code: Kx7…
Open http://127.0.0.1:8780/#setup=3f9c… to finish setup: the setup token is filled in.
```

1. Open the link from the last line and enter the **access code**.
2. The **setup token** is already filled in; choose a **master password**. Save the master password in a password manager: it cannot be recovered.
3. Follow the **Start** tab: connect an approval channel, turn on TOTP, save a secret, create an agent token.

Why two codes? The **access code** keeps strangers away from the web UI, and you keep using it on every new device (`docker exec ucanrun ucr gate` shows it again). The **setup token** works once, only before the vault exists: it proves that whoever creates the vault, and so chooses the master password, can read the server's log. A leaked or reused access code is then not enough to take over a fresh install.

**Agents.** On each machine where an agent runs, the **Agent tokens** tab shows the commands for your system: download `ucr`, save the token, and add ucanrun to the agent's MCP settings without touching the others.

**Runners** run commands on other machines. The **Runner** tab gives a pairing code and the install commands. `ucr` also comes as a Debian package, a Homebrew formula and a Scoop manifest; see [runners](docs/runners.md#with-a-package-manager).

More in the [quick start](docs/quickstart.md).

## Documentation

- [Quick start](docs/quickstart.md)
- [Configuration](docs/configuration.md)
- [Secret templates](docs/templates.md)
- [Agents on Windows](docs/windows.md)
- [Agent skill](skills/ucanrun/SKILL.md): copy to `~/.claude/skills/ucanrun`
- [Fixed actions (advanced)](docs/fixed-actions.md)
- [Creating profiles](docs/profiles.md)
- [Runners](docs/runners.md)
- [Approval channels](docs/channels.md)
- [Passkeys](docs/passkeys.md)
- [Security model](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)

## Development

```bash
mise install
cargo test
```

Set `UCANRUN_LIVE_TG_TOKEN` and `UCANRUN_LIVE_TG_CHAT` to run the test against the real Bot API. See [CONTRIBUTING](CONTRIBUTING.md) and [SECURITY](SECURITY.md).

## License

[MIT](LICENSE)
