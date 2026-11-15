# Quick start

About 10 minutes.

## 0. Install

You need Docker. Download the compose file and start it:

```bash
mkdir ucanrun && cd ucanrun
curl -fsSLO https://raw.githubusercontent.com/huydnd/ucanrun/main/compose.yml
docker compose up -d
docker logs ucanrun
```

It runs `ghcr.io/huydnd/ucanrun:latest`. To run programs on the server itself, use the `latest-exec` tag; see [configuration](configuration.md).

If the port is taken: `UCANRUN_PORT=9000 docker compose up -d`. To serve from a domain:

```bash
UCANRUN_PUBLIC_URL=https://ucanrun.example.com docker compose up -d
```

## 1. Two codes from the log

The log prints an **Access code** and a **Setup token**.

| | Access code | Setup token |
|---|---|---|
| Stops | strangers reaching the web UI | someone else creating the vault first |
| Used | on every new device, for as long as you run ucanrun | once, before the vault exists |
| Lives | in `data/gate.token` or `UCANRUN_GATE_TOKEN`; `docker exec ucanrun ucr gate` shows it | in the log only; new at each start until the vault exists |

Whoever creates the vault chooses the master password and owns everything in it. The setup token proves they can read the server's log, so a leaked or reused access code is not enough to take over a fresh install. The access code can be turned off (`UCANRUN_GATE=off`, behind another access layer); the setup token cannot.

## 2. Create the vault

1. Open `http://127.0.0.1:8780` and enter the access code. Save it in a password manager.
2. Enter the setup token.
3. Choose a **master password** and save it in a password manager. It cannot be recovered.

## 3. Follow the Start tab

The Start tab walks through the steps in order. Skip any step and return to it later; **Hide guides** in a page title hides the explanations once you know them.

1. **Connect an approval channel:** Telegram, Discord, LINE or WhatsApp, under **Settings**. For Telegram, create a bot with @BotFather, paste its token, and send `/pair <code>` to the bot. The code has 6 characters, lasts 3 minutes and is cancelled after 3 wrong tries. See [approval channels](channels.md).
2. **Turn on TOTP:** scan the QR code and save the 8 recovery codes. They are shown once. Add a [passkey](passkeys.md) too: it resists phishing better than TOTP.
3. **Save a secret:** on the Secrets tab, paste the value, write one line on what it is for, and list the hosts it may be sent to, such as `api.github.com`. Without hosts, agents cannot use it in calls.
4. **Add a runner (optional):** to run commands on a machine. See [runners](runners.md).
5. **Create an agent token:** choose your agent and what it may use, then follow the commands shown for its system: download `ucr`, save the token with `ucr login`, and add ucanrun to the agent's MCP settings. The token is stored on that machine (Windows Credential Manager, or `~/.config/ucanrun` with mode 0600), not in the agent's settings file.
6. **Fixed actions (optional):** when the agent should only do the jobs you defined.

Check it on the agent's machine with `ucr doctor`, or call `list_secrets` from the agent.

## How an agent uses a secret

The agent calls the MCP tool `list_secrets`, then `call` with a header such as `Authorization: Bearer {{secret:github_token}}`. Rules:

- The URL host must be one the secret allows.
- Secrets go in headers only, never in the URL or body.
- You approve every request; the message says the agent wrote it.
- With the `exec` image, `run_command` can use secrets marked "allow in commands". These count as high risk, so they need TOTP unless every secret used is set to "No TOTP".

### Workspaces

A secret can belong to a workspace, such as Work or Personal; leave it empty for Shared. The Secrets tab filters and groups by workspace. When you create an agent token you can limit it to some workspaces: secrets elsewhere do not exist for that agent, and fixed actions that use them are hidden and refused.

### Secrets with several fields

A database login has a host, a port, a user and a password. Choose **Several fields** when saving the secret, and mark the fields agents may see, such as host, port, user and database, as **Public**. The agent then writes `{{secret:db.host}}` or `{{secret:db.password}}`.

- Public fields are shown to the agent and may go anywhere, including the URL and command arguments.
- Private fields follow the rules above and are masked in the output.
- `{{secret:db}}` without a field is refused.

For tighter control, the Actions tab defines fixed actions agents may only fill in, see [fixed actions](fixed-actions.md).

## Settings

- **Auto lock:** lock the vault after 15 minutes to 24 hours with no activity (web, approvals or agent requests). Off by default. A locked vault answers agents with error 423 until you sign in.
- **Your secret templates:** fill in the secret form, open **Save as template**, and the setup (name, workspace, notes, hosts, fields, TOTP) shows first among the templates next time. Templates never keep a secret value or a private field value. Manage them under **Settings**.

## Lost your phone

Sign in with the master password and a recovery code in the TOTP field. Each code works once. Then open **Settings**, **TOTP**, **Move to a new phone**.

Recovery codes cannot approve high risk requests.

## Install on a phone

Open the site in a browser and enter the access code.

- **Android, Chrome:** menu, then **Add to Home screen**.
- **iPhone, Safari:** Share, then **Add to Home Screen**.

iPhone keeps separate storage for home screen apps, so you enter the access code once more. There is no offline cache, so vault data stays off the device and the app needs a network.

## Daily use

An agent asks, you get a message on your approval channels, you tap **Approve** or **Deny**. No answer within 2 minutes counts as denied.

After a restart the vault is locked until you sign in. Agents get error 423 until then.

Problems: see [troubleshooting](troubleshooting.md).
