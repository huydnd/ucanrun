# Quick start

About 10 minutes.

## 0. Install

```bash
git clone <repo> && cd ucanrun
docker compose up -d
docker logs ucanrun
```

The log prints an **Access code** and a **Setup token**. No config file is needed. Open `http://127.0.0.1:8780` and enter the access code. Save it in a password manager; `docker exec ucanrun ucr gate` shows it again.

If the port is taken: `UCANRUN_PORT=9000 docker compose up -d`.

To serve from a domain, see [configuration](configuration.md):

```bash
UCANRUN_PUBLIC_URL=https://ucanrun.example.com docker compose up -d
```

## 1. Create the vault

1. Enter the setup token from the log.
2. Choose a **master password** and save it in a password manager. It cannot be recovered.

## 2. Follow the Start tab

The Start tab walks through four steps. Skip any step and return to it later with **Do this step**.

1. **Connect Telegram:** create a bot with @BotFather, paste its token, and send `/pair <code>` to the bot. The code has 6 characters, lasts 3 minutes and is cancelled after 3 wrong tries.
2. **Enable TOTP:** scan the QR code and save the 8 recovery codes. They are shown once.
3. **Save a secret:** on the Secrets tab, paste the value, write one line on what it is for, and list the hosts it may be sent to, such as `api.github.com`. Without hosts, agents cannot use it.
4. **Create an agent token:** choose your agent and the profiles it may use, then follow the instructions shown. The token goes into that agent's own MCP settings.

The agent machine needs the `ucr` command: `docker cp ucanrun:/usr/local/bin/ucr ~/.local/bin/ucr`.

Check it: `ucr profiles` with `UCANRUN_URL` and `UCANRUN_TOKEN` set, or call `list_profiles` from the agent.

## How an agent uses a secret

The agent calls the MCP tool `list_secrets`, then `call` with a header such as `Authorization: Bearer {{secret:github_token}}`. Rules:

- The URL host must be one the secret allows.
- Secrets go in headers only, never in the URL or body.
- You approve every request; the message says the agent wrote it.
- With the `exec` image, `run_command` can use secrets marked "allow in commands". These count as high risk, so they need TOTP unless every secret used is set to "No TOTP".

### Secrets with several fields

A database login has a host, a port, a user and a password. Choose **Several fields** when saving the secret, and mark the fields agents may see, such as host, port, user and database, as **Public**. The agent then writes `{{secret:db.host}}` or `{{secret:db.password}}`.

- Public fields are shown to the agent and may go anywhere, including the URL and command arguments.
- Private fields follow the rules above and are masked in the output.
- `{{secret:db}}` without a field is refused.

For tighter control, the Advanced tab defines fixed actions agents may only fill in, see [fixed actions](catalog.md).

## Lost your phone

Sign in with the master password and a recovery code in the TOTP field. Each code works once. Then open **Settings**, **TOTP**, **Move to a new phone**.

Recovery codes cannot approve high risk requests.

## Install on a phone

Open the site in a browser and enter the access code.

- **Android, Chrome:** menu, then **Add to Home screen**.
- **iPhone, Safari:** Share, then **Add to Home Screen**.

iPhone keeps separate storage for home screen apps, so you enter the access code once more. There is no offline cache, so vault data stays off the device and the app needs a network.

## Daily use

An agent asks, you get a Telegram message, you tap **Approve** or **Deny**. No answer within 2 minutes counts as denied.

After a restart the vault is locked until you sign in. Agents get error 423 until then.

Problems: see [troubleshooting](troubleshooting.md).
