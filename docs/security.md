# Security model

## What ucanrun protects against

- Secrets leaking through transcripts, logs and model context.
- Prompt injection making an agent send a secret away: the agent has none.
- An agent calling something unexpected: only declared profiles exist.
- Strangers approving on Telegram: only the paired user and chat count.
- Replay: approvals, TOTP codes and recovery codes all work once.

## What it does not protect against

- **An agent with more privilege than ucanrun.** A user in the `docker` group can enter the container. Do not put agents in that group. If you must, put a socket proxy with an allowlist in front.
- An approver who taps without reading. Read the command, not the reason. The agent writes the reason.
- A compromised destination service, or a token with too much scope.
- Root on the host.

## Layers

| Layer | How |
|---|---|
| Gate | Without the access code every web path returns 401, except `/healthz`. |
| Vault | One `age` file per secret. The key is wrapped with the master password using scrypt and is only in RAM while unlocked. |
| State | Profiles and tokens are HMAC-signed with a key derived from the vault. A modified file refuses to unlock. |
| Params | Escaped by position. Blocks `..`, control and bidi characters, and values that start a command line option. |
| Approval | Bound to a hash of the action, expires in 2 minutes, silence means no. |
| Choosing a secret | Only the approver chooses, from a declared list, recorded in the audit log. |
| Commands | Off by default. No shell, a private HOME per run, dangerous variables blocked. |
| Output | Redacts secrets and their base64, hex and URL-encoded forms. Redirects are not followed. |
| Web | No API reads a secret. HttpOnly and SameSite cookies, strict CSP, sign-in throttling. |
| Container | Not root, read-only root filesystem, no capabilities, no shell in the default image. |
| Audit | A hash chain detects edited lines. Truncating the end of the file is not detected yet. |

## When something leaks

- **Bot token:** `/revoke` with @BotFather, paste the new token in Settings, pair again.
- **Agent token:** revoke it on the Agent tokens tab and create a new one.
- **Service secret:** rotate it at the service, then save it again under the same name.
- **Master password:** change it in Settings.
- **Recovery codes:** create a new set in Settings.

## Backup

Back up the `data` volume. Secrets stay encrypted and need the master password. Keep originals of important secrets in a password manager.
