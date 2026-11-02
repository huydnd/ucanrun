# Template catalog

Profiles tab, **Quick add**. Each template names the secret it needs; if the vault lacks it, a paste field appears on the card. Templates live in `internal/web/static/catalog.json` and are validated by the test suite.

| Template | Command | Secret | Approval |
|---|---|---|---|
| GitHub: list repos | `github-list-repos` | `github_token` | Ask |
| GitHub: create an issue | `github-create-issue` | `github_token` | Ask |
| Gitea: list repos (edit the URL) | `gitea-list-repos` | `gitea_token` | Ask |
| Gitea: create a private repo (edit the URL) | `gitea-create-repo` | `gitea_token` | Ask |
| Cloudflare: list domains | `cloudflare-list-zones` | `cloudflare_token` | Ask |
| Cloudflare: purge a cache | `cloudflare-purge-cache` | `cloudflare_token` | TOTP |
| DeepSeek: check balance | `deepseek-balance` | `deepseek_key` | Automatic |
| Google AI: list models | `google-ai-list-models` | `google_ai_key` | Automatic |
| Notion: search pages | `notion-search` | `notion_token` | Ask |
| GitHub: choose an account | `github-whoami` | Chosen on Telegram | Ask |
| Restart a service over SSH | `ssh-restart-service` | SSH key and sudo password | TOTP |

Some templates need **Customize**. The SSH one needs the `exec` image and [its own setup](ssh-sudo.md).

Create tokens with the narrowest scope that works. One token per job makes revoking easy.
