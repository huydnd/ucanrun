# Secret templates

The Secrets tab starts with templates for common services. Tap one and the form fills in the name, the notes agents read, the allowed hosts and the TOTP setting. You paste the value and save. Everything stays editable.

| Template | Secret | Hosts | Notes |
|---|---|---|---|
| GitHub | `github_token` | `api.github.com` | `Authorization: Bearer` |
| Gitea / Forgejo | `gitea_token` | change `git.example.com` to your server | `Authorization: token` |
| Cloudflare | `cloudflare_token` | `api.cloudflare.com` | |
| OpenAI | `openai_key` | `api.openai.com` | |
| Anthropic | `anthropic_key` | `api.anthropic.com` | `x-api-key` header |
| Google AI (Gemini) | `google_ai_key` | `generativelanguage.googleapis.com` | `x-goog-api-key` header |
| DeepSeek | `deepseek_key` | `api.deepseek.com` | |
| Notion | `notion_token` | `api.notion.com` | |
| PostgreSQL | `postgres`, fields host, port, user, database (public) and password | none | for `psql` with `run_command`; needs the `exec` image |
| SSH key | `ssh_key`, several lines | none | for `ssh` with `run_command`; needs the `exec` image |
| sudo password | `sudo_password` | none | always asks for TOTP; see [ssh-sudo](ssh-sudo.md) |
| Other API key | you name it | you list them | |

The notes tell agents exactly how to use the secret, for example which header to send, so they can call the API without guessing. Secrets used in commands are marked "allow in commands", which only shows when the server runs with `UCANRUN_ENABLE_EXEC=1`.

A template whose secret already exists opens that secret for editing instead.

Templates are data in `web/static/secret-templates.json`; the test suite checks that every one saves as is.
