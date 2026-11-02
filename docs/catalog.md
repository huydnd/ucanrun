# Fixed actions (advanced)

Most setups do not need this: save secrets with a description and allowed hosts, and agents write their own requests for you to approve. Use fixed actions when an agent should only fill in values you allow.

ucanrun has one general model instead of per-service code:

- A **connection** describes a service once: base URL, how to sign in, the secret, and shared headers.
- An **action** (a profile) uses a connection and states only a method, a path and the values an agent fills in.

The host and the sign-in always come from the connection, so an action can never send a secret elsewhere. Changing a connection, such as moving to a new server, updates every action on it; a change that would break an action is refused.

## Quick add

Profiles tab, **Quick add**. Pick a service, paste its token once, tick the actions agents may request, and tap **Add**. **Other service** sets up any token-based API.

The built-in list is data in `web/static/catalog.json`: GitHub, Gitea, Cloudflare, DeepSeek, Google AI, Notion, and two standalone commands that need the `exec` image: SSH (see [ssh-sudo](ssh-sudo.md)) and a read-only PostgreSQL query. The PostgreSQL entry reads a multi-field secret `postgres` (host, port, user, database public; password private) and runs each query in a read-only transaction with a 20 s statement timeout. Use a database user that only has SELECT, because that is the real limit. Every entry is validated by the test suite.

## Several accounts for one service

Edit the connection and choose **Choose when approving**, then tick the secrets. Telegram shows one **Use name** button per secret, and the result names the secret used.

## Your own templates

Put `*.json` files in `data/catalog.d/` (or `UCANRUN_CATALOG_DIR`):

```json
[{
  "service": {"name": "acme", "title": "Acme", "base_url": "https://api.acme.example/v1",
              "auth": {"type": "bearer", "secret": "acme_token"}},
  "hint": "API token with read access.",
  "actions": [
    {"title": "List orders", "profile": {"name": "acme-orders", "description": "List Acme orders",
      "risk": "low", "http": {"method": "GET", "url": "/orders"}}}
  ]
}]
```

Auth types: `bearer`, `token`, `header` (with `"header": "X-Api-Key"`) and `none`. Invalid entries are skipped and logged.

Export and import in the Profiles tab carry connections and profiles between servers. The file holds secret names, never values.

Create tokens with the narrowest scope that works. One token per service makes revoking easy.
