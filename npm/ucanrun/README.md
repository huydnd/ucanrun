# ucanrun

`ucr`, the agent side of [ucanrun](https://github.com/huydnd/ucanrun): a
credential broker for AI agents. The agent asks to run a call or a command,
you see exactly what will run and approve it, and ucanrun runs it with the
secret. The agent never sees the secret.

This package needs a ucanrun server; see the main repository to run one.

## Use it as an MCP server

```json
{
  "mcpServers": {
    "ucanrun": { "command": "npx", "args": ["-y", "ucanrun", "mcp"] }
  }
}
```

Sign in once, with the agent token from the server's **Agent tokens** tab:

```sh
npx -y ucanrun login <agent-api-url>
```

Or install it globally and call `ucr` directly:

```sh
npm install -g ucanrun
ucr login <agent-api-url>
ucr secrets
```

## How it is built

The `ucanrun` package holds a small launcher. npm installs the native build for
your system from one of `@ucanrun/linux-x64`, `@ucanrun/linux-arm64`,
`@ucanrun/darwin-x64`, `@ucanrun/darwin-arm64` and `@ucanrun/win32-x64`; no
install scripts run. Each release is published from GitHub Actions with npm
provenance, so you can check which commit and workflow built it:

```sh
npm audit signatures
```

Runners (`ucr runner`) are installed differently, as a service under their own
user: follow the **Runner** tab of your server.
