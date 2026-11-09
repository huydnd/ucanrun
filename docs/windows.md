# Agents on Windows

The ucanrun server runs on Linux or macOS. Agents on Windows use `ucr.exe`, the
agent side of `ucr`: `login`, `logout`, `profiles`, `run`, `doctor` and `mcp`.

## Install

Download `ucr-windows-amd64.exe` from the releases, rename it to `ucr.exe`, and
put it in a folder on your `PATH`, such as `%USERPROFILE%\.local\bin`.

The server must be reachable from the Windows machine: over a private network
such as Tailscale, never the open internet. The agent API has no access gate.

## Sign in

```powershell
ucr login http://ucanrun-server:8781
```

Paste the agent token when asked; it is not shown. `ucr` checks it against the
server and saves the URL and token in the **Windows Credential Manager**
(entry `ucanrun`), protected by Windows for your user. Environment variables
`UCANRUN_URL` and `UCANRUN_TOKEN` still win when set.

In an SSH session the Credential Manager is not available, so `ucr` falls back
to `%APPDATA%\ucanrun\token`, which only your user can read by default.

`ucr logout` removes the saved token. `ucr doctor` checks the setup.

## Claude Code and Claude Desktop

Add the MCP server, with no token in the configuration:

```json
{
  "mcpServers": {
    "ucanrun": { "command": "ucr.exe", "args": ["mcp"] }
  }
}
```

For Claude Code, also copy `skills/ucanrun` from this repository to
`%USERPROFILE%\.claude\skills\ucanrun`, so the agent knows when and how to use
ucanrun.

## Commands that need administrator rights

`ucr.exe` only sends requests; the server runs them. To run something on the
Windows machine itself, the server connects over SSH:

1. Turn on the OpenSSH Server on Windows.
2. Make a key for ucanrun and put its public half in
   `C:\ProgramData\ssh\administrators_authorized_keys`, so sessions with it run
   as an administrator. Limit it to the server's address.
3. Save the private key in ucanrun with the **SSH key** template, set to
   **Always ask for TOTP**.
4. Create a fixed action, for example
   `powershell -NoProfile -Command Restart-Service <name>`, with the service
   picked from a list. Do not let agents write administrator commands
   themselves: SSH hands the command to a shell on Windows.

## Limits

- The server itself does not run on Windows.
- Running commands directly on Windows, without SSH, needs a runner on the
  Windows machine, which is planned (see `docs/design/runners.md`).
