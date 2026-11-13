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

## Running commands on Windows

Enroll the Windows machine as a runner (see [runners.md](runners.md)). It then
runs approved commands with the rights of your user, not as administrator:
Windows has no `sudo -S` to raise rights for one approved command.

```powershell
ucr.exe runner enroll http://ucanrun-server:8781 ABCDE-FGHJK --name pc
notepad $env:APPDATA\ucanrun\runner.toml
powershell -ExecutionPolicy Bypass -File runner-windows.ps1
```

For administrator commands, the server can still connect over SSH with a key
in `C:\ProgramData\ssh\administrators_authorized_keys`, saved in ucanrun with
**Always ask for TOTP**, through a fixed action. Do not let agents write those
commands themselves: SSH hands the command to a shell on Windows.

## WSL

A runner can also live in WSL, as a Linux runner with root through sudo. See
[runners.md](runners.md#wsl-linux-inside-windows): turn on systemd, run the
Linux steps inside WSL, and add the task that keeps WSL running.

## Limits

- The server itself does not run on Windows.
- A runner started from an elevated prompt, or from the SSH session of an
  administrator, has administrator rights. Start it with the scheduled task.
