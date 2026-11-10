# Runners

A runner is `ucr` on another machine that runs approved commands. The ucanrun
server keeps the secrets, the approvals and the audit log; the runner only asks
the server for work, checks each job against its own rules, runs it and sends
back the result.

```
 agent ──► ucanrun server ◄── runner (laptop, PC, Raspberry Pi, the server host)
           approve, sign       polls, checks, runs, signs the result
```

- **The runner connects out.** It opens no port, so it works behind NAT and on
  a laptop. It needs to reach the agent API (for example over Tailscale).
- **The runner decides.** `runner.toml` on that machine lists the programs it
  may start. A job outside it is refused even when the server approved it.
- **Secrets travel sealed.** Each job is signed by the server and carries only
  the secrets it needs, encrypted to that runner's own key. The result is
  signed by the runner. Someone who can read or change the traffic can neither
  read a secret nor forge a job or a result.

## Install ucr

Each release on GitHub carries `ucr` for every platform, and the two setup
scripts:

| System | File |
|---|---|
| Linux x86_64 (PC, WSL) | `ucr-linux-amd64` |
| Linux ARM64 (Raspberry Pi, ARM servers) | `ucr-linux-arm64` |
| macOS | `ucr-darwin-arm64`, `ucr-darwin-amd64` |
| Windows | `ucr-windows-amd64.exe` |

`https://github.com/huydnd/ucanrun/releases/latest/download/<file>` always
points at the newest one. The **Add runner** box in the web UI shows the exact
commands for each system; set `UCANRUN_DOWNLOAD_URL` on the server to download
from somewhere else, such as your own mirror.

## Enroll a runner

1. In the web UI: **Overview → Devices and rights → Add runner**. You get a
   single-use code, valid for ten minutes, and the commands to run.
2. On the machine, as the user the runner will run as (not root):

   ```sh
   ucr runner enroll http://ucanrun-server:8781 ABCDE-FGHJK --name laptop
   ```

   It prints the server key and the runner key. Compare them with the Devices
   card.
3. List the programs it may run in `runner.toml` (`~/.config/ucanrun/` on
   Linux and macOS, `%APPDATA%\ucanrun\` on Windows). By default nothing runs.
4. Start it: `ucr runner serve`, or as a service (below).

`ucr runner status` shows the keys, the user and the rules. Remove a runner in
the web UI; `ucr runner forget` deletes its keys on the machine.

## runner.toml

```toml
# Programs this runner may start, as absolute paths. "*" allows any.
allow = ["/usr/bin/systemctl", "/usr/bin/journalctl"]
# Let approved jobs run them through sudo with the password the job carries.
sudo = true
# Refuse jobs that were approved without a TOTP code.
require_totp = true
```

The file is read before every job, so changes apply at once. A mistake in it
stops every job until it is fixed; the Devices card shows the error.

Whatever the file says, the runner also applies the server's own rules: no
shells or interpreters as `argv[0]` (`sh`, `bash`, `python`, `cmd`,
`powershell`, `sudo` …), no secrets in `argv`, no environment variables that
change how a program loads.

## Commands as root

The runner runs as its own user without root. For a command that needs root,
the agent sets `sudo` to the secret that holds that user's sudo password:

```json
{"argv": ["/usr/bin/systemctl", "restart", "nginx"],
 "runner": "homeserver", "sudo": "{{secret:homeserver_sudo}}"}
```

The runner starts `sudo -S -k -- /usr/bin/systemctl restart nginx` and writes
the password to sudo's stdin. `-k` makes sudo ask every time, so root is only
ever available inside a job someone approved. sudo drops the environment, so
with `sudo` secrets go in `stdin` or `files`, not `env`.

Set the sudo secret to **allow in commands** and **always ask for TOTP**.

### Linux service

`scripts/runner-setup-linux.sh` creates the user `ucr-runner`, installs `ucr`,
and adds a systemd service. With `SUDO_CMDS` it also writes a sudo rule for
those programs and sets a random password for `ucr-runner`, shown once to be
saved in ucanrun:

```sh
sudo SUDO_CMDS="/usr/bin/systemctl /usr/bin/journalctl" sh scripts/runner-setup-linux.sh ./ucr
sudo -u ucr-runner UCANRUN_RUNNER_DIR=/var/lib/ucr-runner ucr runner enroll URL CODE --name homeserver
sudoedit /var/lib/ucr-runner/runner.toml
sudo systemctl enable --now ucr-runner
```

### Windows

Windows has no `sudo -S`, so a Windows runner runs commands with the rights of
its user, never as administrator. `scripts/runner-windows.ps1` registers a
scheduled task that starts the runner at boot with a limited token:

```powershell
ucr.exe runner enroll http://ucanrun-server:8781 ABCDE-FGHJK --name pc
notepad $env:APPDATA\ucanrun\runner.toml
powershell -ExecutionPolicy Bypass -File runner-windows.ps1   # from an elevated PowerShell
```

Paths in `runner.toml` use single quotes: `allow = ['C:\Windows\System32\ipconfig.exe']`.
A runner started from an elevated prompt, or from an SSH session of an
administrator, holds administrator rights; the Devices card then marks it
**root**.

## Agents

`list_runners` (MCP) or `ucr runners` shows each runner: online, OS, user,
whether sudo is allowed, and the programs it allows. `run_command` takes
`runner`, and `sudo` for root. A command for a runner needs no secret, but it
is always high risk, so approval asks for TOTP unless every secret it uses is
set to no TOTP.

Errors: `unknown_runner` (enroll it), `runner_offline` (start
`ucr runner serve`), and a refusal from the runner ends the request as failed
with `runner NAME refused: …`.

## What each side keeps

| Where | What |
|---|---|
| Server `state.json` | runner name, public keys, hash of its token |
| Runner `runner.json` (0600) | server URL, token, pinned server key, its own keys |
| Runner `runner.log` | one line per job, each holding the hash of the line before |

The server signs jobs with a key derived from the vault identity, so a locked
vault sends no jobs. Polls do not count as activity for the auto lock.

## Limits

- A runner sees the secrets of the jobs it runs, and can run what its
  `runner.toml` allows as its own user. It cannot read the vault.
- A server taken over while unlocked can send any job that each runner's
  rules allow. Keep `allow` short and `require_totp` on.
- Only a job's id is kept against replays, in memory until the job expires.
