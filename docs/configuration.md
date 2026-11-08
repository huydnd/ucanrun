# Configuration

Nothing is required. All variables are optional.

| Variable | Default | Meaning |
|---|---|---|
| `UCANRUN_PUBLIC_URL` | Empty | The address people use. `https://` turns on Secure cookies and HSTS. |
| `UCANRUN_GATE_TOKEN` | Generated | The access code. When empty, one is created once in `data/gate.token`. |
| `UCANRUN_GATE` | On | `off` removes the gate. Only use it behind another access layer. |
| `UCANRUN_ENABLE_EXEC` | Off | `1` allows profiles that run programs. |
| `UCANRUN_LANG` | `en` | Telegram language, `en` or `vi`. The web UI has its own setting. |
| `UCANRUN_UNLOCK_FILE` | Empty | A file holding the master password, read at start so a restart does not lock agents out. Skips TOTP. Use a Docker secret, and read [the trade-off](security.md). |
| `UCANRUN_APPROVAL_TTL` | `2m` | How long a request waits. |
| `UCANRUN_PORT` | `8780` | Web port in `compose.yml`. |
| `UCANRUN_AGENT_PORT` | `8781` | Agent port in `compose.yml`. |

## Images

| Image | Contents | Can do |
|---|---|---|
| Default | Binary and CA roots, no shell, no tools | Call APIs |
| `exec` | Adds Alpine, `git`, `ssh`, `curl` | Call APIs and run programs |

Use the default image unless you need to run programs. The `exec` image has a larger attack surface.

```bash
docker build --target exec -t ucanrun:exec .
```

The `exec` image sets `UCANRUN_ENABLE_EXEC=1`.

## Remote access

Publish only the web port `8780`, never the agent port `8781`. Set `UCANRUN_PUBLIC_URL` to the domain.

**Caddy** gets a TLS certificate automatically:

```
ucanrun.example.com {
    reverse_proxy 127.0.0.1:8780
}
```

**Cloudflare Tunnel:** add a public hostname pointing at `ucanrun:8780`.

**Tailscale:** `tailscale serve --bg 8780`.

## Agents on another machine

The agent API is unencrypted and bound to localhost. Reach it over a private network such as Tailscale, and set `UCANRUN_URL` in the agent settings. Do not expose it to the internet.

## Releases

Pushing a `v*` tag to GitHub runs `.github/workflows/release.yml`. It builds `amd64` and `arm64` images for GHCR with an SBOM and provenance, signs them with cosign keyless, and attaches `ucr` binaries with `SHA256SUMS` to the release.

Verify an image:

```bash
cosign verify ghcr.io/<owner>/ucanrun:latest \
  --certificate-identity-regexp "https://github.com/<owner>/ucanrun/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The binaries also replace the `docker cp` step for agent machines. Then no clone is needed:

```bash
docker run -d --name ucanrun -p 127.0.0.1:8780:8780 -p 127.0.0.1:8781:8781 \
  --memory 768m -v ucanrun-data:/data ghcr.io/<owner>/ucanrun:latest
```
