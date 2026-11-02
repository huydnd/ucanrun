# Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Only an "Access code" field shows | This browser has not entered the code | `docker exec ucanrun ucr gate` |
| Agent gets error 423 | The vault is locked | Sign in on the web |
| No Telegram message | Vault locked, or not paired | Sign in, check Settings |
| `/pair` gets no reply | Wrong code, 3 minutes passed, or 3 wrong tries | Create a new code in Settings |
| Site shows 502 | Container down, or wrong proxy address | `docker ps`, check the proxy target |
| Setup token keeps changing | The container restarts, usually out of memory | `docker inspect ucanrun`, `mem_limit` must be 768m or more |
| `secret "x" unavailable` | The vault lacks that secret | Add it on the Secrets tab |
| No Run a command option | Using the default image | See [configuration](configuration.md) |
| Error 429 | 5 waiting requests, or 30 in 10 minutes | Wait, or handle the waiting requests |
| Cannot sign in | Too many wrong tries | Wait up to 60 seconds |
| Cannot save a profile | The reason shows under the preview | Fix what it says |

## Useful commands

```bash
docker logs --tail 50 ucanrun
docker exec ucanrun ucr audit-verify
docker exec ucanrun ucr gate
```

Logs contain no secrets. The setup token and access code are printed only until setup is finished.
