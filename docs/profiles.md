# Creating profiles

A profile is one specific action an agent may request. The agent only fills the values you declare. The destination and the secret are fixed by you.

## The form

1. **What to do:** write one sentence. The command name is generated from it.
2. **Where to call:** prefer **Use a connection**, then write only the path. **Full URL** is for one-off calls. **Run a command** needs the `exec` image.
3. **How to authenticate:** comes from the connection. With a full URL, pick a style and a secret, or **Choose when approving on Telegram**.
4. **What the agent may fill in:** add values and pick a type. Tap a value name to insert it into the focused field.
5. **Request body:** only for POST, PUT and PATCH.
6. **Who approves:** pick a level.

**Telegram will show** displays exactly what you will see when approving. Save is enabled only when the profile is valid.

## Approval levels

| Level | Use for |
|---|---|
| Always ask me | The default, for anything that writes |
| Ask and require a TOTP code | Deletions, important changes, server commands |
| Run automatically | Harmless reads, such as a balance |

## Choosing a secret when approving

For several accounts on one service, such as personal and work GitHub.

1. In step 3, choose **Choose when approving on Telegram**.
2. Tick the secrets that may be chosen.

Telegram shows one **Use name** button per secret. The final message and the audit log name the secret used. Only you choose, never the agent. Every listed secret goes to the same address, so never list a secret from another service.

## Rules enforced for you

- Agents cannot change the host.
- Secrets cannot go in a URL or in arguments, where logs and `/proc` would show them.
- No shells or interpreters.
- No variables such as `LD_PRELOAD` or `PATH`.
- A declared value that is never used is refused.
- Values are escaped by position, and cannot add path segments, query fields or command options.

## JSON

**Advanced** on the form shows and accepts JSON. Command profiles also have `stdin`, which feeds a secret to the program, and `files`, which creates temporary 0600 files in the run directory.

```json
{
  "name": "gitea-create-repo",
  "description": "Create a private Gitea repo",
  "risk": "low",
  "params": [{"name": "repo", "pattern": "[a-z0-9._-]{1,64}", "required": true}],
  "http": {
    "method": "POST",
    "url": "https://gitea.example.com/api/v1/user/repos",
    "headers": {"Authorization": "token {{secret:gitea_token}}", "Content-Type": "application/json"},
    "body": "{\"name\":\"{{repo}}\",\"private\":true}"
  }
}
```
