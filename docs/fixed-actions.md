# Fixed actions (advanced)

Most setups do not need this: save secrets with a description and allowed hosts, and agents write their own requests for you to approve. Use fixed actions when an agent should only fill in values you allow.

ucanrun has one general model instead of per-service code:

- A **connection** describes a service once: base URL, how to sign in, the secret, and shared headers.
- An **action** (a profile) uses a connection and states only a method, a path and the values an agent fills in.

The host and the sign-in always come from the connection, so an action can never send a secret elsewhere. Changing a connection, such as moving to a new server, updates every action on it; a change that would break an action is refused.

## Adding one

Actions tab, **API services**, **Add service**: name, base URL, how to sign in and the secret. Then **New action** on that connection: method, path and the values an agent may fill in. The secret itself is saved on the Secrets tab, where [templates](templates.md) cover common services.

## Several accounts for one service

Edit the connection and choose **Choose when approving**, then tick the secrets. Telegram shows one **Use name** button per secret, and the result names the secret used.

**Back up or copy to another server** on the Actions tab carries API services and actions between servers. The file holds secret names, never values.

Create tokens with the narrowest scope that works. One token per service makes revoking easy.
