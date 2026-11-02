# Root commands over SSH

Needs the `exec` image, see [configuration](configuration.md).

Many servers disable SSH password login, and should. ucanrun uses two layers instead:

1. A **dedicated SSH key** to log in as a normal user.
2. That user's **sudo password**, fed to `sudo -S` over standard input.

The agent sees neither, and can only run the fixed commands in the profile.

## Setup

On the target machine, as the user you will use:

```bash
ssh-keygen -t ed25519 -N "" -C ucanrun -f ~/ucanrun_key
printf 'restrict,from="172.16.0.0/12" %s\n' "$(cat ~/ucanrun_key.pub)" >> ~/.ssh/authorized_keys
cat ~/ucanrun_key
```

`restrict` turns off forwarding. `from` allows only the Docker network; change it if ucanrun runs elsewhere.

In the UI:

1. **Secrets**, name `ssh_key`, tick **Multi-line**, paste the key.
2. **Secrets**, name `sudo_password`, enter the sudo password.
3. **Profiles**, card **Restart a service over SSH**, **Customize**.
4. Edit `deploy@server.example.com` and the service list, then save.

The preview must show `stdin: ‹secret:sudo_password›` and `file id_key: ‹secret:ssh_key›`.

Then remove the key files: `rm ~/ucanrun_key ~/ucanrun_key.pub`.

If ucanrun runs on the target machine, use `host.docker.internal` and add `extra_hosts: ["host.docker.internal:host-gateway"]` to `compose.yml`.

## Rules for root profiles

- Always use **Ask and require a TOTP code**.
- Always use **Pick from a list** for agent values. `ssh` passes the command through the remote shell, so free text is command injection.
- Never make a "run any command" profile. That hands root to the agent with one extra tap.
- One job per profile.

## Limits

Host keys are not pinned: each run has a new HOME, so SSH accepts the key on first sight. Use this on a trusted network.

## Common errors

`sudo: 3 incorrect password attempts` means standard input is not the sudo password. Check the preview: it must be the password secret, not the SSH key.
