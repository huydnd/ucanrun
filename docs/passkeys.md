# Passkeys

A passkey (WebAuthn) is a key held by your phone, laptop or security key,
unlocked with a fingerprint, your face or a PIN. ucanrun accepts one wherever
it asks for a TOTP code on the web:

- **Signing in:** enter the master password, then **Use a passkey instead of
  TOTP**.
- **Approving a high risk request:** **Approve with passkey** on the Requests
  tab.

TOTP and recovery codes keep working as a fallback. Approvals in Telegram,
Discord, LINE and WhatsApp still use the TOTP code.

## Why

A TOTP code can be typed into a fake page. A passkey answers only the site it
was made for, so a look-alike address gets nothing.

## Set up

Settings → **Sign-in and vault lock** → **Passkey**: give it a name and press
**Add passkey**. Adding one needs the current TOTP code, or the master
password while TOTP is off. Removing one needs the TOTP code when TOTP is on.

Add at least two, for example a phone and a security key, so losing one
device does not lock you out.

Passkeys are bound to the host in `UCANRUN_PUBLIC_URL` (for example
`ucanrun.example.com`). They need HTTPS and a host name; an IP address does
not work. For trying things out, `http://localhost` works too. Changing the
host means registering the passkeys again.

## How it is checked

- The browser is asked for user verification and no attestation. Keys may be
  ES256, EdDSA or RS256 (2048 bits or more).
- Every answer is checked for its ceremony type, a single-use challenge
  (two minutes), the exact origin, the RP id hash, the user-present and
  user-verified flags, and the signature. A signature counter that does not
  grow is refused, since it points to a copied key.
- The challenge for an approval is built from the request's hash, so an
  answer for one request cannot approve another.
- Signing in takes two steps. The first checks the master password and reads
  the passkeys without opening the vault; the second checks the passkey and
  only then opens it.
- Public keys live in the signed state file; nothing secret is stored.

## Runners that require a passkey

With `require_passkey = true` in a runner's `runner.toml`, that runner only
runs jobs approved with one of your passkeys, and checks the signature itself.
Even a server taken over while the vault is open cannot order a job there.

- The approval's challenge covers a digest of the job: the command with its
  secret placeholders, the runner and the timeout, plus the request hash and
  a nonce. The runner recomputes the digest from the job it received, so a
  command changed after approval no longer matches the signature.
- The runner checks the signature against passkeys pinned on that machine in
  `passkeys.json`, not against what the server sends with the job. They are
  pinned at enrolment; after adding or removing a passkey in the web UI, run
  `ucr runner trust-passkeys` on the runner, compare the fingerprints with
  Settings → Passkey, and confirm.
- The runner keeps each passkey's signature counter, so an old approval
  cannot be reused.
- Requests for such a runner never run by themselves and cannot be approved
  with TOTP or from a chat; the Requests tab shows only **Approve with
  passkey**.
- Approvals that pick a secret at approval time change the command after
  signing, so a runner that requires a passkey refuses them.

