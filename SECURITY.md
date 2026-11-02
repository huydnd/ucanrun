# Security policy

## Reporting a vulnerability

Please do not open a public issue. Use GitHub private vulnerability reporting on this repository, and include steps to reproduce.

## Scope

In scope: secret disclosure, approval bypass, authentication bypass, escaping a profile, and tampering that goes undetected.

Out of scope: a user who already has root or Docker access on the host. Read the [security model](docs/security.md) for what ucanrun does not defend against.

## Promises

These are design rules. A change that breaks one is a vulnerability.

- No API, CLI command or MCP tool returns a secret value.
- An agent cannot choose the destination host of a profile.
- An expired or unanswered request never runs.
- An approval applies to one exact action, once.
