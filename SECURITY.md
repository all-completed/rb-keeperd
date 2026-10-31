# Security

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository
(Security → Report a vulnerability). Please don't open a public issue for a security bug.

## Threat model, in short

- The daemon authenticates with an Ed25519 identity that never leaves the host. Each
  unlock is sealed to a per-boot X25519 key held only in RAM. A person approves every
  unlock on a desktop Keeper after comparing a code. The server relays messages and
  never sees plaintext.
- Nothing depends on this code or the rbkeeper-unlock-v1 spec being secret.
- **Root on the host can read the vault while the daemon is unlocked.** See README
  "Limits" and DEPLOY.md §0. Enroll only hosts whose root you trust.
- **Anyone holding the account's API key** can get every field marked **auto** while
  the daemon is unlocked, by pointing a session at the stored host and requesting a
  fill. This is what "auto" means, and the desktop Keeper behaves the same way. Mark
  fields auto only if you accept that. One-time codes and `secret_request`s always
  need a person.
