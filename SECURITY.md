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
- **macOS gets weaker guarantees** than Linux: no `mlockall`, `PT_DENY_ATTACH` doesn't
  stop root, and the binary is not notarized. See README "Limits" → macOS.

## Verifying a release

Release binaries are built on GitHub's runners by `.github/workflows/release.yml`,
from a `v*` tag on `main`, and published with that workflow's own `GITHUB_TOKEN`.
Before installing one, check both:

- the keyless cosign signature on `SHA256SUMS`, bound to that workflow on a `v*` tag:
  `cosign verify-blob --bundle SHA256SUMS.sigstore.json --certificate-identity-regexp
  '^https://github\.com/all-completed/rb-keeperd/\.github/workflows/release\.yml@refs/tags/v'
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS`,
  then the archive's line in `SHA256SUMS`;
- the build provenance: `gh attestation verify <archive> -R all-completed/rb-keeperd`.

DEPLOY.md, "Install from a release", has the full commands.
