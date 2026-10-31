# rb-keeperd

`rbkeeperd` is the headless Keeper for
[remote-browser-service](https://rb.all-completed.com/).

It runs as a host service on a machine with no person in front of it (a home server,
a NAS, a small VM). After every boot it asks a desktop Keeper for approval to unlock.
Once approved it holds the vault in RAM and silently answers the auto-fills a person
already marked **auto**. That way an agent can log into a session while every desktop
Keeper is closed.

The protocol is **rbkeeper-unlock-v1**, shared with the desktop Keeper
([all-completed/remote-browser-keeper](https://github.com/all-completed/remote-browser-keeper),
`docs/rbkeeper-unlock-v1.md`). The vectors under `tests/vectors/` are synthetic and public.
Security rests on keys and on a person approving each unlock, not on the code being secret.
Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

Deploy: [DEPLOY.md](DEPLOY.md). Every step there is an owner action run as root on the host.

## Commands

```
rbkeeperd enroll [--identity PATH]   create the Ed25519 identity once (0600, root); print public key + rbk1- fingerprint
rbkeeperd pubkey [--identity PATH]   reprint them
rbkeeperd run --server URL           unlock through a desktop Keeper, then serve auto-fills
```

The identity defaults to `/var/lib/rbkeeperd/identity.key`. The commands never print
the private key, and no secret is ever read from argv or the environment.
`RBKEEPERD_LOG=debug|info|warn` sets the log level.

Exit codes:

- `0`: SIGTERM or interrupt, after wiping the keys.
- `78`: the server refused the identity (WebSocket close 1008), or the host or config is
  wrong (plain swap, a bad identity file, a failed `mlockall`). The unit doesn't restart it.
- `2`: a usage error.

## What `run` does

1. **Hardening, before any secret exists:**
   - `RLIMIT_CORE=0`, `PR_SET_DUMPABLE 0` and `mlockall(MCL_CURRENT|MCL_FUTURE)`;
   - it refuses to start if an active swap device is not dm-crypt.
2. **Unlock (spec §4–§6):**
   - It creates a fresh X25519 ephemeral key in RAM. The key is never written anywhere.
   - It signs `unlock_request` (JCS over type, headless_id, boot_id, eph_pub, ts, nonce) and
     logs the public comparison code `XXXX-XXXX`, then waits for `unlock_pending {request_id}`.
   - It accepts only an `unlock_response` whose `request_id` matches, then HPKE-opens it
     (X25519-HKDF-SHA256 / HKDF-SHA256 / ChaCha20-Poly1305, info `rbkeeper-unlock-v1|hid|boot_id`,
     aad `request_id`). After that the ephemeral key is zeroized.
   - It waits up to the server's 300 s. On timeout or cancel it retries with a fresh
     nonce and ts. Deny means about 60 min of backoff; 1013 means waiting the hour;
     1008 means stop with exit 78.
3. **Keeper connection:**
   - It connects to `/api/keeper/ws` with the device token from the unlock payload and
     sends `device_info {platform: "headless"}`.
   - It pulls the vault (`aesgcm-sha256-v2` or `aesgcm-pbkdf2-v2`), decrypts it and checks
     `secret_id`. It refreshes the vault on `vault_updated` and every 10 min.
4. **Serving (spec §9)** follows the desktop's silent-fill rule exactly:
   - It answers a `fill_request` only when every requested field has a vault entry
     (`session|host|selector`, with `host` = hostname lowercased, one `www.` stripped)
     marked auto, and no requested field is a one-time `code`.
   - Anything else gets no answer, so the request stays open for a person.
   - It never cancels or denies, and it never writes to the vault.
5. **Locking:**
   - A revoked token (401 or 1008), a vault key mismatch, or a re-keyed vault wipes the
     token, password and vault, and it asks for a new unlock.
   - SIGTERM wipes everything and exits.

## Reading of the spec

§9 is titled `secret_request`, but its rules (all fields auto, no code fields, host
normalisation) are about fill fields. The daemon reads it as **`fill_request` only**.
A `secret_request`, like a one-time code, always needs a person, so the headless
Keeper never answers one.

## Limits (read before trusting it)

- **Root on the host can read the daemon's memory**, for example with a kernel module or
  by replacing the binary before a reboot. `ptrace_scope=3` and the non-dumpable flag
  stop only non-root processes and debuggers. See DEPLOY.md §0.
- **Only buffers this crate owns are zeroized:**
  - Covered: secrets live in `secrecy::SecretString` / `zeroize::Zeroizing`, and nothing
    secret derives a printing `Debug` or `Display`.
  - Not covered: copies inside `tungstenite`, `reqwest`/`hyper`, `rustls` and `serde_json`
    (frame and body buffers). Those pages are still `mlock`ed, never swapped, never in a
    core file.
- **Dependency logs are capped at `warn`** at every level. At TRACE `tungstenite` logs
  the whole HTTP upgrade request, and that includes the `Authorization: Bearer` header.
  `tests/integration.rs` captures the logs of a full unlock+fill run and asserts that no
  secret appears in them.
- **The `hpke` crate doesn't zeroize its X25519 key by default.** `x25519-dalek` is a
  direct dependency only so that its `zeroize` feature is turned on, and a compile-time
  check in `unlock.rs` fails the build if it is lost.

## Layout and tests

```
src/identity.rs   Ed25519 identity: file checks (0600, owner, size), headless_id, rbk1- fingerprint
src/unlock.rs     unlock_request signing (JCS), comparison code, HPKE open of the payload
src/vault.rs      vault pull + decrypt (both formats), secret_id check
src/serve.rs      the silent-fill decision
src/daemon.rs     the unlock / connect / serve / lock state machine
src/hardening.rs  rlimit, dumpable, mlockall, swap check
src/logging.rs    stderr logger with the dependency cap
tests/            the spec's shared vectors + an end-to-end run against a fake server
packaging/        systemd unit and sysctl file (installed by DEPLOY.md)
```

```sh
cargo test --locked
cargo clippy --all-targets -- -D warnings
```

## License

MIT, see [LICENSE](LICENSE).
