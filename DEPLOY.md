# Deploying rb-keeperd

Every step here is an **owner action**: run them as root on the host (below: `<host>`).
The daemon runs as a **host systemd service**, not in a container, and talks to
`https://rb.all-completed.com/` by default. Steps 0–7 are for Linux (x86_64 or arm64).
For a Mac (Apple Silicon or Intel), read step 0 and then follow [macOS](#macos) at the end.

Run the steps in order. Each step ends with a check; stop if a check fails.

## 0. What root can still do (read first)

rb-keeperd holds the vault password and the device token in RAM only:

- the pages are `mlockall`ed;
- the process is not dumpable and there are no core files;
- `ptrace_scope=3` stops any process from attaching to it;
- nothing is written to disk, the environment or argv.

**None of that protects against root on the host.** Root can still:

- load a kernel module or use `/dev/mem`/`kcore`-style access to read the daemon's memory;
- swap the binary or the unit for one that logs the secrets, then reboot. A reboot
  re-asks for approval, and this boot's comparison code looks like any other's;
- use the device token while it is live.

So whoever has root on the host can get the vault for as long as the daemon is
unlocked. Only enroll the host if you accept that. The control you keep is the
approval itself: an unlock happens only after **you** check the comparison code and
press Approve on a desktop Keeper. An unexpected unlock request means the machine
rebooted, or something is pretending to be the daemon. Deny it.

## 1. Install the binary

Install a signed release (below), or build from source (further down). Either way you end
up with `/usr/local/bin/rbkeeperd` and a directory holding `packaging/`, which steps 4
and 5 install from.

### Install from a release

Each `v*` tag publishes four archives on
[this repo's releases](https://github.com/all-completed/rb-keeperd/releases), built by
`.github/workflows/release.yml` on GitHub's runners:

| Host | Asset |
| --- | --- |
| Linux x86_64 (static, musl) | `rbkeeperd-linux-x86_64.tar.gz` |
| Linux arm64 (static, musl) | `rbkeeperd-linux-arm64.tar.gz` |
| macOS Apple Silicon | `rbkeeperd-macos-arm64.tar.gz` |
| macOS Intel | `rbkeeperd-macos-x64.tar.gz` |

Each archive is flat (no top-level directory) and holds `rbkeeperd`, README, DEPLOY,
SECURITY, LICENSE and `packaging/` (the systemd unit and sysctl file on Linux, the
launchd plist on macOS), at the same paths as in this repo. `SHA256SUMS` lists their
hashes; `SHA256SUMS.sig` + `SHA256SUMS.pem` are its keyless cosign signature and signing
certificate. `SHA256SUMS.sigstore.json` carries the same signature as a Sigstore bundle
(signature, certificate and transparency-log entry), which also verifies offline.

Download and verify, as a normal user:

```sh
asset=rbkeeperd-linux-x86_64.tar.gz      # or rbkeeperd-linux-arm64 / -macos-arm64 / -macos-x64 .tar.gz
base=https://github.com/all-completed/rb-keeperd/releases/latest/download
curl -fL -O "$base/$asset" -O "$base/SHA256SUMS" -O "$base/SHA256SUMS.sig" -O "$base/SHA256SUMS.pem"

# 1. SHA256SUMS was signed by this repo's release workflow, on a v* tag (cosign).
cosign verify-blob SHA256SUMS --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
  --certificate-identity-regexp '^https://github\.com/all-completed/rb-keeperd/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com   # → Verified OK
#    (offline: download SHA256SUMS.sigstore.json and pass --bundle SHA256SUMS.sigstore.json
#    instead of --signature/--certificate.)
# 2. The archive is the one SHA256SUMS lists.
grep " $asset\$" SHA256SUMS | sha256sum -c -                   # macOS: shasum -a 256 -c -  → OK
# 3. GitHub's build provenance: built from this repo by that workflow.
gh attestation verify "$asset" -R all-completed/rb-keeperd \
  --signer-workflow all-completed/rb-keeperd/.github/workflows/release.yml
```

Stop if any of the three fails. Then install (Linux):

```sh
mkdir rbkeeperd && tar -xzf "$asset" -C rbkeeperd && cd rbkeeperd
sudo install -o root -g root -m 0755 rbkeeperd /usr/local/bin/rbkeeperd
```

Run the remaining steps from this directory. The check at the end of "Build from source"
applies too; `file` also says `statically linked` (or `static-pie linked`).

### Build from source

```sh
# As a normal user on <host> (not root): toolchain + source.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
. "$HOME/.cargo/env"
sudo apt-get install -y build-essential pkg-config git   # or the distro's equivalent; needs a C compiler (ring); rustc ≥ 1.88

git clone https://github.com/all-completed/rb-keeperd.git && cd rb-keeperd

cargo test --locked            # all green before you install
cargo build --release --locked
sudo install -o root -g root -m 0755 target/release/rbkeeperd /usr/local/bin/rbkeeperd
```

Check: `file /usr/local/bin/rbkeeperd` names your CPU (`x86-64` or `ARM aarch64`), and
`/usr/local/bin/rbkeeperd --help` prints the usage.

## 2. Enroll the identity (once)

```sh
sudo /usr/local/bin/rbkeeperd enroll
```

This creates `/var/lib/rbkeeperd/` (mode 0700) and `identity.key` (mode 0600) and prints:

```
headless_id: hk1_…
public_key:  <base64>
fingerprint: rbk1-XXXX-XXXX-XXXX
```

It never prints the private key. If you run it again it does not replace the key;
it prints the same three lines. `sudo rbkeeperd pubkey` prints them as well.

Check:

```sh
sudo stat -c '%a %U %G' /var/lib/rbkeeperd/identity.key   # → 600 root root
sudo stat -c '%a %U'    /var/lib/rbkeeperd                # → 700 root
```

Do not copy, back up or `cat` `identity.key`. If it is lost, re-enroll.

## 3. Pin it in the desktop Keeper

On your desktop, open the Keeper, choose **Add headless Keeper** and:

1. Name it after the host, e.g. `<host>`.
2. Paste the `public_key` line from step 2. Paste the public key, never the file.
3. Check that the fingerprint the Keeper shows is **exactly** the `fingerprint` from
   step 2. If it differs, cancel and do not continue.
4. Save. The Keeper registers the key (`POST /api/keeper/headless`) and pins it in the vault.

The daemon can be approved only after this pin is in the vault.

## 4. Kernel and swap

```sh
sudo install -o root -g root -m 0644 packaging/sysctl.d/90-rbkeeperd.conf /etc/sysctl.d/90-rbkeeperd.conf
sudo sysctl --system
sysctl kernel.yama.ptrace_scope                         # → kernel.yama.ptrace_scope = 3
```

Mode 3 is one-way until the next reboot. After this, nothing on the host can attach a
debugger (`gdb -p`, `strace -p`) to any process, the daemon included. Removing the
file takes effect only after a reboot.

Swap must be **off or dm-crypt**. The daemon checks `/proc/swaps` at start and refuses
to run otherwise (exit 78).

```sh
swapon --show          # empty output = no swap = OK
```

If it lists a partition, a swap file or `zram` (zram counts as swap here):

```sh
sudo swapoff -a
# and stop it coming back: comment out the swap line in /etc/fstab, and/or
#   sudo systemctl disable --now zramswap.service   (or your distro's zram unit)
```

A Kubernetes node normally runs with swap off already. An encrypted swap (a `dm-crypt`
device whose uuid starts with `CRYPT-`, e.g. a `swap` line in `/etc/crypttab`) is
accepted as well.

The clock must be right before the daemon asks for an unlock: the server refuses an
`unlock_request` whose timestamp is more than 120 s from its own (1008 `stale timestamp`).
The unit starts `After=time-sync.target`; make that target wait for a real sync:

```sh
sudo systemctl enable systemd-time-wait-sync.service
timedatectl show -p NTPSynchronized                     # → NTPSynchronized=yes
```

On a board without a working RTC (many SBCs), the clock starts at the last shutdown
time and stays there until NTP answers. If the NTP server from DHCP is slow or missing,
add public servers:

```sh
sudo mkdir -p /etc/systemd/timesyncd.conf.d
printf '[Time]\nNTP=time.cloudflare.com pool.ntp.org\n' | sudo tee /etc/systemd/timesyncd.conf.d/90-rbkeeperd.conf
sudo systemctl restart systemd-timesyncd
```

## 5. Install and start the service

```sh
sudo install -o root -g root -m 0644 packaging/rbkeeperd.service /etc/systemd/system/rbkeeperd.service
sudo systemctl daemon-reload
sudo systemctl enable --now rbkeeperd
systemctl status rbkeeperd --no-pager
```

The unit sets these limits and sandbox options:

- `LimitCORE=0` and `LimitMEMLOCK=infinity`;
- `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp` and `MemoryDenyWriteExecute`;
- write access only to `/var/lib/rbkeeperd`;
- `CapabilityBoundingSet=CAP_IPC_LOCK`, plus the usual `Protect*`/`Restrict*` options.

To point it at another server, run `sudo systemctl edit rbkeeperd` and add:

```
[Service]
ExecStart=
ExecStart=/usr/local/bin/rbkeeperd run --server https://<your-server>/
```

## 6. Approve the unlock

```sh
journalctl -u rbkeeperd -f
```

At start the daemon logs:

```
hardening: RLIMIT_CORE=0, PR_SET_DUMPABLE 0, mlockall(MCL_CURRENT|MCL_FUTURE); swap is off or encrypted
rb-keeperd 0.2.0 for hk1_… at https://rb.all-completed.com/
unlock: hk1_… on boot <boot id> — comparison code ABCD-1234 (check it on the Keeper before approving)
unlock: request req_… is waiting for a Keeper
```

The desktop Keeper shows an approval for **<host>** with a code:

- If it matches the code in the log, press **Approve**.
- If it doesn't match, or you didn't expect a request, press **Deny**. The daemon
  then waits about an hour before it asks again.

An unanswered request expires after 300 s. The daemon then asks again with a fresh
request and the same code (the code changes only when the ephemeral key does).

After approval the log shows:

```
unlock: approved (vault format …)
keeper: connected as hk1_… (<host>)
vault: version N with M fields
```

## 7. End-to-end check

Before you start, the vault must hold a test session's (below: `mysite`) login
fields saved with **auto** on. Only all-auto, non-code fields are ever served
headlessly. A one-time code, or any field without auto, is always left for a person.

1. `sudo reboot` the host.
2. After it is back, `journalctl -u rbkeeperd -b` shows a **new** comparison code, and the
   desktop Keeper shows the approval. Compare the codes and approve.
3. **Quit every desktop Keeper** so that
   only the daemon can answer.
4. Ask for a fill on session `mysite` the usual way (e.g. the MCP `request_fill` tool on
   the `mysite` session's login page).
5. Expect:
   - the fill completes, and `get_fill_status` shows it filled;
   - `journalctl -u rbkeeperd` shows
     `fill: req… for session "mysite" on <site host> — served N field(s)`;
   - no field value appears in that log, or anywhere else in the journal.

A request the daemon cannot serve logs `— left for a person` and stays open.

## Operating

- **Restart or stop:** `systemctl restart|stop rbkeeperd`. SIGTERM wipes the keys and
  exits 0. Every start, and every reboot, needs a new approval.
- **The daemon locked itself** (the log shows `locked: …; keys wiped, asking for a new unlock`):
  this happens on a revoked token (401 or 1008), a vault key mismatch, or after
  re-keying the vault on a desktop. Approve the new request.
- **It stopped with exit 78** (`systemctl status` shows `status=78`): the server refused
  the identity (1008 `unlock_request rejected`, for example because the key isn't pinned
  or registered), there is plain swap, or the config is wrong. The unit won't restart it.
  Fix the cause, then `systemctl restart rbkeeperd`.
- **`clock is off — check NTP`** (1008 `stale timestamp`): this host's clock is more than
  120 s from the server's. This is not an exit 78: the daemon keeps running and asks again
  with a fresh timestamp after 30 s, 60 s, … up to every 5 min, so it unlocks by itself
  once NTP has set the clock. Check `timedatectl` and §4. A 1008 `replayed nonce` is
  retried at once with a fresh nonce.
- **Logs:** set `RBKEEPERD_LOG=debug` with `systemctl edit` to get more detail. The
  daemon's own lines never hold a secret at any level, and dependency crates are
  capped at `warn` so their trace output (which would include the token header) is
  never emitted.

## Rollback / removal

```sh
sudo systemctl disable --now rbkeeperd
sudo rm /etc/systemd/system/rbkeeperd.service && sudo systemctl daemon-reload
sudo rm /usr/local/bin/rbkeeperd
sudo shred -u /var/lib/rbkeeperd/identity.key && sudo rmdir /var/lib/rbkeeperd
sudo rm /etc/sysctl.d/90-rbkeeperd.conf      # ptrace_scope returns to the distro default after a reboot
```

Then, in the desktop Keeper:

1. Remove the `<host>` headless Keeper. This tombstones the pin, so the old key can
   never be approved again.
2. Revoke its `headless:<host>:*` device in the devices list.

If you skip these, the server still knows the key, but no Keeper will approve it.

## macOS

`rbkeeperd` also runs on a Mac (Apple Silicon or Intel) as a launchd daemon. Its
guarantees there are **weaker than on Linux**: read README "Limits" → macOS, and step 0,
before you enroll a Mac. Run everything as an admin user; `sudo` is root.

1. **Download and verify** as in step 1, "Install from a release", with
   `asset=rbkeeperd-macos-arm64.tar.gz` (`uname -m` → `arm64`) or
   `asset=rbkeeperd-macos-x64.tar.gz` (`uname -m` → `x86_64`). Use `shasum -a 256 -c -`.

2. **Quarantine.** The binary is ad-hoc signed (`codesign -s -`, which arm64 needs to run
   it at all) but **not notarized**. A tarball downloaded with a browser carries the
   quarantine flag, and Gatekeeper then refuses to run it. Clear the flag only after the
   verification above passed:

   ```sh
   mkdir rbkeeperd && tar -xzf "$asset" -C rbkeeperd && cd rbkeeperd
   xattr -d com.apple.quarantine rbkeeperd   # "No such xattr" is fine (curl sets no flag)
   ```

3. **Install:**

   ```sh
   sudo install -d -o root -g wheel -m 0755 /usr/local/bin
   sudo install -o root -g wheel -m 0755 rbkeeperd /usr/local/bin/rbkeeperd
   file /usr/local/bin/rbkeeperd               # → Mach-O 64-bit executable arm64 (or x86_64)
   codesign -dv /usr/local/bin/rbkeeperd 2>&1 | grep Signature   # → Signature=adhoc
   /usr/local/bin/rbkeeperd --help
   ```

4. **Enroll** (once), then pin it in the desktop Keeper exactly as in step 3:

   ```sh
   sudo /usr/local/bin/rbkeeperd enroll
   sudo stat -f '%Lp %Su' "/Library/Application Support/rbkeeperd/identity.key"   # → 600 root
   sudo stat -f '%Lp %Su' "/Library/Application Support/rbkeeperd"                # → 700 root
   ```

   The identity lives in `/Library/Application Support/rbkeeperd/identity.key`. Do not
   copy, back up or `cat` it. Keep it out of Time Machine:
   `sudo tmutil addexclusion "/Library/Application Support/rbkeeperd"`.

5. **Swap and sleep.** The daemon reads `sysctl vm.swapusage` at start and refuses to run
   (exit 78) unless it ends in `(encrypted)`, which every macOS since 10.7 does:

   ```sh
   sysctl vm.swapusage        # → vm.swapusage: total = … used = … free = …  (encrypted)
   ```

   macOS has no `ptrace_scope`; the daemon calls `ptrace(PT_DENY_ATTACH)` itself. A server
   should not sleep or hibernate (hibernation writes RAM to `/var/vm/sleepimage`):
   `sudo pmset -a sleep 0 hibernatemode 0`.

6. **Install and start the daemon:**

   ```sh
   sudo install -o root -g wheel -m 0644 packaging/macos/com.allcompleted.rbkeeperd.plist /Library/LaunchDaemons/
   sudo launchctl bootstrap system /Library/LaunchDaemons/com.allcompleted.rbkeeperd.plist
   sudo launchctl print system/com.allcompleted.rbkeeperd | grep -E 'state =|last exit code'
   ```

   It starts now and at every boot (`RunAtLoad`). To point it at another server:

   ```sh
   sudo launchctl bootout system/com.allcompleted.rbkeeperd
   sudo plutil -replace ProgramArguments.3 -string 'https://<your-server>/' /Library/LaunchDaemons/com.allcompleted.rbkeeperd.plist
   sudo launchctl bootstrap system /Library/LaunchDaemons/com.allcompleted.rbkeeperd.plist
   ```

7. **Approve** as in step 6, reading the log with `tail -f /var/log/rbkeeperd.log`. The
   first line is `hardening: RLIMIT_CORE=0, ptrace(PT_DENY_ATTACH), mlock on the daemon's own
   secret buffers (no mlockall on macOS); swap is off or encrypted`, and the boot id is
   `kern.bootsessionuuid` in lowercase. Then run the end-to-end check of step 7
   (`sudo shutdown -r now` to reboot).

**Operating on macOS.** launchd has no `RestartPreventExitStatus`, so the plist does **not**
keep the daemon alive: a restart after exit 78 would only re-ask with a refused key. The
daemon retries every transient failure itself; it exits only on SIGTERM (0), exit 78, or a
crash, and then stays down until the next boot or:

```sh
sudo launchctl kickstart -k system/com.allcompleted.rbkeeperd   # (re)start; needs a new approval
sudo launchctl kill TERM system/com.allcompleted.rbkeeperd      # stop: wipes the keys, exits 0
```

**Removal on macOS:**

```sh
sudo launchctl bootout system/com.allcompleted.rbkeeperd
sudo rm /Library/LaunchDaemons/com.allcompleted.rbkeeperd.plist /usr/local/bin/rbkeeperd
sudo rm -r "/Library/Application Support/rbkeeperd"   # APFS has no in-place overwrite (no shred)
sudo rm -f /var/log/rbkeeperd.log
```

Then remove the headless Keeper and revoke its device in the desktop Keeper, as in
"Rollback / removal".
