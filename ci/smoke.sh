#!/usr/bin/env bash
# Smoke-test a built rbkeeperd binary on the machine it was built for:
#   --help, enroll, pubkey, and `run` against an unreachable server, which must log
#   the hardening it applied and keep running until SIGTERM (exit 0). On Linux it
#   also checks that plain swap still stops `run` with exit 78.
# Used by .github/workflows/ci.yml and release.yml. Usage: ci/smoke.sh PATH/TO/rbkeeperd
# Linux needs root (mlockall without a memlock limit, swapoff); it re-runs itself
# with `sudo -n`. CI only: on Linux it turns swap off on the runner.
set -euo pipefail

bin="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
os="$(uname -s)"
if [ "$os" = Linux ] && [ "$(id -u)" != 0 ]; then
    exec sudo -n bash "$0" "$bin"
fi

work="$(mktemp -d)"
pid=""
cleanup() { [ -n "$pid" ] && kill -KILL "$pid" 2>/dev/null; rm -rf "$work"; }
trap cleanup EXIT
identity="$work/state/identity.key"
fail() { echo "smoke: FAIL: $*" >&2; [ -f "$work/run.log" ] && sed 's/^/  run.log: /' "$work/run.log" >&2; exit 1; }

"$bin" --help 2>"$work/help" || fail "--help exited $?"
grep -q 'rbkeeperd run --server URL' "$work/help" || fail "--help did not print the usage"
echo "smoke: --help ok"

"$bin" enroll --identity "$identity" >"$work/enroll" 2>/dev/null || fail "enroll exited $?"
grep -Eq '^headless_id: hk1_[0-9a-f]{32}$' "$work/enroll" || fail "enroll: no headless_id"
grep -Eq '^fingerprint: rbk1-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$' "$work/enroll" || fail "enroll: no fingerprint"
if [ "$os" = Darwin ]; then mode="$(stat -f %Lp "$identity")"; else mode="$(stat -c %a "$identity")"; fi
[ "$mode" = 600 ] || fail "identity mode $mode, expected 600"
"$bin" pubkey --identity "$identity" >"$work/pubkey" 2>/dev/null || fail "pubkey exited $?"
cmp -s "$work/enroll" "$work/pubkey" || fail "pubkey differs from enroll"
echo "smoke: enroll + pubkey ok ($(grep fingerprint "$work/enroll"))"

# Port 9 (discard) on loopback: nothing listens, so `run` stays in its retry loop.
server="https://127.0.0.1:9/"
if [ "$os" = Linux ] && [ -n "$(swapon --noheadings --show=NAME 2>/dev/null)" ]; then
    rc=0
    "$bin" run --server "$server" --identity "$identity" 2>"$work/run.log" || rc=$?
    [ "$rc" = 78 ] || fail "run with plain swap exited $rc, expected 78"
    grep -q 'is not encrypted' "$work/run.log" || fail "run with plain swap: no 'is not encrypted' error"
    echo "smoke: plain swap -> exit 78 ok ($(grep -o 'active swap [^ ]*' "$work/run.log"))"
    swapoff -a
fi

"$bin" run --server "$server" --identity "$identity" 2>"$work/run.log" &
pid=$!
for _ in $(seq 1 50); do
    grep -q 'comparison code' "$work/run.log" 2>/dev/null && break
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
done
kill -0 "$pid" 2>/dev/null || { wait "$pid" || true; fail "run exited early"; }
grep -q '^INFO hardening: ' "$work/run.log" || fail "run did not log its hardening"
grep -Eq 'on boot [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} ' "$work/run.log" \
    || fail "run: the boot id is not a lowercase UUID"
kill -TERM "$pid"
rc=0
wait "$pid" || rc=$?
pid=""
[ "$rc" = 0 ] || fail "run exited $rc after SIGTERM, expected 0"
grep -q 'SIGTERM: wiping keys' "$work/run.log" || fail "run: no SIGTERM line"
echo "smoke: run ok:"
grep -E '^INFO (hardening|unlock: hk1_)' "$work/run.log" | sed 's/^/  /'
echo "smoke: all ok"
