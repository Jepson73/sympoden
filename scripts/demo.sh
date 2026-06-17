#!/usr/bin/env bash
# Slice 01 end-to-end acceptance demo.
#
# Alice creates an identity, posts a signed note, pushes it to a blind relay, and
# goes fully offline. Later, Bob - a separate process, never running at the same
# time as Alice's - syncs, pulls the blob, decrypts it, verifies Alice's signature,
# and displays the note. See docs/slices/SLICE-01.md for the acceptance criteria
# this demonstrates.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Building workspace"
cargo build --workspace --quiet

echo "==> Verifying the relay has zero dependency on any crypto/identity crate"
if cargo tree -p sympoden-relay | grep -Ei 'dalek|chacha20poly1305|argon2|sha2|hkdf'; then
    echo "FAIL: sympoden-relay depends on a crypto crate - it must stay structurally blind"
    exit 1
fi
echo "OK: relay has no crypto dependency"

echo "==> Checking for telemetry/analytics-looking dependencies"
if grep -Eiq 'sentry|segment|amplitude|mixpanel|google-analytics|posthog' Cargo.lock; then
    echo "FAIL: a telemetry/analytics-looking dependency was found in Cargo.lock"
    exit 1
fi
echo "OK: no telemetry/analytics dependency found in Cargo.lock"

CLI="./target/debug/sympoden-cli"
RELAY="./target/debug/sympoden-relay"
RELAY_ADDR="127.0.0.1:18733"

WORKDIR=$(mktemp -d)
RELAY_PID=""
cleanup() {
    [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

ALICE_DIR="$WORKDIR/alice"
BOB_DIR="$WORKDIR/bob"
NOTE_BODY="hello bob, from alice - $(date +%s)"

echo "==> Starting the relay"
"$RELAY" "$RELAY_ADDR" &
RELAY_PID=$!
sleep 0.3

echo "==> Alice: init"
printf 'alice-pass\nalice-pass\n' | "$CLI" --data-dir "$ALICE_DIR" init >/dev/null

echo "==> Bob: init"
printf 'bob-pass\nbob-pass\n' | "$CLI" --data-dir "$BOB_DIR" init >/dev/null

BOB_CARD=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" whoami)

echo "==> Alice: add Bob as a peer, post a note, push it, then go fully offline"
printf 'alice-pass\n' | "$CLI" --data-dir "$ALICE_DIR" add-peer "$BOB_CARD" >/dev/null
printf 'alice-pass\n' | "$CLI" --data-dir "$ALICE_DIR" post "$NOTE_BODY" >/dev/null
printf 'alice-pass\n' | "$CLI" --data-dir "$ALICE_DIR" sync --relay "$RELAY_ADDR" >/dev/null
# Alice's process tree ends here. Nothing of hers stays running while Bob syncs.

echo "==> Bob: sync later and check the note arrived"
SYNC_OUTPUT=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" sync --relay "$RELAY_ADDR")
if ! echo "$SYNC_OUTPUT" | grep -qF "$NOTE_BODY"; then
    echo "FAIL: Bob did not receive Alice's note"
    exit 1
fi
echo "OK: Bob received and verified Alice's note via sync"

LIST_OUTPUT=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" list)
if ! echo "$LIST_OUTPUT" | grep -qF "$NOTE_BODY"; then
    echo "FAIL: note missing from Bob's local list"
    exit 1
fi
echo "OK: note appears in Bob's local list"

echo "==> Checking a wrong passphrase fails cleanly (no panic)"
set +e
WRONG_OUTPUT=$(printf 'totally-wrong\n' | "$CLI" --data-dir "$ALICE_DIR" list 2>&1)
WRONG_STATUS=$?
set -e
if [ "$WRONG_STATUS" -eq 0 ]; then
    echo "FAIL: a wrong passphrase should not succeed"
    exit 1
fi
if ! echo "$WRONG_OUTPUT" | grep -qi "incorrect passphrase"; then
    echo "FAIL: expected a clean typed error, got: $WRONG_OUTPUT"
    exit 1
fi
echo "OK: wrong passphrase fails with a typed error (exit code $WRONG_STATUS), no panic"

echo
echo "All Slice 01 acceptance criteria demonstrated successfully."
