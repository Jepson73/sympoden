#!/usr/bin/env bash
# Slice 01 + Slice 02 end-to-end acceptance demo.
#
# Slice 01: Alice creates an identity, posts a signed note, pushes it to a blind
# relay, and goes fully offline. Later, Bob - a separate process, never running at
# the same time as Alice's - syncs, pulls the blob, decrypts it, verifies Alice's
# signature, and displays the note. See docs/slices/SLICE-01.md.
#
# Slice 02 (TOFU): the same exchange, but now checking *who* Bob believes sent it.
# Bob receives Alice's first note before pinning her (Unknown), pins her, and the
# same note reclassifies as Known on the next listing (AC8's recompute-at-display).
# A third identity (Carol) who Bob never pins stays Unknown forever - Bob's
# single-peer cap means he can't pin her even if he tried, which this script also
# checks, along with a rejected re-pin (same label, different key) and an idempotent
# re-add (same label, same key). See docs/slices/SLICE-02.md.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Building the headless crates (engine, relay, cli)"
# Deliberately not --workspace: sympoden-app (Tauri) needs system webview libraries
# this script doesn't assume are installed. It's excluded from the workspace's
# default-members for the same reason; build it explicitly and separately once those
# prerequisites are met.
cargo build -p sympoden-engine -p sympoden-relay -p sympoden-cli --quiet

echo "==> Verifying the relay has zero dependency on any crypto/identity crate"
if cargo tree -p sympoden-relay | grep -Ei 'dalek|chacha20poly1305|argon2|sha2|hkdf'; then
    echo "FAIL: sympoden-relay depends on a crypto crate - it must stay structurally blind"
    exit 1
fi
echo "OK: relay has no crypto dependency"

echo "==> Checking for telemetry/analytics-looking dependencies"
if cargo tree -p sympoden-engine -p sympoden-relay -p sympoden-cli 2>/dev/null \
    | grep -Eiq '\b(sentry|segment|amplitude|mixpanel|google-analytics|posthog)\b'; then
    echo "FAIL: a telemetry/analytics-looking dependency was found in the headless crates"
    exit 1
fi
echo "OK: no telemetry/analytics dependency found in the headless crates"

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

ALICE_CARD=$(printf 'alice-pass\n' | "$CLI" --data-dir "$ALICE_DIR" whoami)
BOB_CARD=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" whoami)

echo "==> Alice: add Bob as a peer, post a note, push it, then go fully offline"
printf 'alice-pass\n' | "$CLI" --data-dir "$ALICE_DIR" add-peer bob "$BOB_CARD" >/dev/null
printf 'alice-pass\n' | "$CLI" --data-dir "$ALICE_DIR" post "$NOTE_BODY" >/dev/null
printf 'alice-pass\n' | "$CLI" --data-dir "$ALICE_DIR" sync --relay "$RELAY_ADDR" >/dev/null
# Alice's process tree ends here. Nothing of hers stays running while Bob syncs.

echo "==> Bob: sync later (before pinning Alice) and check the note arrived as unknown"
SYNC_OUTPUT=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" sync --relay "$RELAY_ADDR")
if ! echo "$SYNC_OUTPUT" | grep -qF "$NOTE_BODY"; then
    echo "FAIL: Bob did not receive Alice's note"
    exit 1
fi
if ! echo "$SYNC_OUTPUT" | grep -qi "unknown sender"; then
    echo "FAIL: expected the note to show as an unknown sender before Bob pins Alice"
    exit 1
fi
echo "OK: Bob received and verified Alice's note via sync, shown as unknown (not yet pinned)"

LIST_OUTPUT=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" list)
if ! echo "$LIST_OUTPUT" | grep -qF "$NOTE_BODY" || ! echo "$LIST_OUTPUT" | grep -qi "unknown sender"; then
    echo "FAIL: note missing from Bob's local list, or not shown as unknown"
    exit 1
fi
echo "OK: note appears in Bob's local list, shown as unknown sender (SLICE-02 AC2)"

echo "==> Bob: pin Alice, then re-list - the same note should reclassify as known"
printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" add-peer alice "$ALICE_CARD" >/dev/null
LIST_OUTPUT=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" list)
if ! echo "$LIST_OUTPUT" | grep -qF "$NOTE_BODY" || ! echo "$LIST_OUTPUT" | grep -q "(alice):"; then
    echo "FAIL: expected Alice's note to now show under her pinned label \"alice\""
    exit 1
fi
if echo "$LIST_OUTPUT" | grep -qi "unknown sender"; then
    echo "FAIL: Alice's note still shows as unknown after pinning her - recompute-at-display is broken"
    exit 1
fi
echo "OK: the same note reclassified from unknown to known on the next listing (SLICE-02 AC1, AC8)"

echo "==> Alice: post two notes before Bob picks up the first (no data loss)"
FIRST_BODY="first note - $(date +%s)"
SECOND_BODY="second note - $(date +%s)"
printf 'alice-pass\n' | "$CLI" --data-dir "$ALICE_DIR" post "$FIRST_BODY" >/dev/null
printf 'alice-pass\n' | "$CLI" --data-dir "$ALICE_DIR" post "$SECOND_BODY" >/dev/null
PUSH1_OUTPUT=$(printf 'alice-pass\n' | "$CLI" --data-dir "$ALICE_DIR" sync --relay "$RELAY_ADDR")
if ! echo "$PUSH1_OUTPUT" | grep -qi "stays pending"; then
    echo "FAIL: expected the relay to reject the second push (one blob per recipient)"
    exit 1
fi
printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" sync --relay "$RELAY_ADDR" >/dev/null
printf 'alice-pass\n' | "$CLI" --data-dir "$ALICE_DIR" sync --relay "$RELAY_ADDR" >/dev/null
printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" sync --relay "$RELAY_ADDR" >/dev/null
BOB_NOTES=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" list)
if ! echo "$BOB_NOTES" | grep -qF "$FIRST_BODY" || ! echo "$BOB_NOTES" | grep -qF "$SECOND_BODY"; then
    echo "FAIL: a note was lost across two posts before the peer picked up the first"
    exit 1
fi
echo "OK: both notes arrived - posting ahead of a sync never silently loses one"

CAROL_DIR="$WORKDIR/carol"
STRANGER_BODY="hello from a stranger bob never pinned - $(date +%s)"

echo "==> Carol (a stranger Bob never pins): post to Bob, who already has Alice pinned"
printf 'carol-pass\ncarol-pass\n' | "$CLI" --data-dir "$CAROL_DIR" init >/dev/null
CAROL_CARD=$(printf 'carol-pass\n' | "$CLI" --data-dir "$CAROL_DIR" whoami)
printf 'carol-pass\n' | "$CLI" --data-dir "$CAROL_DIR" add-peer bob "$BOB_CARD" >/dev/null
printf 'carol-pass\n' | "$CLI" --data-dir "$CAROL_DIR" post "$STRANGER_BODY" >/dev/null
printf 'carol-pass\n' | "$CLI" --data-dir "$CAROL_DIR" sync --relay "$RELAY_ADDR" >/dev/null

SYNC_OUTPUT=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" sync --relay "$RELAY_ADDR")
if ! echo "$SYNC_OUTPUT" | grep -qF "$STRANGER_BODY" || ! echo "$SYNC_OUTPUT" | grep -qi "unknown sender"; then
    echo "FAIL: expected Carol's note to arrive and show as an unknown sender"
    exit 1
fi
echo "OK: Carol's note arrived, shown as unknown sender - a stranger Bob never pinned"

echo "==> Bob: a second distinct label is rejected (single-peer cap, SLICE-02 D2/AC6)"
set +e
CAP_OUTPUT=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" add-peer carol "$CAROL_CARD" 2>&1)
CAP_STATUS=$?
set -e
if [ "$CAP_STATUS" -eq 0 ] || ! echo "$CAP_OUTPUT" | grep -qi "already configured"; then
    echo "FAIL: expected adding a second distinct peer to be rejected, got: $CAP_OUTPUT"
    exit 1
fi
echo "OK: a second distinct peer is rejected - Carol can never be pinned while Alice is, so her note stays unknown forever"

echo "==> Bob: re-pinning \"alice\" with a different key is rejected, the working pin survives (AC5)"
set +e
REPIN_OUTPUT=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" add-peer alice "$CAROL_CARD" 2>&1)
REPIN_STATUS=$?
set -e
if [ "$REPIN_STATUS" -eq 0 ] || ! echo "$REPIN_OUTPUT" | grep -qi "different key"; then
    echo "FAIL: expected re-pinning \"alice\" to a different key to be rejected, got: $REPIN_OUTPUT"
    exit 1
fi
LIST_OUTPUT=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" list)
if ! echo "$LIST_OUTPUT" | grep -qF "$NOTE_BODY" || ! echo "$LIST_OUTPUT" | grep -q "(alice):"; then
    echo "FAIL: Alice's pin did not survive the rejected re-pin attempt"
    exit 1
fi
echo "OK: rejected re-pin did not disturb the existing \"alice\" pin"

echo "==> Bob: re-adding \"alice\" with her actual (unchanged) card is a no-op success (AC4)"
printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" add-peer alice "$ALICE_CARD"
echo "OK: idempotent re-add succeeded"

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
echo "All Slice 01 and Slice 02 acceptance criteria demonstrated successfully."
