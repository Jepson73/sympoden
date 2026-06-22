#!/usr/bin/env bash
# Slice 01 + Slice 02 + Slice 03 end-to-end acceptance demo.
#
# Slice 01: Alice creates an identity, posts a signed note, pushes it to a blind
# relay, and goes fully offline. Later, Bob - a separate process, never running at
# the same time as Alice's - syncs, pulls the blob, decrypts it, verifies Alice's
# signature, and displays the note. See docs/slices/SLICE-01.md.
#
# Slice 02 (TOFU): the same exchange, but now checking *who* Bob believes sent it.
# Bob receives Alice's first note before pinning her (Unknown), pins her, and the
# same note reclassifies as Known on the next listing (AC8's recompute-at-display).
# See docs/slices/SLICE-02.md.
#
# Slice 03 (key-as-identity + multi-peer send): a peer is identified by key, not
# label - Bob can pin a third, distinct peer (the one-peer cap is gone), and a second
# peer can share an existing label (a collision, warned-about by default, refusable
# with --strict, and resolvable via relabel-peer). A posted note can broadcast to every
# pinned peer or target a directed subset, with per-recipient delivery state so one
# occupied relay slot never blocks or duplicates delivery to anyone else.
# See docs/slices/SLICE-03.md.
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
if ! echo "$LIST_OUTPUT" | grep -qF "$NOTE_BODY" || ! echo "$LIST_OUTPUT" | grep -q "(alice ("; then
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
STRANGER_BODY="hello from a stranger bob never pins - $(date +%s)"

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

DAVE_DIR="$WORKDIR/dave"
echo "==> Bob: pinning a 2nd and 3rd distinct peer succeeds - the one-peer cap is gone (SLICE-03 AC1)"
printf 'dave-pass\ndave-pass\n' | "$CLI" --data-dir "$DAVE_DIR" init >/dev/null
DAVE_CARD=$(printf 'dave-pass\n' | "$CLI" --data-dir "$DAVE_DIR" whoami)
printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" add-peer carol "$CAROL_CARD" >/dev/null
printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" add-peer dave "$DAVE_CARD" >/dev/null
PEER_COUNT=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" list-peers | wc -l)
if [ "$PEER_COUNT" -ne 3 ]; then
    echo "FAIL: expected Bob to have 3 pinned peers (alice, carol, dave), got $PEER_COUNT"
    exit 1
fi
echo "OK: a 2nd and 3rd distinct peer pin both succeeded - no cap"

EVE_DIR="$WORKDIR/eve"
echo "==> Bob: pinning a peer under a label he already uses is a collision - warned, not blocked by default (SLICE-03 AC3)"
printf 'eve-pass\neve-pass\n' | "$CLI" --data-dir "$EVE_DIR" init >/dev/null
EVE_CARD=$(printf 'eve-pass\n' | "$CLI" --data-dir "$EVE_DIR" whoami)
COLLISION_OUTPUT=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" add-peer alice "$EVE_CARD" 2>&1)
if ! echo "$COLLISION_OUTPUT" | grep -qi "warning.*already used by a pinned peer"; then
    echo "FAIL: expected a printed collision warning, got: $COLLISION_OUTPUT"
    exit 1
fi
ALICE_LINES=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" list-peers | grep -c '^alice (')
if [ "$ALICE_LINES" -ne 2 ]; then
    echo "FAIL: expected two distinct \"alice\"-labeled peers after the collision, got $ALICE_LINES"
    exit 1
fi
echo "OK: a second \"alice\" was pinned under a different key, with a printed warning - not blocked"

MALLORY_DIR="$WORKDIR/mallory"
echo "==> Bob: a third \"alice\"-labeled peer is refused under --strict (SLICE-03 AC3, the seam's reject path)"
printf 'mallory-pass\nmallory-pass\n' | "$CLI" --data-dir "$MALLORY_DIR" init >/dev/null
MALLORY_CARD=$(printf 'mallory-pass\n' | "$CLI" --data-dir "$MALLORY_DIR" whoami)
set +e
STRICT_OUTPUT=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" add-peer alice "$MALLORY_CARD" --strict 2>&1)
STRICT_STATUS=$?
set -e
if [ "$STRICT_STATUS" -eq 0 ] || ! echo "$STRICT_OUTPUT" | grep -qi "already pinned to a different peer"; then
    echo "FAIL: expected --strict to refuse a colliding add-peer, got: $STRICT_OUTPUT"
    exit 1
fi
ALICE_LINES=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" list-peers | grep -c '^alice (')
if [ "$ALICE_LINES" -ne 2 ]; then
    echo "FAIL: --strict's refusal must not have written anything - still expected exactly 2 \"alice\" peers, got $ALICE_LINES"
    exit 1
fi
echo "OK: --strict refused the third collision and wrote nothing"

echo "==> Bob: relabeling the impostor \"alice\" (Eve) to her own name, by fingerprint (SLICE-03 AC5)"
EVE_FINGERPRINT=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" list-peers \
    | grep '^alice (' | tail -n1 | sed -E 's/^alice \(([^)]*)\)$/\1/' | tr -d ' ')
printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" relabel-peer "alice#$EVE_FINGERPRINT" eve >/dev/null
LIST_PEERS_OUTPUT=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" list-peers)
if [ "$(echo "$LIST_PEERS_OUTPUT" | grep -c '^alice (')" -ne 1 ] || ! echo "$LIST_PEERS_OUTPUT" | grep -q '^eve ('; then
    echo "FAIL: expected exactly one \"alice\" and a new \"eve\" after relabeling, got: $LIST_PEERS_OUTPUT"
    exit 1
fi
EVE_FINGERPRINT_AFTER=$(echo "$LIST_PEERS_OUTPUT" | grep '^eve (' | sed -E 's/^eve \(([^)]*)\)$/\1/' | tr -d ' ')
if [ "$EVE_FINGERPRINT_AFTER" != "$EVE_FINGERPRINT" ]; then
    echo "FAIL: relabeling must not change the peer's key/fingerprint"
    exit 1
fi
echo "OK: relabeled without touching the underlying key - fingerprint unchanged"

echo "==> Bob: re-adding Eve's card under yet another label is a loud no-op, not a silent rename (SLICE-03 AC2/Adjustment 3)"
NOOP_OUTPUT=$(printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" add-peer evelyn "$EVE_CARD" 2>&1)
if ! echo "$NOOP_OUTPUT" | grep -qi 'already pinned as "eve" - use relabel-peer to rename'; then
    echo "FAIL: expected the loud no-op message, got: $NOOP_OUTPUT"
    exit 1
fi
if printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" list-peers | grep -q '^evelyn ('; then
    echo "FAIL: add-peer must never silently create/rename a label - \"evelyn\" must not exist"
    exit 1
fi
echo "OK: same-key re-add under a new label changed nothing, loudly"

echo "==> Bob: re-adding \"alice\" with her actual (unchanged) card is a silent no-op success (SLICE-02 AC4)"
printf 'bob-pass\n' | "$CLI" --data-dir "$BOB_DIR" add-peer alice "$ALICE_CARD"
echo "OK: idempotent re-add succeeded"

echo "==> Frank/Grace/Henry/Ivan: broadcast, directed, and partial-delivery retry (SLICE-03 AC3/4/6/7)"
FRANK_DIR="$WORKDIR/frank"
GRACE_DIR="$WORKDIR/grace"
HENRY_DIR="$WORKDIR/henry"
IVAN_DIR="$WORKDIR/ivan"

printf 'frank-pass\nfrank-pass\n' | "$CLI" --data-dir "$FRANK_DIR" init >/dev/null
printf 'grace-pass\ngrace-pass\n' | "$CLI" --data-dir "$GRACE_DIR" init >/dev/null
printf 'henry-pass\nhenry-pass\n' | "$CLI" --data-dir "$HENRY_DIR" init >/dev/null
printf 'ivan-pass\nivan-pass\n' | "$CLI" --data-dir "$IVAN_DIR" init >/dev/null

FRANK_CARD=$(printf 'frank-pass\n' | "$CLI" --data-dir "$FRANK_DIR" whoami)
GRACE_CARD=$(printf 'grace-pass\n' | "$CLI" --data-dir "$GRACE_DIR" whoami)
HENRY_CARD=$(printf 'henry-pass\n' | "$CLI" --data-dir "$HENRY_DIR" whoami)

# Grace and Henry both pin Frank back, so Frank's notes classify as Known on arrival
# (mirrors SLICE-02's "Bob also pins Alice" - the multi-recipient case must prove
# labeled delivery works, not just that bytes arrive).
printf 'frank-pass\n' | "$CLI" --data-dir "$FRANK_DIR" add-peer grace "$GRACE_CARD" >/dev/null
printf 'frank-pass\n' | "$CLI" --data-dir "$FRANK_DIR" add-peer henry "$HENRY_CARD" >/dev/null
printf 'grace-pass\n' | "$CLI" --data-dir "$GRACE_DIR" add-peer frank "$FRANK_CARD" >/dev/null
printf 'henry-pass\n' | "$CLI" --data-dir "$HENRY_DIR" add-peer frank "$FRANK_CARD" >/dev/null

echo "==> Ivan (a throwaway): occupies Henry's relay slot before Frank ever pushes to him"
printf 'ivan-pass\n' | "$CLI" --data-dir "$IVAN_DIR" add-peer henry "$HENRY_CARD" >/dev/null
OCCUPYING_BODY="ivan's occupying note - $(date +%s)"
printf 'ivan-pass\n' | "$CLI" --data-dir "$IVAN_DIR" post "$OCCUPYING_BODY" >/dev/null
printf 'ivan-pass\n' | "$CLI" --data-dir "$IVAN_DIR" sync --relay "$RELAY_ADDR" >/dev/null

BROADCAST_BODY="frank's broadcast note - $(date +%s)"
printf 'frank-pass\n' | "$CLI" --data-dir "$FRANK_DIR" post "$BROADCAST_BODY" >/dev/null
PUSH_OUTPUT=$(printf 'frank-pass\n' | "$CLI" --data-dir "$FRANK_DIR" sync --relay "$RELAY_ADDR")
if ! echo "$PUSH_OUTPUT" | grep -qi "handed note .* to the relay for grace"; then
    echo "FAIL: expected the broadcast to succeed for grace, got: $PUSH_OUTPUT"
    exit 1
fi
if ! echo "$PUSH_OUTPUT" | grep -qi "henry .* stays pending"; then
    echo "FAIL: expected henry's push to bounce as occupied (his slot holds ivan's note), got: $PUSH_OUTPUT"
    exit 1
fi
echo "OK: broadcast reached grace immediately; henry's occupied slot left him pending, not blocking grace (AC6/AC7)"

GRACE_LIST=$(printf 'grace-pass\n' | "$CLI" --data-dir "$GRACE_DIR" sync --relay "$RELAY_ADDR")
if ! echo "$GRACE_LIST" | grep -qF "$BROADCAST_BODY" || ! echo "$GRACE_LIST" | grep -qi "frank ("; then
    echo "FAIL: expected grace to receive frank's broadcast note, classified as known"
    exit 1
fi
echo "OK: grace received the broadcast note, classified Known (AC3/AC5/AC8)"

HENRY_SYNC1=$(printf 'henry-pass\n' | "$CLI" --data-dir "$HENRY_DIR" sync --relay "$RELAY_ADDR")
if ! echo "$HENRY_SYNC1" | grep -qF "$OCCUPYING_BODY" || ! echo "$HENRY_SYNC1" | grep -qi "unknown sender"; then
    echo "FAIL: expected henry to first drain ivan's occupying note (unknown sender), got: $HENRY_SYNC1"
    exit 1
fi
if echo "$HENRY_SYNC1" | grep -qF "$BROADCAST_BODY"; then
    echo "FAIL: frank's broadcast note must not have reached henry yet - his slot was still occupied at push time"
    exit 1
fi
echo "OK: henry's first sync only drained the occupier, freeing his slot - frank's note has not arrived yet"

RETRY_OUTPUT=$(printf 'frank-pass\n' | "$CLI" --data-dir "$FRANK_DIR" sync --relay "$RELAY_ADDR")
if ! echo "$RETRY_OUTPUT" | grep -qi "handed note .* to the relay for henry"; then
    echo "FAIL: expected the retried push to henry to succeed now that his slot is free, got: $RETRY_OUTPUT"
    exit 1
fi
HENRY_SYNC2=$(printf 'henry-pass\n' | "$CLI" --data-dir "$HENRY_DIR" sync --relay "$RELAY_ADDR")
if ! echo "$HENRY_SYNC2" | grep -qF "$BROADCAST_BODY"; then
    echo "FAIL: expected henry to receive frank's broadcast note on the retried sync"
    exit 1
fi
HENRY_NOTES=$(printf 'henry-pass\n' | "$CLI" --data-dir "$HENRY_DIR" list)
HENRY_BODY_COUNT=$(echo "$HENRY_NOTES" | grep -cF "$BROADCAST_BODY")
if [ "$HENRY_BODY_COUNT" -ne 1 ]; then
    echo "FAIL: expected exactly one copy of frank's broadcast note in henry's list, got $HENRY_BODY_COUNT"
    exit 1
fi
echo "OK: the retried push delivered to henry exactly once - no duplicate (AC6/AC7)"

echo "==> Frank: a directed post (--to grace) reaches only grace, never henry (SLICE-03 AC4)"
DIRECTED_BODY="frank's directed note for grace only - $(date +%s)"
printf 'frank-pass\n' | "$CLI" --data-dir "$FRANK_DIR" post "$DIRECTED_BODY" --to grace >/dev/null
printf 'frank-pass\n' | "$CLI" --data-dir "$FRANK_DIR" sync --relay "$RELAY_ADDR" >/dev/null
printf 'grace-pass\n' | "$CLI" --data-dir "$GRACE_DIR" sync --relay "$RELAY_ADDR" >/dev/null
printf 'henry-pass\n' | "$CLI" --data-dir "$HENRY_DIR" sync --relay "$RELAY_ADDR" >/dev/null

if ! printf 'grace-pass\n' | "$CLI" --data-dir "$GRACE_DIR" list | grep -qF "$DIRECTED_BODY"; then
    echo "FAIL: expected grace (the directed recipient) to receive the directed note"
    exit 1
fi
if printf 'henry-pass\n' | "$CLI" --data-dir "$HENRY_DIR" list | grep -qF "$DIRECTED_BODY"; then
    echo "FAIL: henry was not in the --to list and must never receive the directed note"
    exit 1
fi
echo "OK: directed post reached only the selected recipient - checked positively and negatively"

echo "==> Frank: an unresolvable --to value fails clean, addressing nothing"
set +e
BAD_TO_OUTPUT=$(printf 'frank-pass\n' | "$CLI" --data-dir "$FRANK_DIR" post "should never be sent" --to nobody 2>&1)
BAD_TO_STATUS=$?
set -e
if [ "$BAD_TO_STATUS" -eq 0 ] || ! echo "$BAD_TO_OUTPUT" | grep -qi "no pinned peer matches"; then
    echo "FAIL: expected an unresolvable --to to fail with UnknownPeerKey, got: $BAD_TO_OUTPUT"
    exit 1
fi
if printf 'frank-pass\n' | "$CLI" --data-dir "$FRANK_DIR" list | grep -qF "should never be sent"; then
    echo "FAIL: a post whose recipient failed to resolve must never be stored - it was supposed to fail before insert_note ran"
    exit 1
fi
echo "OK: an unresolvable recipient query fails cleanly (UnknownPeerKey) before the note is ever created"

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
echo "All Slice 01, Slice 02, and Slice 03 acceptance criteria demonstrated successfully."
