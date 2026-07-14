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
#
# Slice 04 (receive-side consent: delete a peer, block a key): a peer can be unpinned
# (delete), reclassifying their existing notes to Unknown without erasing anything; a
# key can be blocked, independently of whether it's pinned, so a subsequently received
# note from it is decrypted/verified then dropped before storage. Delete and block are
# independently invokable, not welded together - a UI/CLI default may couple them, but
# each is separately expressible. See docs/slices/SLICE-04.md.
#
# Slice 05 (self-signed peer cards): a card's Ed25519 key now signs its paired X25519
# key, so a card whose X25519 half was substituted in transit (or whose signature was
# corrupted) is rejected before pinning, never silently accepted; a pre-Slice-05
# unsigned card gets a friendly "ask for a fresh card" message, not a generic error; a
# validly-signed card for an already-pinned identity claiming a *different* X25519 key
# is rejected loudly, naming the peer and both X25519 fingerprints, and never touches
# the stored pin. See docs/slices/SLICE-05.md.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Building the headless crates (engine, relay, cli)"
# Deliberately not --workspace: sympoden-app (Tauri) needs system webview libraries
# this script doesn't assume are installed. It's excluded from the workspace's
# default-members for the same reason; build it explicitly and separately once those
# prerequisites are met.
cargo build -p sympoden-engine -p sympoden-relay -p sympoden-cli --quiet
# mint_conflicting_card: a test-fixture-only binary (not a CLI subcommand, not shipped
# anywhere else) used solely by the Slice 05 D-C case below, where constructing a
# *validly signed* card claiming a different X25519 key requires the real Ed25519
# private key - something sympoden-cli deliberately exposes no command for (rotation is
# an explicit non-goal; see sympoden-engine/examples/mint_conflicting_card.rs).
cargo build -p sympoden-engine --example mint_conflicting_card --quiet

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
MINT_CONFLICTING_CARD="./target/debug/examples/mint_conflicting_card"

# Slice 05 helpers: a card is base64(JSON) (SLICE-05.md D-E: opaque outside Rust) - the
# only way to hand-tamper one for a demo script is to decode, edit a field, and
# re-encode. python3's stdlib json/base64 does this without a jq dependency.
tamper_card_field() {
    # usage: tamper_card_field <card-base64> <field-name> <new-value>
    python3 -c '
import base64, json, sys
card_b64, field, value = sys.argv[1], sys.argv[2], sys.argv[3]
obj = json.loads(base64.b64decode(card_b64))
obj[field] = value
print(base64.b64encode(json.dumps(obj).encode()).decode())
' "$1" "$2" "$3"
}
card_field() {
    # usage: card_field <card-base64> <field-name>
    python3 -c '
import base64, json, sys
print(json.loads(base64.b64decode(sys.argv[1]))[sys.argv[2]])
' "$1" "$2"
}
flip_signature_byte() {
    # usage: flip_signature_byte <card-base64> -> a card with the same keys/version but
    # a corrupted signature (still valid base64, different bytes).
    python3 -c '
import base64, json, sys
obj = json.loads(base64.b64decode(sys.argv[1]))
sig = bytearray(base64.b64decode(obj["signature"]))
sig[0] ^= 0xFF
obj["signature"] = base64.b64encode(bytes(sig)).decode()
print(base64.b64encode(json.dumps(obj).encode()).decode())
' "$1"
}
strip_to_legacy_shape() {
    # usage: strip_to_legacy_shape <card-base64> -> today's pre-Slice-05 shape: only
    # the two bare keys, no version/signature.
    python3 -c '
import base64, json, sys
obj = json.loads(base64.b64decode(sys.argv[1]))
legacy = {"ed25519_public": obj["ed25519_public"], "x25519_public": obj["x25519_public"]}
print(base64.b64encode(json.dumps(legacy).encode()).decode())
' "$1"
}

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

echo "==> Slice 04 setup: Kate, and five peers/strangers she'll delete/block/re-add"
KATE_DIR="$WORKDIR/kate"
LEO_DIR="$WORKDIR/leo"
MIA_DIR="$WORKDIR/mia"
NORA_DIR="$WORKDIR/nora"
OSCAR_DIR="$WORKDIR/oscar"
PAULA_DIR="$WORKDIR/paula"
QUINN_DIR="$WORKDIR/quinn"

printf 'kate-pass\nkate-pass\n' | "$CLI" --data-dir "$KATE_DIR" init >/dev/null
printf 'leo-pass\nleo-pass\n' | "$CLI" --data-dir "$LEO_DIR" init >/dev/null
printf 'mia-pass\nmia-pass\n' | "$CLI" --data-dir "$MIA_DIR" init >/dev/null
printf 'nora-pass\nnora-pass\n' | "$CLI" --data-dir "$NORA_DIR" init >/dev/null
printf 'oscar-pass\noscar-pass\n' | "$CLI" --data-dir "$OSCAR_DIR" init >/dev/null
printf 'paula-pass\npaula-pass\n' | "$CLI" --data-dir "$PAULA_DIR" init >/dev/null
printf 'quinn-pass\nquinn-pass\n' | "$CLI" --data-dir "$QUINN_DIR" init >/dev/null

KATE_CARD=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" whoami)
LEO_CARD=$(printf 'leo-pass\n' | "$CLI" --data-dir "$LEO_DIR" whoami)
MIA_CARD=$(printf 'mia-pass\n' | "$CLI" --data-dir "$MIA_DIR" whoami)
OSCAR_CARD=$(printf 'oscar-pass\n' | "$CLI" --data-dir "$OSCAR_DIR" whoami)
PAULA_CARD=$(printf 'paula-pass\n' | "$CLI" --data-dir "$PAULA_DIR" whoami)
QUINN_CARD=$(printf 'quinn-pass\n' | "$CLI" --data-dir "$QUINN_DIR" whoami)

# Kate pins everyone she'll exchange with - except Nora, who stays a stranger.
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" add-peer leo "$LEO_CARD" >/dev/null
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" add-peer mia "$MIA_CARD" >/dev/null
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" add-peer oscar "$OSCAR_CARD" >/dev/null
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" add-peer paula "$PAULA_CARD" >/dev/null
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" add-peer quinn "$QUINN_CARD" >/dev/null

# Everyone who will address Kate pins her back, including Nora the stranger - it's
# Kate who never pins Nora, which is what makes Nora's case the unpinned one.
printf 'leo-pass\n' | "$CLI" --data-dir "$LEO_DIR" add-peer kate "$KATE_CARD" >/dev/null
printf 'mia-pass\n' | "$CLI" --data-dir "$MIA_DIR" add-peer kate "$KATE_CARD" >/dev/null
printf 'nora-pass\n' | "$CLI" --data-dir "$NORA_DIR" add-peer kate "$KATE_CARD" >/dev/null
printf 'oscar-pass\n' | "$CLI" --data-dir "$OSCAR_DIR" add-peer kate "$KATE_CARD" >/dev/null
printf 'paula-pass\n' | "$CLI" --data-dir "$PAULA_DIR" add-peer kate "$KATE_CARD" >/dev/null

echo "==> Slice 04: deleting Leo (kept unblocked) reclassifies his note Unknown; re-adding repaints it Known (AC1/AC2)"
LEO_BODY="leo's first note to kate - $(date +%s)"
printf 'leo-pass\n' | "$CLI" --data-dir "$LEO_DIR" post "$LEO_BODY" --to kate >/dev/null
printf 'leo-pass\n' | "$CLI" --data-dir "$LEO_DIR" sync --relay "$RELAY_ADDR" >/dev/null
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" sync --relay "$RELAY_ADDR" >/dev/null

KATE_LIST=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" list)
if ! echo "$KATE_LIST" | grep -qF "$LEO_BODY" || ! echo "$KATE_LIST" | grep -q "leo ("; then
    echo "FAIL: expected Leo's note stored and classified Known before delete"
    exit 1
fi

printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" delete-peer leo --keep-unblocked >/dev/null
KATE_LIST=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" list)
if ! echo "$KATE_LIST" | grep -qF "$LEO_BODY" || ! echo "$KATE_LIST" | grep -qi "unknown sender"; then
    echo "FAIL: expected Leo's existing note to reclassify Unknown after delete - nothing should be erased"
    exit 1
fi
echo "OK: deleting Leo reclassified his stored note to Unknown, nothing erased from notes (AC1)"

printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" add-peer leo "$LEO_CARD" >/dev/null
KATE_LIST=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" list)
if ! echo "$KATE_LIST" | grep -qF "$LEO_BODY" || ! echo "$KATE_LIST" | grep -q "leo ("; then
    echo "FAIL: expected re-adding Leo to repaint his note back to Known in one stroke"
    exit 1
fi
echo "OK: re-adding Leo repainted his existing note back to Known, no per-note action (AC2)"

echo "==> Slice 04: deleting Oscar without blocking - his next note still arrives, unpinned but not dropped (AC5)"
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" delete-peer oscar --keep-unblocked >/dev/null
OSCAR_BODY="oscar's note after being deleted but not blocked - $(date +%s)"
printf 'oscar-pass\n' | "$CLI" --data-dir "$OSCAR_DIR" post "$OSCAR_BODY" --to kate >/dev/null
printf 'oscar-pass\n' | "$CLI" --data-dir "$OSCAR_DIR" sync --relay "$RELAY_ADDR" >/dev/null
KATE_SYNC=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" sync --relay "$RELAY_ADDR")
if ! echo "$KATE_SYNC" | grep -qF "$OSCAR_BODY"; then
    echo "FAIL: a deleted-but-unblocked sender's fresh note must still arrive, got: $KATE_SYNC"
    exit 1
fi
if ! printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" list | grep -qi "unknown sender"; then
    echo "FAIL: Oscar's note should classify Unknown - he's unpinned, just not blocked"
    exit 1
fi
echo "OK: delete-without-block let Oscar's fresh note arrive normally (Unknown, not dropped) - delete and block stayed independent (AC5)"

echo "==> Slice 04: blocking Mia (still pinned) drops her next note before storage, without unpinning her (AC3/AC5)"
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" block mia >/dev/null
BLOCKED_BODY="mia's note while blocked - $(date +%s)"
printf 'mia-pass\n' | "$CLI" --data-dir "$MIA_DIR" post "$BLOCKED_BODY" --to kate >/dev/null
printf 'mia-pass\n' | "$CLI" --data-dir "$MIA_DIR" sync --relay "$RELAY_ADDR" >/dev/null
KATE_SYNC=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" sync --relay "$RELAY_ADDR")
if ! echo "$KATE_SYNC" | grep -qi "dropped a note from a blocked sender"; then
    echo "FAIL: expected Kate to drop Mia's note while blocked, got: $KATE_SYNC"
    exit 1
fi
if printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" list | grep -qF "$BLOCKED_BODY"; then
    echo "FAIL: a dropped note must never be stored or listed"
    exit 1
fi
if ! printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" list-peers | grep -q '^mia ('; then
    echo "FAIL: blocking must not have unpinned Mia - she should still be pinned"
    exit 1
fi
echo "OK: Mia's note was decrypted/verified then dropped, never stored - her pin and Known classification untouched (AC3/AC5)"

echo "==> Slice 04: Kate's relay slot was freed by the pull despite the drop - Mia's next push succeeds immediately"
SECOND_BLOCKED_BODY="mia's second note, still blocked - $(date +%s)"
printf 'mia-pass\n' | "$CLI" --data-dir "$MIA_DIR" post "$SECOND_BLOCKED_BODY" --to kate >/dev/null
PUSH_OUTPUT=$(printf 'mia-pass\n' | "$CLI" --data-dir "$MIA_DIR" sync --relay "$RELAY_ADDR")
if ! echo "$PUSH_OUTPUT" | grep -qi "handed note .* to the relay for kate"; then
    echo "FAIL: expected Mia's push to Kate's routing key to succeed immediately - it should have been freed by the earlier drop, not left occupied"
    exit 1
fi
echo "OK: the relay slot was free - the drop happens client-side, after pulling, never holding the relay slot hostage (AC3)"

printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" unblock mia >/dev/null
KATE_SYNC=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" sync --relay "$RELAY_ADDR")
if ! echo "$KATE_SYNC" | grep -qF "$SECOND_BLOCKED_BODY"; then
    echo "FAIL: expected Mia's note to arrive normally after unblocking, got: $KATE_SYNC"
    exit 1
fi
echo "OK: unblocking let a subsequently received note through - block specifically gated the dropped one, not a general failure (AC4)"

echo "==> Slice 04: blocking an unknown sender, end to end - list prints the key, block uses it, the next note drops (D-E, AC3)"
NORA_BODY="nora's note - a stranger kate never pins - $(date +%s)"
printf 'nora-pass\n' | "$CLI" --data-dir "$NORA_DIR" post "$NORA_BODY" --to kate >/dev/null
printf 'nora-pass\n' | "$CLI" --data-dir "$NORA_DIR" sync --relay "$RELAY_ADDR" >/dev/null
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" sync --relay "$RELAY_ADDR" >/dev/null

KATE_LIST=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" list)
if ! echo "$KATE_LIST" | grep -qF "$NORA_BODY" || ! echo "$KATE_LIST" | grep -qi "unknown sender"; then
    echo "FAIL: expected Nora's note to arrive and show as unknown sender"
    exit 1
fi
# The full hex key is list's trailing field (D-E) - the only way to name a
# never-pinned sender precisely enough to block them; a fingerprint cannot be
# reversed back into one.
NORA_KEY=$(echo "$KATE_LIST" | grep -F "$NORA_BODY" | awk '{print $NF}')
if [ "${#NORA_KEY}" -ne 64 ]; then
    echo "FAIL: expected list to print Nora's full 64-hex author key as the trailing field, got: $NORA_KEY"
    exit 1
fi

printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" block "$NORA_KEY" >/dev/null
NORA_BODY2="nora's second note, after kate blocks her by key - $(date +%s)"
printf 'nora-pass\n' | "$CLI" --data-dir "$NORA_DIR" post "$NORA_BODY2" --to kate >/dev/null
printf 'nora-pass\n' | "$CLI" --data-dir "$NORA_DIR" sync --relay "$RELAY_ADDR" >/dev/null
KATE_SYNC=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" sync --relay "$RELAY_ADDR")
if ! echo "$KATE_SYNC" | grep -qi "dropped a note from a blocked sender"; then
    echo "FAIL: expected Nora's second note to be dropped after blocking her by her printed key, got: $KATE_SYNC"
    exit 1
fi
if printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" list | grep -qF "$NORA_BODY2"; then
    echo "FAIL: a dropped note must never be stored"
    exit 1
fi
echo "OK: blocked a never-pinned stranger by the exact key list printed - list, copy, block, drop, end to end (D-E, AC3)"

echo "==> Slice 04: deleting (default, coupled) and re-adding Paula leaves the block standing - the re-add path says so (D-B, AC6)"
# Deliberately not stripped of spaces (unlike EVE_FINGERPRINT above): list-blocked
# prints the same space-grouped format_fingerprint output, so the literal substring
# (spaces included) is what must match there.
PAULA_FINGERPRINT=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" list-peers \
    | grep '^paula (' | sed -E 's/^paula \(([^)]*)\)$/\1/')
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" delete-peer paula >/dev/null
if ! printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" list-blocked | grep -qF "$PAULA_FINGERPRINT"; then
    echo "FAIL: expected Paula's key to be blocked by the default coupled delete"
    exit 1
fi

READD_OUTPUT=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" add-peer paula "$PAULA_CARD")
if ! echo "$READD_OUTPUT" | grep -qi "still blocked"; then
    echo "FAIL: expected the re-add path to surface the D-B notice, got: $READD_OUTPUT"
    exit 1
fi

PAULA_BODY="paula's note after being re-added but still blocked - $(date +%s)"
printf 'paula-pass\n' | "$CLI" --data-dir "$PAULA_DIR" post "$PAULA_BODY" --to kate >/dev/null
printf 'paula-pass\n' | "$CLI" --data-dir "$PAULA_DIR" sync --relay "$RELAY_ADDR" >/dev/null
KATE_SYNC=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" sync --relay "$RELAY_ADDR")
if ! echo "$KATE_SYNC" | grep -qi "dropped a note from a blocked sender"; then
    echo "FAIL: expected a note from re-added-but-still-blocked Paula to still be dropped, got: $KATE_SYNC"
    exit 1
fi
echo "OK: re-adding Paula restored her pin but left the block standing - the re-add path warned, her mail still drops (D-B, AC6)"

echo "==> Slice 04: deleting Quinn purges her not-yet-pushed pending send; re-adding does not resurrect it (AC9)"
PENDING_BODY="kate's note addressed to quinn, never pushed before delete - $(date +%s)"
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" post "$PENDING_BODY" --to quinn >/dev/null
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" delete-peer quinn >/dev/null
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" add-peer quinn "$QUINN_CARD" >/dev/null
PUSH_AFTER_READD=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" sync --relay "$RELAY_ADDR")
if echo "$PUSH_AFTER_READD" | grep -qi "quinn"; then
    echo "FAIL: re-adding quinn must not resurrect the pending send purged by delete, got: $PUSH_AFTER_READD"
    exit 1
fi
printf 'quinn-pass\n' | "$CLI" --data-dir "$QUINN_DIR" sync --relay "$RELAY_ADDR" >/dev/null
if printf 'quinn-pass\n' | "$CLI" --data-dir "$QUINN_DIR" list | grep -qF "$PENDING_BODY"; then
    echo "FAIL: quinn must never receive a note whose pending send was purged before any push"
    exit 1
fi
echo "OK: delete purged the not-yet-pushed send; re-adding quinn did not resurrect or push it (AC9)"

echo "==> Slice 04: add-peer refuses to pin one's own card (AC7)"
SELF_OUTPUT=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" add-peer myself "$KATE_CARD")
if ! echo "$SELF_OUTPUT" | grep -qi "refusing to pin yourself"; then
    echo "FAIL: expected add-peer to refuse pinning kate's own card, got: $SELF_OUTPUT"
    exit 1
fi
if printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" list-peers | grep -q '^myself ('; then
    echo "FAIL: self-add must write nothing"
    exit 1
fi
echo "OK: add-peer refused to pin Kate's own card, nothing written (AC7)"

echo "==> Slice 05 setup: Rose, freshly pinned by Kate with a genuine v2 signed card"
ROSE_DIR="$WORKDIR/rose"
printf 'rose-pass\nrose-pass\n' | "$CLI" --data-dir "$ROSE_DIR" init >/dev/null
ROSE_CARD=$(printf 'rose-pass\n' | "$CLI" --data-dir "$ROSE_DIR" whoami)
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" add-peer rose "$ROSE_CARD" >/dev/null
if ! printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" list-peers | grep -q '^rose ('; then
    echo "FAIL: expected a freshly generated v2 signed card to pin normally"
    exit 1
fi
echo "OK: a fresh v2 signed card pinned normally through the existing add-peer flow (SLICE-05 AC1)"

echo "==> Slice 05: a card with a tampered X25519 key is rejected, nothing written (AC2)"
SIBYL_DIR="$WORKDIR/sibyl"
printf 'sibyl-pass\nsibyl-pass\n' | "$CLI" --data-dir "$SIBYL_DIR" init >/dev/null
SIBYL_CARD=$(printf 'sibyl-pass\n' | "$CLI" --data-dir "$SIBYL_DIR" whoami)
SIBYL_X25519=$(card_field "$SIBYL_CARD" x25519_public)
# A card claiming Rose's Ed25519 identity but Sibyl's X25519 key - the signature no
# longer verifies over the edited claim.
TAMPERED_X25519_CARD=$(tamper_card_field "$ROSE_CARD" x25519_public "$SIBYL_X25519")
set +e
TAMPER_OUTPUT=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" add-peer rose2 "$TAMPERED_X25519_CARD" 2>&1)
TAMPER_STATUS=$?
set -e
if [ "$TAMPER_STATUS" -eq 0 ] || ! echo "$TAMPER_OUTPUT" | grep -qi "does not verify"; then
    echo "FAIL: expected a tampered-X25519 card to be rejected with a signature error, got: $TAMPER_OUTPUT"
    exit 1
fi
if printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" list-peers | grep -q '^rose2 ('; then
    echo "FAIL: a rejected tampered card must never be pinned"
    exit 1
fi
echo "OK: a card with a substituted X25519 key was rejected before pinning, nothing written (SLICE-05 AC2)"

echo "==> Slice 05: a card with a corrupted signature is rejected, nothing written (AC4)"
TAMPERED_SIG_CARD=$(flip_signature_byte "$ROSE_CARD")
set +e
SIG_TAMPER_OUTPUT=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" add-peer rose3 "$TAMPERED_SIG_CARD" 2>&1)
SIG_TAMPER_STATUS=$?
set -e
if [ "$SIG_TAMPER_STATUS" -eq 0 ] || ! echo "$SIG_TAMPER_OUTPUT" | grep -qi "does not verify"; then
    echo "FAIL: expected a tampered-signature card to be rejected, got: $SIG_TAMPER_OUTPUT"
    exit 1
fi
if printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" list-peers | grep -q '^rose3 ('; then
    echo "FAIL: a rejected tampered-signature card must never be pinned"
    exit 1
fi
echo "OK: a card with a corrupted signature was rejected before pinning, nothing written (SLICE-05 AC4)"

echo "==> Slice 05: a legacy (pre-Slice-05, unsigned) card gets a friendly message, not a generic error (AC5)"
LEGACY_CARD=$(strip_to_legacy_shape "$SIBYL_CARD")
set +e
LEGACY_OUTPUT=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" add-peer sibyl "$LEGACY_CARD" 2>&1)
LEGACY_STATUS=$?
set -e
if [ "$LEGACY_STATUS" -eq 0 ] || ! echo "$LEGACY_OUTPUT" | grep -qi "older version of sympoden"; then
    echo "FAIL: expected a legacy-shaped card to be rejected with the friendly older-version message, got: $LEGACY_OUTPUT"
    exit 1
fi
echo "OK: a legacy unsigned card was rejected with the friendly ask-for-a-fresh-card message, not a generic error (SLICE-05 AC5)"

echo "==> Slice 05 (D-C): a validly-signed card for Rose's identity claiming a *different* X25519 key is rejected loudly, her pin untouched (AC7)"
CONFLICTING_ROSE_CARD=$("$MINT_CONFLICTING_CARD" "$ROSE_DIR/identity.keyfile.json" "rose-pass")
set +e
CONFLICT_OUTPUT=$(printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" add-peer rose "$CONFLICTING_ROSE_CARD" 2>&1)
CONFLICT_STATUS=$?
set -e
if [ "$CONFLICT_STATUS" -eq 0 ] || ! echo "$CONFLICT_OUTPUT" | grep -qi "already pinned with a different encryption key"; then
    echo "FAIL: expected the D-C conflicting-X25519 case to be rejected loudly, got: $CONFLICT_OUTPUT"
    exit 1
fi
if ! echo "$CONFLICT_OUTPUT" | grep -qi "rose ("; then
    echo "FAIL: expected the D-C rejection to name the peer (rose), got: $CONFLICT_OUTPUT"
    exit 1
fi
# Indirect proof the stored pin is untouched (the CLI has no direct "show x25519"
# command): Kate sends Rose a note using the pin as stored; it must still decrypt
# cleanly under Rose's *original* X25519 key, proving the rejected card never wrote
# through.
ROSE_PROOF_BODY="proof kate's pin of rose still uses her original key - $(date +%s)"
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" post "$ROSE_PROOF_BODY" --to rose >/dev/null
printf 'kate-pass\n' | "$CLI" --data-dir "$KATE_DIR" sync --relay "$RELAY_ADDR" >/dev/null
printf 'rose-pass\n' | "$CLI" --data-dir "$ROSE_DIR" sync --relay "$RELAY_ADDR" >/dev/null
if ! printf 'rose-pass\n' | "$CLI" --data-dir "$ROSE_DIR" list | grep -qF "$ROSE_PROOF_BODY"; then
    echo "FAIL: Rose could not decrypt a note sealed under Kate's stored pin - the rejected D-C card must have corrupted it"
    exit 1
fi
echo "OK: the D-C conflicting-X25519 card was rejected loudly, naming the peer; Kate's stored pin for Rose was left untouched (SLICE-05 D-C, AC7)"

echo
echo "All Slice 01, Slice 02, Slice 03, Slice 04, and Slice 05 acceptance criteria demonstrated successfully."
