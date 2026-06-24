# Slice 04 — Receive-side consent: delete a peer, block a key

The receive-side companion to Slice 03's peer-pinning work. Slices 01–03 let you pin,
relabel, and fan-out to peers, but carried forward an accepted limitation unchanged
since Slice 01: there is no way to *un*-pin a peer, and no way to stop a key's mail
from landing at all. This is the near-term code basis `docs/FOUNDATION.md` §6 already
names for Slice 04 (the block/mute/delete note, the level-split principle, and the
honesty edges) — this slice builds to that note, it does not re-derive it.

**Purely additive — nothing prior is revised.** Unlike Slice 03 (which revised Slice
02's strict-reject default), this slice changes no existing Slice 01–03 acceptance
criterion or shipped behavior. It adds two new local-only capabilities (delete a peer,
block a key) on top of unchanged primitives.

**Two of three FOUNDATION §6 mechanisms, not three.** §6 names delete, block, *and*
mute. This slice builds **delete and block only**. Mute (received-and-kept but
display-suppressed) is deliberately deferred — see NON-GOALS. So is the
mutual-connection handshake (§6's named eventual completion of this consent surface)
and anything room-level (rooms don't exist yet; the level-split principle is inherited,
not built against).

This slice does **not** touch the envelope format, the relay, the wire protocol, or
any crypto primitive.

## The properties this slice adds

> A peer can be deleted (unpinned). Because trust classification is always recomputed
> from the *current* peers table at display time (Slice 02 D3, unchanged), deleting a
> peer's pin reclassifies every note from that key — already stored, and any future
> one — to `Unknown` on the next render, with no per-note rewrite and nothing erased
> from the `notes` table. Re-adding the same key later repaints every note from it back
> to `Known`, in one stroke, the same way.

> A key can be blocked, independently of whether it is currently pinned. While a key is
> blocked, anything arriving from it on the direct path is decrypted and verified
> (unchanged), then discarded **before** it is stored — dropped, never inserted into
> `notes`, never classified, never displayed. Unblocking stops new drops; it does not
> retroactively do anything to notes already dropped (they were never kept) or already
> stored before the block began (they stay, per the no-unsend boundary, FOUNDATION §4).

> Delete and block are independent underneath: deleting a peer never touches whether
> their key is blocked, and blocking a key never touches whether it is pinned. A UI may
> couple them as one default action, but the engine exposes both as separately callable
> operations, and an engine-level test exercises each combination.

> A user cannot pin their own identity key as a peer.

> Adding, relabeling, or deleting a peer refreshes the notes list's trust
> classifications immediately, without requiring a sync — because the reclassification
> is a local recompute against already-stored notes, not a network operation.

## Design decisions

### D-A — block lives in its own table, independent of `peers`

```sql
CREATE TABLE IF NOT EXISTS blocked_keys (
    ed25519_pubkey TEXT PRIMARY KEY,
    blocked_at     INTEGER NOT NULL
);
```

No foreign key to `peers.ed25519_pubkey`, and none should be added: FOUNDATION §6 is
explicit that block must work on "anything arriving from that key" — including a key
that was never pinned at all (the stranger case). A foreign key would force a row to
exist in `peers` first, which is exactly backwards. `blocked_keys` and `peers` share
only their key encoding (hex, matching `StoredNote::author_pubkey` and
`PinnedPeer::ed25519_pubkey`), never a row.

This is the load-bearing choice in this slice. If "blocked" were a boolean column on
`peers`, then `DELETE FROM peers WHERE ed25519_pubkey = ?` (delete) would silently
erase the block as a side effect of removing the row — welding delete and block
together underneath, which is exactly what FOUNDATION §6's "separable underneath"
forbids. A separate table makes that weld structurally impossible: deleting a peer
issues no SQL against `blocked_keys` at all, and blocking a key issues no SQL against
`peers` at all. Each operation only ever touches its own table.

**Recommendation: adopt as specified.** I see no reason to deviate.

### D-B — re-adding a deleted-and-blocked peer restores the name, leaves the block standing

Direct consequence of D-A's independence: `add_peer` only ever writes to `peers`, so
re-pinning a previously deleted key has zero effect on a standing row in
`blocked_keys`. The intended behavior, stated explicitly rather than left to fall out
silently: after delete-and-block, then re-add, the peer's notes repaint `Known` again
(trust reclassification, free, via D-A's independence) — but their *mail still does not
arrive*, because the block was never lifted. This is a sharp edge if undiscovered: a
user reasonably reads "I re-added them" as "we're back to normal," and nothing in the
re-add flow tells them otherwise.

**Recommendation: yes, surface it at re-add time.** After a successful `add_peer`, the
call site (CLI/app) checks `is_blocked` on that key and, if true, says so plainly —
e.g. `"alice" pinned. Note: this key is still blocked — mail from them will keep being
dropped until you unblock it.` This is a UI-layer check (one extra `Store::is_blocked`
call after `add_peer` succeeds), not new engine coupling between the two tables —
consistent with "couple at the UI, never weld underneath." Silently leaving this
undiscoverable would violate invariant #6 (honest about limits) the same way an
unannounced block would.

Covered by an engine-level test: block a key, delete the (separately pinned) peer,
re-add it, assert `is_blocked` is still `true` and a note from that key pulled
afterward is still dropped.

### D-C — the block check sits in the pull loop, between decrypt+verify and store

`receive_incoming` (decrypt the envelope, verify the note's signature) is unchanged —
it has no concept of a peer table or a block list, and gains none. The check is a new
step in the CLI's `cmd_sync` and the app's `sync_now_inner`, both of which already call
`receive_incoming` then `store.insert_note` in sequence:

```
sync::receive_incoming(envelope_bytes, x25519_secret)   // unchanged
  -> note: Note                                          // decrypted, signature-verified
  -> hex::encode(note.author_pubkey.as_bytes())
  -> store.is_blocked(&author_hex)?
       true  => drop. No insert_note. No classify_stored_note. Nothing displayed.
       false => trust::classify_stored_note(...) -> store.insert_note(...)  // unchanged
```

The relay routes by *recipient* routing key and has no concept of sender — confirmed
against `sympoden-relay/src/main.rs`'s `HashMap<String, Entry>` keyed purely by routing
key, no sender field anywhere. So there is structurally no "never pull it": the blob is
always pulled (freeing the recipient's relay slot for whatever comes next) and only
then evaluated and dropped client-side. This is the mechanism FOUNDATION §6 already
states ("pulled from your own routing-key mailbox... identified as a blocked author,
dropped unstored") — this slice implements exactly that, no more.

**The straggler**, named in FOUNDATION §6's honesty edges and not solved here: a blob
that reached the relay *during* a block, but is pulled for the first time only *after*
the block is lifted, is evaluated against the block list *at pull time* — by then
unblocked, so it is treated as an ordinary current note. Nothing marks it as having
arrived during the past block window, and a sender-claimed timestamp is not trustworthy
enough to gate on. Narrow (only fires if unblock lands between the sender's push and
the recipient's next sync) and named in the Honesty section below, not solved.

**Recommendation: implement exactly this call site, no relay change, no `sync.rs`
change.** This is the only design that keeps `receive_incoming` (and therefore
`sync.rs`'s envelope path) genuinely zero-diff.

### D-D — new error/outcome shapes: idempotent, no new `StoreError` variants

Every operation this slice adds has a failure mode whose only honest answer is "do
nothing, report it plainly" — none of them have `relabel_peer`'s failure
characteristic (a missing target silently *drops information the caller just
supplied*, namely the new label). So none of them need a hard error:

- **`delete_peer(ed25519_pubkey) -> Result<(), StoreError>`.** Deleting an already-gone
  peer reaches the same end state (peer absent) whether or not a row existed — there is
  no caller-supplied value that would be silently lost the way a relabel's new label
  would be. **Deliberately idempotent, not erroring** — the inverse of `relabel_peer`'s
  precedent, justified by the absence of a lost-update risk, not an oversight. (If a
  caller wants to know whether anything was actually removed, `get_peer_by_key` before
  calling settles it; I don't think that's worth a new outcome enum for one bit of
  information no acceptance criterion needs.)
- **`block_key(ed25519_pubkey, blocked_at) -> Result<(), StoreError>`** and
  **`unblock_key(ed25519_pubkey) -> Result<(), StoreError>`.** Same reasoning: blocking
  an already-blocked key, or unblocking an already-unblocked one, reaches the same end
  state either way. Idempotent, no error, no new outcome enum — there is no
  `AlreadyPinnedUnderLabel`-shaped surprise here (block has no second dimension like a
  label that could silently diverge from what the caller expected).
- **`is_blocked(ed25519_pubkey) -> Result<bool, StoreError>`** and
  **`list_blocked() -> Result<Vec<BlockedKey>, StoreError>`** (new struct
  `BlockedKey { ed25519_pubkey: String, blocked_at: i64 }`, mirroring `PinnedPeer`'s
  shape). `list_blocked` exists so blocking isn't write-only: without it, there is no
  way to see or manage what's currently blocked, which is the same usability gap
  `list_peers` exists to close on the pinning side.
- **Self-add rejection lives at the CALL SITES, not in `Store::add_peer` — ruled
  2026-06-24, overruling an earlier draft of this section that put it inside the
  engine.** `Store` has no concept of "self" anywhere today — every other method is
  purely mechanical, knowing keys, labels, and timestamps but never which key belongs to
  the caller — and must keep none. Threading a `my_ed25519_pubkey: &str` parameter
  through `add_peer` would be the first crack in that boundary, and `AddPeerOutcome`
  would gain an `IsSelf` variant that every match on the type carries forever, for a
  check that is a single `==` the caller already holds both sides of. Instead: both
  production call sites — `sympoden-cli`'s `cmd_add_peer` and `sympoden-app`'s
  `add_peer_card` — already hold `identity`/`session.identity` (they need it to decode
  the card in the first place), and the caller's own key is one
  `identity.signing_key.verifying_key()` away. The guard is
  `if ed25519_pubkey == hex::encode(identity.signing_key.verifying_key().as_bytes())`,
  run *before* `check_label_collision` or `add_peer` is reached — the same shape as
  `CliError::LabelCollisionRefused` (CLI) and `AddPeerResult::NeedsCollisionConfirmation`
  (app): a policy decision sitting at the call site, never welded into `Store`.
  `add_peer`'s signature and `AddPeerOutcome`'s variant set are untouched, and so are the
  ~10 existing `add_peer` call sites in `store.rs`'s own unit tests — this check is zero
  diff to `store.rs` and `error.rs`.

  *(Superseded reasoning, kept for the record rather than silently dropped: the earlier
  draft argued for an engine-level check on the Slice 03 closeout's precedent that
  fan-out decision logic must be engine-shared, not re-derived per surface. That
  precedent doesn't transfer here — fan-out logic has to be shared because it resolves
  recipient queries, a non-trivial computation the CLI and app would otherwise each
  re-implement and could each get subtly wrong. "Is this key mine" has no resolution
  step to duplicate; it is one equality the caller already has both operands for. The
  closer precedent is `LabelCollisionRefused`, which already lives at the call site for
  exactly this reason, not the fan-out one.)*

**Recommendation: no new `StoreError` variants at all this slice.** Every new failure
mode is idempotent-by-design; the existing `UnknownPeerKey`/`AmbiguousPeerQuery` variants
stay exactly as they are, for exactly the operations that already had them
(`relabel_peer`, `resolve_peer_query`, `record_pending_sends`'s directed-target check).

### D-E — naming a block target, surfaced in addition to D-A–D-D

Not asked for explicitly, but load-bearing for block to be usable by a human at all, so
I'm surfacing it rather than quietly picking: **how does a user name a key to block —
in particular, a stranger's key they never pinned?**

The CLI's only existing sender-identifying output (`trust_label` in
`sympoden-cli/src/main.rs`) prints a *fingerprint* (20 hex chars of a hash), never the
full 64-hex key — by design, the same way `list-peers` shows fingerprints, not raw
keys. But `block_key` needs the *exact* key, and a fingerprint cannot be reversed back
into one. Two ways to close this gap:

1. Extend `cmd_list`'s per-note output to also print the full `author_pubkey` hex
   (already a field on `StoredNote`, already locally known — this is showing more of
   data the user already has locally, not new engine logic, and is zero-diff to
   `content.rs`/`trust.rs`). A user copies it to `block-key <hex>`.
2. Add a fingerprint-to-key lookup that scans locally stored notes' authors for one
   whose `fingerprint_hex` matches a typed short fingerprint, so `block <fingerprint>`
   works the same way `resolve_peer_query` already lets you address a *pinned* peer by
   fingerprint — except scanning `notes.author_pubkey`, not `peers`.

**Recommendation: do both, but only the CLI needs (1).** The **app** already ships the
exact key to the frontend per note — `NoteView.note` is the full `StoredNote`, and
`sympoden-app/src/main.rs`'s own test (`secrets_never_appear_in_command_return_types`)
confirms `author_pubkey` is already in that serialized payload. So the app's "block
this sender" action can pass `item.note.author_pubkey` straight to `block_key`, exact
key, no resolution layer — the same lesson the relabel bug already taught
(`fix(app): relabel_peer takes the exact key, not a resolved query`, `3d0f5c2`). Only
the **CLI's** plain-text output needs the addition in (1) to make the raw key
discoverable at all; once it is, the CLI's `block`/`unblock` commands can try
`resolve_peer_query` first (the common "block a pinned peer" case, ergonomic by label
or fingerprint) and fall back to treating the argument as a literal 64-hex key if
resolution fails (the stranger case) — never inventing a second matching mechanism,
just falling back to the one thing a key always is.

**Ruling (2026-06-24): approved as specified, with one sharpening.** `cmd_list`'s
full-hex-key addition is not just a nice-to-have alongside D-A through D-D — it is the
*only* mechanism by which a human, or `scripts/demo.sh`, can name a stranger to `block`
at all, so the acceptance test for "block an unknown sender" must drive the full
sequence — `list` prints the key, that key is fed to `block`, the next note from that
sender drops — through the real CLI path, not assert `Store::block_key` works in
isolation against a hand-typed key. Folded into AC3 and the demo section below.

## Components

**Engine (`sympoden-engine`):**
- `store.rs`:
  - New table `blocked_keys` (D-A), created alongside `notes`/`peers`/`note_sends` in
    `Store::open`.
  - `delete_peer(&self, ed25519_pubkey: &str) -> Result<(), StoreError>` — `DELETE FROM
    peers WHERE ed25519_pubkey = ?1`, **plus** `DELETE FROM note_sends WHERE peer_key =
    ?1 AND pushed_at IS NULL`. Idempotent (D-D). The second delete is the decided answer
    to a real fork `pending_sends()`'s join surfaces: `pending_sends()` inner-joins
    `note_sends` to `peers`, so deleting a peer alone makes any not-yet-pushed row
    addressed to them unjoinable and *invisible* — but not gone. Re-adding the same key
    later (AC2's scenario) re-matches the join, and that old, possibly long-stale queued
    send would resurrect and push on the next sync with no further action from the
    user — exactly the silent accident ROADMAP.md's "pending sends need an explicit
    decision, not an accident" warned against. **Decided: delete cancels the outstanding
    intent.** It purges not-yet-pushed rows addressed to that key outright; re-adding
    starts clean — only notes posted *after* the re-add can be addressed to them again.
    Already-*pushed* rows are left untouched as historical record (the send already
    happened; nothing to cancel, same "what's sent is sent" spirit as FOUNDATION §4).
  - `block_key(&self, ed25519_pubkey: &str, blocked_at: i64) -> Result<(), StoreError>`,
    `unblock_key(&self, ed25519_pubkey: &str) -> Result<(), StoreError>`,
    `is_blocked(&self, ed25519_pubkey: &str) -> Result<bool, StoreError>`,
    `list_blocked(&self) -> Result<Vec<BlockedKey>, StoreError>` (D-A/D-D). New struct
    `BlockedKey { ed25519_pubkey: String, blocked_at: i64 }`.
  - `add_peer`: **unchanged signature and outcome set** (D-D, overruled from an earlier
    draft) — no `my_ed25519_pubkey` parameter, no `AddPeerOutcome::IsSelf` variant.
    `Store` stays identity-free; self-add rejection is a guard at the CLI's and app's
    call sites (see below), run before `add_peer` is ever reached.
  - `record_pending_sends`/`pending_sends`: **unchanged.** Block governs inbound only;
    a blocked-but-still-pinned peer remains a valid broadcast/directed send target if the
    user explicitly addresses them — block is the receiver's decision about what they'll
    keep from someone, not a restriction on what the user sends to that someone. Stated
    explicitly so this doesn't drift into scope at implementation time.
- `trust.rs`: **zero diff.** A dropped (blocked) note never reaches
  `classify_stored_note` at all, so there is nothing for this module to change.
  Delete's reclassification is the existing recompute-at-display behavior, unchanged
  since Slice 02.
- `error.rs`: **zero diff** (D-D: no new `StoreError` variants).
- `crypto.rs`, `content.rs`, `sync.rs`, the `relay` crate: **zero diff** (D-C).

**CLI (`sympoden-cli`):**
- `delete-peer <query>`: resolves via the existing `resolve_peer_query`, calls
  `delete_peer`. By default also calls `block_key` (the coupled default action) unless
  `--keep-unblocked` is passed (the delete-without-block escape hatch, D's "must remain
  expressible").
- `block <key-or-query>` / `unblock <key-or-query>`: try `resolve_peer_query` first
  (pinned-peer case); on `UnknownPeerKey`/`AmbiguousPeerQuery`, fall back to treating the
  argument as a literal 64-hex key if it parses as one (the stranger case, D-E);
  otherwise surface the original resolution error. Call `block_key`/`unblock_key`
  directly — this is the standalone block-without-delete path.
- `list-blocked`: prints each blocked key's fingerprint and `blocked_at`.
- `list`: extended to also print each note's full `author_pubkey` hex (D-E(1)), so a
  CLI user has something to copy into `block <key>` for a stranger they've never
  pinned. `scripts/demo.sh`'s existing assertions against this output (`grep -qF
  "$BODY"`, `grep -qi "frank ("`) are substring matches against a line that's gaining
  one more trailing field — confirmed they still pass with the addition; no existing
  demo assertion anchors the end of the line.
- `add-peer`: `cmd_add_peer` compares the parsed card's `ed25519_pubkey` against
  `hex::encode(identity.signing_key.verifying_key().as_bytes())` **before** the existing
  collision pre-check or any call to `add_peer` (D-D, call-site guard); on a match,
  prints a distinct line (e.g. `"that's your own card - refusing to pin yourself"`) and
  returns — `check_label_collision` and `add_peer` are never called, nothing is written,
  the engine never sees the candidate key. On any successful `Added`/re-add outcome,
  checks `is_blocked` and prints the D-B notice if true.

**App (`sympoden-app`):**
- `remove_peer(ed25519_pubkey, keep_unblocked: bool)`: calls `delete_peer`, and
  `block_key` unless `keep_unblocked` — mirrors the CLI's coupled default action.
- `block_key(ed25519_pubkey)` / `unblock_key(ed25519_pubkey)`: standalone Tauri
  commands. The per-note "block this sender" action in the frontend passes
  `item.note.author_pubkey` directly — the exact key already present in `NoteView`,
  never through any resolution layer (D-E).
- `list_blocked()`: thin wrapper, returns `Vec<BlockedKeyView>` (mirrors `PeerView`'s
  shape: key plus its display fingerprint).
- `add_peer_card`: compares the parsed card's `ed25519_pubkey` against
  `session.identity.signing_key.verifying_key()` **before** the existing collision
  pre-check or any call to `Store::add_peer` (D-D, call-site guard); on a match, returns
  a new app-level `AddPeerResult::IsSelf` variant — an outcome of the Tauri command, not
  of the engine; `Store::AddPeerOutcome` gains nothing — without writing anything. Checks
  `is_blocked` after a successful add for the D-B notice.
- Frontend (`ui/main.js`): `refreshPeers()` calls `refreshNotes()` at its end (the
  render-on-pin/unpin property) — this is the entire fix; `list_notes` already
  recomputes trust fresh against the current peers table on every call, so no backend
  change is needed for this property, only the missing call. **The peer row must surface
  delete and block as independently invokable controls** — stated explicitly, not left to
  inference: "only a coupled Remove button" fails the separable-underneath property (§6,
  D-A). Each peer row gets: a "Remove" button (default coupled — calls `remove_peer` with
  `keep_unblocked: false`); a way to remove **without** blocking (e.g. a checkbox next to
  Remove — calls `remove_peer` with `keep_unblocked: true`, the delete-without-block
  half); and a standalone "Block" button on the same row (calls `block_key` directly,
  leaving the pin untouched — the block-without-delete half, for a peer you want to keep
  pinned but stop hearing from). A blocked-keys panel lists `list_blocked()` with
  "Unblock" buttons; each note also gains a "Block sender" action passing its own
  `author_pubkey` (the only route available for the stranger case, where there is no peer
  row at all).

**Tests / demo:**
- `scripts/demo.sh` extended with a new section covering: delete → existing notes from
  that key reclassify to `Unknown` in the next `list` → re-add (same card) → notes
  reclassify back to `Known`, no per-note action; block-without-delete (block a peer
  while still pinned) → push a fresh note from that peer → sync → the note never
  appears in `list`, the peer's pin and `Known` classification are untouched, and the
  relay slot is freed (provable the same way Slice 03's partial-delivery demo proved
  occupied-slot release: a third party can now push to that same routing key
  successfully); unblock → push another fresh note → sync → it now appears, proving
  block specifically gated the dropped one, not a general failure; delete-without-block
  (`--keep-unblocked`) → a fresh note from that key still arrives despite the peer being
  unpinned, proving the two stay independent; **blocking an unknown sender, end to end**
  (D-E, ruled 2026-06-24) → a note from a never-pinned key arrives and lists as `Unknown`
  → `list`'s extended output (D-E(1)) prints that sender's full hex key — the only way to
  name them at all — → that printed hex is copied into `block <hex>` → a subsequent note
  from the same sender is decrypted, verified, and dropped; the test drives this exact
  sequence (list, copy, block, drop) rather than asserting `Store::block_key` against a
  hand-typed key, so the addressability gap D-E exists to close is actually exercised, not
  assumed; self-add (`add-peer` with one's own `whoami` card) → the CLI's call-site guard
  (D-D) rejects it before `Store::add_peer` is ever invoked, nothing written.

## Acceptance criteria

1. Deleting a pinned peer removes their row from `peers`; every note already stored
   from that key reclassifies from `Known` to `Unknown` on the very next `list`/
   `list_notes` call, with no write to the `notes` table and no per-note state anywhere.
2. Re-adding the same key (same card) after a delete repaints every note from that key
   back to `Known` in one stroke — not a per-note operation, the same recompute that
   drove (1) in reverse.
3. Blocking a key — pinned or never-pinned — causes a note subsequently received from
   that key to be decrypted and signature-verified (unchanged path) and then dropped:
   never inserted into `notes`, never classified, never visible in any listing. The
   relay slot it occupied is freed by the pull regardless of the drop. **For the
   never-pinned case, exercised end to end** (D-E, ruled 2026-06-24): a stranger's note
   arrives and lists `Unknown`; `cmd_list`'s extended output is the only way to name that
   sender at all; the full hex key printed there is the value handed to `block`; a
   subsequent note from the same sender then drops. The test drives `list → block →
   drop` through the real CLI path, not `Store::block_key` called directly against a
   hand-typed key.
4. Unblocking a key causes a *subsequently* received note from that key to be stored
   and displayed normally; it has no retroactive effect on notes already dropped while
   the block was active (they were never kept; there is nothing to recover) or on notes
   already stored before the block began (the no-unsend boundary, FOUNDATION §4: they
   stay).
5. Block and delete are independently callable and independently effective: blocking a
   still-pinned peer stops their mail without affecting their `Known` classification or
   pin; deleting a peer without blocking reclassifies their past notes to `Unknown` but
   does not stop a freshly received note from that key from arriving and storing
   normally.
6. Re-adding a key that is separately still blocked (D-B) restores `Known`
   classification for its notes but does not lift the block — a note pulled afterward
   from that key is still dropped — and the re-add path tells the user the key is still
   blocked. **This AC governs classification and block only — it has no bearing on
   pending sends.** Pending-send resurrection is governed exclusively by AC9/AC10: nothing
   in this AC implies, and re-adding must not cause, a previously-purged pending
   `note_sends` row to come back.
7. Pinning the caller's own Ed25519 key is rejected before it ever reaches
   `Store::add_peer` — a guard at the call site (D-D, ruled 2026-06-24: the CLI's
   `cmd_add_peer` and the app's `add_peer_card`, not an engine-level check) — and no row
   is written. Exercised against both the CLI's and the app's `whoami` card fed back into
   their own `add-peer`/`add_peer`.
8. After any peer-table mutation (add, relabel, delete) in the app, the rendered notes
   list's trust classifications update without the user invoking Sync. **Verified by GUI
   walkthrough, not by `cargo test` or `scripts/demo.sh`** — there is no JS test harness
   in this repo (no `node` available in this environment), the same gate Slice 03's
   closeout applied to its own GUI-only checks. The walkthrough confirms the frontend
   calls `list_notes` after every such mutation, not only after `sync_now`. **The same
   walkthrough also confirms the peer row exposes delete and block as two independently
   clickable controls**, not only a coupled "Remove" button — block-without-delete and
   delete-without-block must both be reachable directly in the GUI, not only via the
   CLI's `--keep-unblocked` flag and standalone `block` command.
9. Deleting a peer purges any not-yet-pushed `note_sends` row addressed to them
   (decided fork, D-A/Components): the pair disappears from `pending_sends()`
   immediately, and re-adding the same key afterward does **not** resurrect or push it —
   only notes posted after the re-add can be addressed to them again. An already-pushed
   `note_sends` row for that key is left untouched (historical record, not re-sent,
   never resurrected either way).
10. **Pushed-vs-pending split, exercised concretely** (ruled 2026-06-24, sharpening AC9):
    a peer holding **both** a pushed (`pushed_at` set) and a pending (`pushed_at NULL`)
    `note_sends` row at the moment of deletion. After delete: the pushed row survives
    untouched — still present, still queryable as the historical record of what was
    actually sent — and the pending row is gone, absent from `pending_sends()`. This is
    one test distinguishing the two rows by `pushed_at`, not an inference drawn from AC9's
    general statement.
11. **Zero-diff:** `git diff <slice-start>..HEAD -- sympoden-engine/src/crypto.rs
    sympoden-engine/src/content.rs sympoden-engine/src/sync.rs sympoden-engine/src/trust.rs
    sympoden-relay/` is empty.
12. `cargo test --workspace` green, `cargo clippy --workspace --all-targets -- -D
    warnings` clean, `cargo build -p sympoden-app` succeeds. `scripts/demo.sh` green,
    covering ACs 1–7, 9, and 10 end to end against a live relay, extending (not
    replacing) Slice 01–03's existing coverage.

## Explicit NON-GOALS (do not build these in Slice 04)

- **Mute.** A third, softer mechanism (received-and-kept but display-suppressed) named
  in FOUNDATION §6 alongside delete and block, but deliberately deferred — it needs its
  own table and a display-path filter, and is a clean later fast-follow once delete and
  block exist. Not built here.
- **The mutual-connection handshake.** FOUNDATION §6 names two-way accepted connection
  as the eventual completion of this consent surface and explicitly records it as an
  open fork — whether it belongs in S-04 or a later slice. This slice answers that fork:
  it belongs to a later slice. S-04 is one-sided receive-side control only; no request /
  accept / decline / pending states of any kind.
- **Room-level block/mute.** Rooms don't exist yet. The level-split principle
  (FOUNDATION §6) — that block/delete act only on the direct mailbox path and
  structurally cannot reach a room-pull path — is inherited as a stated constraint for
  whenever rooms are built; nothing is built toward it here.
- **Anything that makes block reach the sender's device.** Block is local and
  cooperative on the sender's side only (FOUNDATION §6 honesty edge): the blind relay
  cannot filter by sender (confirmed against `sympoden-relay`'s sender-blind storage
  model, D-C), so the sender keeps sealing-and-pushing, unaware anything changed. No UI
  text in this slice may imply "they can no longer reach me" — only that this client
  will no longer keep what arrives from them.
- **Restricting outbound sends to a blocked peer.** Block governs receipt only; a
  blocked-but-pinned peer remains addressable for broadcast/directed posting if the user
  explicitly chooses to (see Components, `store.rs`).
- Out-of-band key verification, revocation, key rotation, multi-device, peer
  **exchange** UX (QR/pairing-code) — all out, as in prior slices.

## Honesty section (FOUNDATION §6 — say this plainly, not just in the design notes)

- **Block is local and cooperative on the sender's side only.** Blocking or deleting a
  peer never reaches their device — they keep your card and keep sealing-and-pushing
  exactly as before, with no signal that anything changed. The blind relay structurally
  cannot filter by sender (it has no concept of one). Block stops *this client from
  keeping* what arrives; it does not stop them sending, and does not stop the relay from
  briefly holding their blob in this client's mailbox slot until the next pull. Any UI
  copy that reads as "they can no longer reach you" misrepresents the mechanism and must
  not ship.
- **The straggler (D-C).** A note that reached the relay during a block, but is pulled
  for the first time only after the block is lifted, is evaluated against the block list
  at pull time — by then clear — and is treated as an ordinary current note. This is
  narrow (only fires if unblock lands between the sender's push and the recipient's next
  sync) and is named here as known-and-accepted, not solved.
- **Delete never erases anything.** Consistent with FOUNDATION §4's no-unsend boundary
  applied from the recipient's side too: notes already received are the recipient's to
  keep regardless of what they later do to the sender's pin. Deleting a peer changes how
  their *existing* notes are labeled, never whether they exist.

## Status

**Spec approved 2026-06-24, implementation not yet started.** D-A, D-B, D-C, and D-E are
approved as originally specified. D-D is overruled in one respect — self-add rejection
moves from inside `Store::add_peer` to a guard at the CLI's and app's call sites, keeping
`Store` identity-free — and folded in above; everything else in D-D (idempotent
`block_key`/`unblock_key`/`delete_peer`, no new `StoreError` variants) stands as written.
AC3, AC6, AC8, and AC9 are sharpened with explicit end-to-end exercises (D-E's
unknown-sender path; the pushed-vs-pending split, now its own AC10; the GUI's
independent delete/block controls), and ACs are renumbered accordingly through AC12. No
`Store`/CLI/app code is written yet; implementation proceeds on these terms next, on the
same commit-discipline terms as Slice 03 (small reviewable commits, no push, no tag).
