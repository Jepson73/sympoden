# Slice 03 — Multi-peer send, on a key-as-identity peer model

Lifts Slice 02's deliberate one-peer cap (see SLICE-02 D2) and answers the send-side
question that cap sidestepped: with N pinned peers, which one(s) does a posted note go
to? The answer is **fan-out sealing** — broadcast to all pinned peers (the default) or a
directed subset — each recipient gets the note sealed individually to their own key.

This revision replaces an earlier draft of this slice that kept Slice 02's **label is
the peer's identity** model and only lifted the cap on top of it. That model breaks the
moment two people can plausibly share a label (two real "Pamela"s; a stranger naming
themselves after someone you trust) — which multi-peer send makes a live concern for the
first time. This version re-keys the peer model: **the public key is the peer's
identity; the label is a non-unique, user-chosen, re-nameable annotation on it.** This is
not additive on top of the earlier draft — it changes what `add_peer`'s continuity check
protects, how send-state is keyed, and how peers are displayed and addressed. Everything
below supersedes the label-as-PK draft.

**This revises v0.2.0's shipped behavior.** Slice 02 (v0.2.0) rejected re-pinning a label
to a different key, unconditionally, with no override. This slice relaxes that to the
default (lower) tier — warn and allow a label collision rather than block it — and keeps
the old strict behavior available as a policy choice at an explicit seam, not removed
outright. This follows FOUNDATION.md's "security — and its setup burden — is a ladder,
**defaulted low**" principle (line 387): the easy default should not block a legitimate
second contact who happens to share a name with an existing one; a future tier can ask
for the stricter behavior at the same seam. **This is not the circle model**
(FOUNDATION.md §6) — no shared group key, no named/typed membership, no admission
ceremony. Just "your current set of keyed peers, addressed," with human-readable but
non-authoritative labels.

This slice does **not** touch the envelope format, the relay, the wire protocol, or any
crypto primitive.

## The properties this slice adds

> A peer is identified by their public key. A label is a display convenience attached
> to a key, never the other way around: two different keys may carry the same label, one
> key's label may change, but a label never resolves to more than one key implicitly —
> any operation that needs *the* peer behind a label either finds exactly one, or
> surfaces the ambiguity, never guesses.

> Posting a note addresses one or more pinned peers, by key — all of them by default
> (broadcast), or an explicit, unambiguously-resolved subset (directed). Each addressed
> peer receives their own copy, sealed to their own key, independently of whether any
> other addressed peer has received theirs yet.

> Delivery state is tracked per `(note, recipient key)`. A relay-side contention against
> one recipient's routing key never blocks, delays, or duplicates delivery to any other
> recipient of the same note.

> A label collision (two pinned peers sharing a label) is always surfaced to the human
> who caused it — eyes-open by construction, whether the default policy allows it or a
> stricter policy rejects it. It is never silently swallowed in either direction.

## Design decisions

**D1 — Peers table re-keyed: the public key is the primary key, the label is not.**

```sql
CREATE TABLE peers (
    ed25519_pubkey TEXT PRIMARY KEY,
    x25519_pubkey  TEXT NOT NULL,
    label          TEXT NOT NULL,
    first_seen     INTEGER NOT NULL
);
```

`PinnedPeer`'s field shape is unchanged (`label`, `ed25519_pubkey`, `x25519_pubkey`,
`first_seen`) — only which column is the primary key changes. This is why `trust.rs`
stays genuinely zero-diff (D5): `classify_author` already matched a note's author
against `peer.ed25519_pubkey`, never against `peer.label` — it never relied on label
uniqueness, so re-keying the table underneath it changes nothing about its correctness.

The one-peer cap is gone (Slice 02 D2's enforcement deleted): adding a peer under any
new key succeeds, regardless of how many peers, or what labels, already exist.

**D2 — `add_peer`'s old continuity check (Slice 02's "same label, different key →
reject") is cut, not re-scoped.** An earlier draft of this revision kept a hard reject
for "same Ed25519 key, different X25519 key," reasoning it guarded against a tampered
or redirected card. **That reject is removed entirely in this slice.** Three reasons,
all from review: it was never requested by the brief; it sat oddly inside a slice whose
entire purpose is moving the *label* check from reject to warn-and-allow, while quietly
keeping a different hard reject on the *key* side; and it could not be exercised through
the CLI at all (`whoami` only ever emits a card with a matched `(ed25519, x25519)` pair,
so there is no way to construct the mismatched case outside a unit test that calls
`Store::add_peer` directly with hand-built strings). The genuine fix for card tampering —
binding the X25519 key to the Ed25519 key by signature, so substitution fails at import,
first-pin included — is self-signing the card, which is its own hardening slice (see
Known Limitation, below), not this one.

`add_peer` is reduced to exactly what's needed for key-as-identity, no more:
- **A new Ed25519 key** → a new peer row (`AddPeerOutcome::Added`). No comparison
  against any other peer's key or label happens here — that is what `check_label_
  collision` is for (D3), run by the caller beforehand if it cares.
- **The same Ed25519 key, same label** → idempotent no-op (`AddPeerOutcome::
  AlreadyPinned`).
- **The same Ed25519 key, a *different* label** → idempotent on the data (nothing is
  written, the stored label does not change), but **loud**: `AddPeerOutcome::
  AlreadyPinnedUnderLabel { existing_label }`. `add_peer` never silently changes an
  existing peer's label as a side effect of being called again — `relabel_peer` is the
  **only** function that changes a label (D4) — but a caller who passed a different
  label clearly expected *something* to happen, so the outcome says plainly: already
  pinned as `"{existing_label}"` — use `relabel-peer` to rename, rather than returning
  the same silent `AlreadyPinned` it would for an exact match.

There is no longer any comparison of the X25519 half on a same-key re-add at all — it is
not read, not checked, not stored-over. `StoreError::PeerKeyMismatch` is deleted
outright (see error.rs in Components): nothing constructs it once this cut is made.

**D3 — Label collision: surfaced via a pre-check the caller runs, not a policy
parameter buried in `add_peer`.** New: `check_label_collision(label, ed25519_pubkey) ->
Result<Vec<PinnedPeer>, StoreError>` — returns every *other* (different-key) peer
already using `label`; empty means no collision. `add_peer` itself always proceeds for a
new key (the default/lower tier is "allow"); it does not take a policy flag and does not
refuse on collision. The decision of what to *do* about a non-empty collision result —
warn and proceed, or refuse — lives entirely at the calling layer (CLI, app), which
calls `check_label_collision` before calling `add_peer` and decides. This is deliberately
"a pre-check the caller runs," not a policy enum threaded through the engine: it keeps
the engine's surface minimal (two small, independently-testable functions) and means a
future, stricter tier changes *only* what the calling layer does with the pre-check's
result — never the engine. (Today: CLI's default path warns and proceeds; CLI's
`--strict` flag refuses and writes nothing if the pre-check is non-empty — see
Components. This is the seam exercised concretely now, not left as an unbuilt promise.)

**D4 — Relabeling is new, explicit, and never touches the key.** `relabel_peer
(ed25519_pubkey, new_label) -> Result<(), StoreError>` updates only the `label` column,
addressed by key (`UPDATE peers SET label = ?1 WHERE ed25519_pubkey = ?2`). There is no
function anywhere that updates `ed25519_pubkey` or `x25519_pubkey` for an existing row —
changing a peer's key has no path other than pinning it as a new row (D1); this is
structural (no such `UPDATE` statement exists in the codebase), not a documented
convention that could be violated by a future careless addition. Relabeling can itself
create a fresh label collision (renaming "carol" to "alice" while an "alice" is already
pinned) — the calling layer is expected to run the same `check_label_collision` pre-check
before calling `relabel_peer` that it runs before `add_peer` (D3); `relabel_peer` itself
does not gate on it, for the same minimal-engine-surface reason.

**D5 — Fingerprint: derived at the display layer from a key already in hand, not
carried inside `AuthorTrust`.** New, in `identity.rs` (not on the zero-diff list):

```rust
pub const FINGERPRINT_HEX_LEN: usize = 20; // 80 bits

pub fn fingerprint_hex(ed25519_pubkey_hex: &str) -> String   // 20 raw hex chars
pub fn format_fingerprint(fingerprint_hex: &str) -> String   // "a1b2 c3d4 e5f6 0718 293a"
```

`fingerprint_hex` is the first **20** hex characters (80 bits) of `SHA-256(domain_tag ||
raw_key_bytes)` — a domain-separated hash of the key, not a slice of the raw key. No new
crypto primitive is added: `sha2` is already an engine dependency, and `crypto.rs`
already exports `content_address` (SHA-256) for exactly this kind of use; `identity.rs`
calls that existing function with its own domain tag (`b"sympoden-fingerprint-v1\0"`,
following `content.rs`'s established domain-separation pattern for signed bytes) rather
than reusing `routing_key_for`'s hash verbatim — the routing key and the display
fingerprint are different concerns derived from the same public key, and tying them
together would mean a future protocol change to routing-key derivation silently changes
what's shown on screen, or vice versa. **Crucially, this is a call into `crypto.rs`'s
existing public function, not an edit to it** — `crypto.rs` stays zero diff.

80 bits (one constant, `FINGERPRINT_HEX_LEN`, used uniformly everywhere a fingerprint is
shown) is chosen over the originally-sketched 32 bits (8 hex chars) specifically because
it costs nothing — it's a slice of an already-computed, fixed-cost hash, not additional
work or storage per extra bit — so there's no reason to economize by trading away
multi-target collision headroom. The display format groups it in fours
(`format_fingerprint`) purely for eyeball comparison; this mirrors the existing
precedent of `cmd_list`'s note-id prefix (`&id[..8]`) in spirit (a short, stable, public
derivation shown alongside a label), but is computed by hashing, not slicing.

`AuthorTrust::Known(String)` is **not** changed to carry a fingerprint — it stays exactly
the label string it always was. The fingerprint is computed by the CLI/app display code
directly from `StoredNote::author_pubkey` (already present on every note, Own/Known/
Unknown alike) via `identity::fingerprint_hex`, independent of which `AuthorTrust`
variant came back. This is *why* `trust.rs` stays zero-diff (confirmed, not just hoped):
nothing about classification needs to know about fingerprints; display composes the two
already-available pieces (the trust label, the raw author key) itself.

This happens to close Slice 02's Known Limitation (f) ("no per-key fingerprint for
unknowns... deferred — see ROADMAP.md" — which named exactly "whenever multi-peer
lands" as the trigger): showing a fingerprint alongside *every* trust label, including
Unknown, means two different unpinned senders now read as visibly different, not just
two different same-labeled peers.

**D6 — Recipient resolution (label/fingerprint → key) is a pure, shared, engine-level
lookup, not duplicated per frontend, and reuses `StoreError` rather than inventing a
second error type.** New, in `store.rs` next to `PinnedPeer`:

```rust
pub fn resolve_peer_query<'a>(query: &str, peers: &'a [PinnedPeer])
    -> Result<&'a PinnedPeer, StoreError>
```

It returns `StoreError::UnknownPeerKey { query }` on no match and
`StoreError::AmbiguousPeerQuery { query, candidates }` on more than one match — the same
two variants `record_pending_sends` (D7) raises for an unresolvable `Directed` target.
This is deliberate, not incidental: whether a recipient reference fails to resolve
because a human typed an unknown label at the CLI, or because a key vanished between
resolution and write (it can't, this slice — peers are immutable — but the type doesn't
need to assume that forever), the caller-facing signal is the same `UnknownPeerKey`. One
error type for "this isn't a peer," not two.

Accepted query forms, tried in order: (1) `label#fingerprint` (e.g.
`pamela#a1b2c3d4e5f60718293a`, the raw 20-char form, no spaces) — exact match on both,
for disambiguating a known collision directly; (2) a bare label that **exactly and
uniquely** matches a peer's label — tried before fingerprint, so a label that happens to
look like a fingerprint (e.g. someone labels a peer `"deadbeef"`) still resolves as a
label first, not as a coincidental fingerprint match on a different peer; a bare label
matching more than one peer returns `StoreError::AmbiguousPeerQuery` with every
same-labeled candidate (so the caller can print each one's fingerprint and ask the user
to retry with form 1 or 3); (3) a bare 20-hex-char fingerprint, tried only if (2) found
no label match — matches by key fingerprint alone; no match in any form returns
`StoreError::UnknownPeerKey`. Label takes precedence over fingerprint specifically
because a label is something the user chose on purpose, while a fingerprint collision
with a label is coincidental; pinned down by a unit test constructing exactly that
clash (a peer labeled with another peer's fingerprint string). This resolution logic is
pure (`&[PinnedPeer]` in, no I/O) and identical for the CLI's `--to` flag and the app's
recipient picker — one implementation, not two independently-maintained ones. (A `fp:`
namespace prefix was considered to separate the two query kinds outright instead of
relying on precedence; not adopted this slice — precedence plus the regression test
below was judged sufficient, and it keeps the common case, a bare label, free of any
prefix ceremony.)

**D7 — Send state keys on the recipient's key, not their label (the actual point of
this slice).** Labels are no longer a valid join key for anything (D1) — `note_sends`
must key on `peer_key` (the recipient's `ed25519_pubkey`), or "send to Pamela" would be
ambiguous the moment a second Pamela exists.

```sql
CREATE TABLE note_sends (
    note_id   TEXT NOT NULL,
    peer_key  TEXT NOT NULL,   -- peers.ed25519_pubkey
    pushed_at INTEGER,         -- NULL = not yet handed to the relay
    PRIMARY KEY (note_id, peer_key)
);
```

`SendTargets` is `Broadcast` or `Directed(Vec<String>)`, where the `Vec<String>` holds
**already-resolved** `ed25519_pubkey` hex strings, not user-typed queries — resolving a
`--to`-style query (label, fingerprint, or `label#fingerprint`) to a key is a CLI/app
concern (D6, run *before* calling into the engine), so the engine never has to guess what
a label meant. `record_pending_sends(note_id, targets)` resolves `Broadcast` to every
currently-pinned key and validates every `Directed` key actually exists (typed
`StoreError::UnknownPeerKey`, nothing written on failure) — same ordering requirement as
before: **this call must run, and succeed, before `insert_note`**, so a target that turns
out invalid never leaves an orphaned, unaddressed note behind. (Kept verbatim from the
prior draft — this catch holds regardless of the identity-model change.)

`pending_sends()` joins `note_sends` (`pushed_at IS NULL`) ⋈ `notes` ⋈ `peers` (on
`peers.ed25519_pubkey = note_sends.peer_key`), returning `PendingSend { note: StoredNote,
peer: PinnedPeer }` — unchanged in shape from the prior draft, just joined on the right
column now.

**D8 — Relay contention handled at the sender, `continue` not `break` (unchanged from
the prior draft).** The push loop iterates every pending `(note, recipient key)` row
independently; an "occupied" bounce on one recipient leaves that row pending and the
loop *continues* to the next row rather than stopping. This is still the entire
partial-delivery mechanism (AC7) and is still not a relay change (relay stays zero-diff).

**Honest leftover, unchanged from the prior draft:** `notes.synced_at` stays in the
schema (and in `StoredNote`) because `content.rs::to_stored()` sets it and is held at
zero diff; it is no longer read or written by anything (`note_sends` is now sole source
of truth for delivery state). `Store::mark_synced` and `Store::unsynced_own_notes` are
deleted as dead code now that `pending_sends()` replaces their purpose.

## What it must prove

- A peer is identified by key; a label is just an annotation. Two peers can share a
  label without either one's notes being misattributed (each still classifies by key
  match, unaffected by what other peer happens to carry the same string).
- A label collision is always visible to a human at the moment it would occur — never
  silently allowed, never silently blocked.
- A peer's label can change without its key changing, and nothing can change a peer's
  key in place.
- Broadcast reaches every currently pinned key; directed reaches exactly the resolved
  subset; an ambiguous recipient query errors with candidates, never guesses.
- One recipient's relay contention never blocks, delays, or duplicates delivery to any
  other recipient of the same note.
- Every recipient still classifies the sender via Slice 02's unchanged Own/Known/Unknown
  logic, and can now also see a fingerprint that disambiguates same-labeled or unpinned
  senders.

## Components

**Engine (`sympoden-engine`):**
- `store.rs`:
  - `peers` table re-keyed on `ed25519_pubkey` (D1). `PinnedPeer` struct shape unchanged.
  - `add_peer(&self, label, ed25519_pubkey, x25519_pubkey, first_seen) ->
    Result<AddPeerOutcome, StoreError>` where `AddPeerOutcome = { Added, AlreadyPinned,
    AlreadyPinnedUnderLabel { existing_label: String } }`. Cap removed; the old X25519
    continuity check is cut, not re-scoped (D2/Adjustment 1) — `x25519_pubkey` is no
    longer compared on a same-key re-add at all.
  - `get_peer_by_key(&self, ed25519_pubkey) -> Result<Option<PinnedPeer>, StoreError>`.
  - `check_label_collision(&self, label, ed25519_pubkey) -> Result<Vec<PinnedPeer>,
    StoreError>` (D3).
  - `relabel_peer(&self, ed25519_pubkey, new_label) -> Result<(), StoreError>` (D4);
    `StoreError::UnknownPeerKey` if no peer has that key.
  - `resolve_peer_query` / `PeerQueryError` (D6), pure, no DB access.
  - New `note_sends` table (D7) plus `SendTargets`, `record_pending_sends`,
    `pending_sends`, `mark_send_pushed` — re-keyed on `peer_key`, otherwise as designed
    in the prior draft.
  - Removed: `mark_synced`, `unsynced_own_notes`.
  - `list_peers()` unchanged in signature; ordering becomes `(label ASC, first_seen
    ASC)` so same-labeled peers sort adjacent for display.
- `identity.rs`: new `fingerprint_hex(pubkey_hex: &str) -> String` (D5). Everything else
  in this file (key generation, keyfile seal/unlock, `PublicCard`,
  `PublicCard::from_pinned_peer`) is untouched — `from_pinned_peer` already works off
  `PinnedPeer`'s unchanged field shape, so it needs no edit despite the table's PK
  changing underneath it.
- `error.rs`: `StoreError::PeerAlreadyConfigured` removed (dead — the cap it guarded is
  gone). `StoreError::PeerKeyMismatch` removed (dead — Adjustment 1, D2: the check it
  guarded is cut, nothing constructs it). New: `StoreError::UnknownPeerKey { query:
  String }` (a resolve/send-target reference that matches no pinned peer — used by
  `resolve_peer_query`, D6, and `record_pending_sends`'s `Directed`-target validation,
  D7) and `StoreError::AmbiguousPeerQuery { query: String, candidates: Vec<PinnedPeer> }`
  (a label or fingerprint query matching more than one peer — `resolve_peer_query` only).
- `content.rs`, `crypto.rs`, `trust.rs`, **and `sync.rs`: zero diff.** The push-loop
  orchestration (D7/D8 — iterate every pending row, `continue` not `break` on occupied)
  was assumed, in the first planning pass, to live inside `sync.rs`. On inspection it
  doesn't: `sync.rs` only ever exported `prepare_outgoing`, `receive_incoming`, and
  `RelayClient` — generic over one `&PublicCard` per call, with no knowledge of peers,
  labels, or how many times it's called. The actual push loop has always lived in the
  CLI's `cmd_sync` and the app's `sync_now_inner`. Fan-out is therefore implemented
  entirely by calling `sync.rs`'s existing, unmodified functions once per pending
  recipient from those two call sites — a smaller diff than the first plan claimed, not
  a larger one. (D5 confirms `trust.rs` specifically; see Zero-diff set below.)
- `sympoden-relay`: **zero diff.**

**CLI (`sympoden-cli`):**
- `add-peer <label> <card> [--strict]`: looks up the card's key via `get_peer_by_key`
  first. If the key is genuinely new, calls `check_label_collision`; default (no
  `--strict`): if non-empty, print a warning naming each existing same-labeled peer by
  fingerprint, then call `add_peer` anyway (eyes-open allow); with `--strict`: if
  non-empty, error out and call nothing (eyes-open refuse) — this is today's concrete
  exercise of the D3 seam, not a hypothetical. If the key already exists, the collision
  pre-check is skipped entirely (nothing new is being written) and `add_peer`'s outcome
  is printed directly — including, per Adjustment 3, the loud
  `already pinned as "{existing_label}" - use relabel-peer to rename` line when the
  given label differs from the one already on file for that key.
- `relabel-peer <label-or-fingerprint-query> <new-label> [--strict]`: resolves the query
  via `resolve_peer_query`, runs the same collision pre-check against `new_label`, same
  warn/refuse split, then calls `relabel_peer`.
- `list-peers`: prints `label (fingerprint)` per pinned peer — never a bare label, since
  a bare label is no longer guaranteed to identify one peer.
- `post <body> [--to <query>]*`: repeatable `--to`. Each query resolved via
  `resolve_peer_query` against the current peer list *before* note creation; an
  unresolvable or ambiguous query errors immediately (listing candidates with
  fingerprints for the ambiguous case) — nothing is created or addressed. No `--to` at
  all = `Broadcast`. Resolved keys feed `SendTargets::Directed`, called via
  `record_pending_sends` **before** `insert_note` (D7's ordering requirement, carried
  over unchanged from the prior draft).
- `sync`'s push phase rewritten around `pending_sends()`; per-recipient status lines
  replace the old single-peer "stays pending" line.

**App (`sympoden-app`):**
- `add_peer(label, card, confirm_collision: bool)`: looks up the card's key via
  `get_peer_by_key` first, same as the CLI. If new and `check_label_collision` is
  non-empty and `confirm_collision` is `false`, returns a structured "needs
  confirmation" result (existing same-labeled peers, with fingerprints) **without
  writing anything** — the frontend shows a confirm dialog and re-invokes with
  `confirm_collision: true` if the user proceeds. If empty, or already confirmed, calls
  `add_peer` and returns its `AddPeerOutcome` (serialized) directly to the frontend —
  including `AlreadyPinnedUnderLabel`, which the frontend renders as the same loud
  message the CLI prints (Adjustment 3), not a silent success. (The app's confirm-dialog
  UX and the CLI's `--strict` flag are two different front-ends over the same engine
  seam — D3.)
- `relabel_peer(ed25519_pubkey, new_label, confirm_collision: bool)`: same shape.
- `list_peers`: thin wrapper, unchanged shape (`Vec<PinnedPeer>`, already `Serialize`).
- `post_note(body, recipients: Option<Vec<String>>)`: `recipients` holds resolved keys
  (the frontend resolves via the checkbox selection, not by typing a query — see below),
  `None`/empty = broadcast. Same validate-before-insert ordering as the CLI.
- `sync_now`'s push phase mirrors the CLI.
- Frontend (`ui/main.js`): the peer list is rendered as `label (fingerprint)` rows (one
  per *peer*, not per label) so it is unambiguous by construction — the recipient
  checkbox list is keyed by `ed25519_pubkey`, never by label, so there is no equivalent
  of the CLI's ambiguous-label problem in the app at all. A received note's trust line
  shows the fingerprint exactly as the engine computed it: `NoteView.fingerprint` /
  `PeerView.fingerprint` are derived in Rust via `format_fingerprint(fingerprint_hex(...))`
  (`FINGERPRINT_HEX_LEN` = 20) and sent over IPC; the frontend renders that string as
  received — it never recomputes the hash or re-derives a length itself.

**Tests / demo:**
- `scripts/demo.sh` extended with:
  - Multi-peer-by-key: a 2nd and 3rd peer pin succeeds under fresh labels.
  - Label collision: a peer is pinned under a label Bob already uses for someone else;
    default path succeeds with a printed warning; `list-peers` shows both, distinguished
    only by fingerprint; a third attempt with `--strict` is rejected and does not add a
    third same-labeled peer.
  - Relabel: one of the colliding peers is relabeled to a distinct name; `list-peers`
    reflects it; the peer's key (and thus its trust classification on existing/future
    notes) is unchanged.
  - Same-key re-add with a different label: re-running `add-peer` with an already-pinned
    key's exact card but a new label prints the loud no-op line (Adjustment 3) and
    `list-peers` confirms the label did **not** change.
  - Broadcast: Alice (with Bob and Carol pinned, both pinning Alice back so AC6 exercises
    `Known`) posts with no `--to`; both receive.
  - Directed: Alice posts `--to bob` only; Bob's `list` contains it, Carol's does
    **not** (checked both ways, not just the positive case).
  - Partial delivery (AC7): a throwaway identity occupies Carol's relay slot before
    Alice's broadcast; Bob receives immediately, Carol's delivery stays pending; Carol
    later syncs (drains the occupier's blob, freeing her slot), Alice retries, Carol
    receives Alice's note exactly once.
  - Existing Slice 01/02 sections continue to run, **except two that assert behavior
    this slice deliberately reverses** and must be replaced, not left in place:
    - the "second distinct label is rejected" section (the cap), replaced by the
      multi-peer-by-key section above;
    - the "re-pinning 'alice' with a different key is rejected, the working pin
      survives" section (`scripts/demo.sh` lines ~158-172 as of v0.2.0) — this is
      *exactly* the v0.2.0 continuity behavior D2/D3 revise. Under this slice, pinning a
      different key under the label "alice" is a label collision: the default path
      **succeeds** (exit 0) with a printed warning, and `list-peers` now shows two
      "alice" entries distinguished by fingerprint. The *rejection* assertion moves to a
      new `--strict` invocation of the same scenario, which must still fail closed. A
      demo left asserting the old unconditional rejection on the default path would
      fail outright against this slice's actual behavior — this is flagged explicitly
      so it isn't mistaken for an oversight when the green-to-red flip is noticed.

## Acceptance criteria

1. Pinning a 2nd and 3rd peer under fresh keys succeeds regardless of label — the
   one-peer cap is gone.
2. Re-adding an already-pinned `ed25519_pubkey` is always idempotent on the stored peer
   data: with the same label, it's a silent no-op; with a different label, the label
   does **not** change, but the outcome is surfaced loudly (Adjustment 3) rather than
   swallowed — `relabel-peer` is the only way to actually change it. There is no
   X25519-mismatch check at all this slice (Adjustment 1 cuts it outright; see Known
   Limitations for the deferred card-integrity hardening this leaves open).
3. A label collision (a new key pinned under a label another peer already uses) is
   never silent: the default path succeeds but surfaces a warning naming the existing
   same-labeled peer(s) by fingerprint; a `--strict`/confirmation-declined path refuses
   and writes nothing. Both paths are demonstrated.
4. Every peer listing (CLI `list-peers`, app peer UI) shows label **and** fingerprint,
   never a bare label — sufficient to tell same-labeled peers apart by sight.
5. A peer's label can be changed via `relabel_peer`/`relabel-peer`, addressed by key or
   fingerprint, without altering its key; no operation anywhere changes an existing
   peer's key in place.
6. Broadcast post reaches every currently pinned peer (by key); directed post reaches
   exactly the resolved subset (checked positively for selected peers and negatively for
   unselected ones); an ambiguous `--to` label errors and lists candidates with
   fingerprints rather than guessing.
7. Per-`(note, recipient key)` send state: if one recipient's relay slot is occupied at
   push time, every other recipient still receives the note on that pass; the occupied
   recipient's delivery stays pending and is retried successfully on a later sync, with
   no duplicate delivery to anyone.
8. Every recipient classifies the sender correctly (Own/Known/Unknown, Slice 02's
   mechanism, unchanged) regardless of label collisions among the sender's other peers —
   classification is by key, never affected by what label any peer carries.
9. Zero diff to `crypto.rs`, `content.rs`, `trust.rs`, `sync.rs`, and the entire `relay`
   crate (verified by `git diff` against the pre-Slice-03 commit).
10. `cargo test --workspace` green, `cargo clippy --workspace --all-targets -- -D
    warnings` clean, `cargo build -p sympoden-app` succeeds. `scripts/demo.sh` green
    covering ACs 1-8 in full — Adjustment 1's cut removes the one path (an
    X25519-mismatch reject) that the prior draft could not stage through the CLI, so
    this AC no longer needs the carve-out the prior draft required.

## Explicit NON-GOALS (do not build these in Slice 03)

A persisted, user-facing tier/policy setting for collision handling (the engine-level
seam — D3 — exists and is exercised via a CLI flag and an app confirm dialog; an actual
settings UI, a stored preference, or any notion of "tiers" as a first-class concept is
Phase 1+ work) · mutual-connection handshake / a receive-side consent gate (Slice 02's
identification-vs-delivery gap is still open; its own slice) · named/typed circles
(Friend/Family/custom) · peer **delete** (relabel exists; delete does not — a fresh data
directory is still the only way to fully remove a mistaken pin) · a relay per-slot queue
(contention is tolerated and handled at the sender, not fixed at the relay — D8) · a
shared group key (rejected on-thesis per FOUNDATION.md §6; fan-out-sealing only) · any
change to the envelope, relay, wire protocol, or crypto primitives · the durable/open-
flow/discovery/tier layers · out-of-band key verification (safety numbers / QR
fingerprint comparison) beyond the bare display fingerprint added here, which is a
disambiguation aid, not a verified-out-of-band security ceremony · **card self-signing**
(binding a card's X25519 key to its Ed25519 key by signature, so a substituted X25519
half fails verification at import) — this is the genuine fix for card tampering that
Adjustment 1 explicitly named and deliberately left out of this slice; it is its own
hardening slice, not a side effect of the identity-model rework here.

## Known limitations (accepted for Slice 03)

a. **A label collision being "allowed by default" means TOFU's first-contact trust
   problem (Slice 02 Known Limitation a) now has a sharper edge.** An attacker who knows
   you'd trust a name can pin themselves under that exact label next to the real one,
   and the default policy lets them — distinguished from the real contact only by a
   fingerprint most users will not manually compare unprompted. The fingerprint exists
   so the *information* to tell them apart is present, not so that a casual user
   reliably will. Mitigated only by the warning text at the moment of the collision and
   by deliberate use of `--strict`/the confirm dialog; true out-of-band verification
   remains a non-goal (see above).
b. **20 hex characters (80 bits) is still a display aid, not a verification ceremony.**
   It comfortably resists *accidental* collision and is enough to make two values "look
   different at a glance" for casual comparison, but a user who never actually compares
   two fingerprints character-by-character gets none of that benefit — and even a
   careful glance-comparison of a 20-character string is a weaker defense than a real
   safety-number/QR ceremony with explicit positional comparison (explicit non-goal
   here; see NON-GOALS).
c. **Small-group relay contention is tolerated, not solved** (unchanged from the prior
   draft) — the relay still holds exactly one undelivered blob per routing key; no
   queue. Phase 1 relay work.
d. **A crash between a successful push and recording it could, in principle, cause a
   duplicate** (unchanged from the prior draft) — an accepted, narrow, best-effort-
   framed risk, not solved by a transactional outbox this slice.
e. **`notes.synced_at` is an inert, write-once-always-None field** (unchanged from the
   prior draft) — `note_sends` is the sole source of truth for delivery state.
f. **Fan-out is a new traffic-correlation surface.** A broadcast is N near-simultaneous
   pushes to N routing keys from one sender. The relay stays blind and logs nothing
   (zero diff), but the *pattern* is observable in principle to anyone watching traffic
   to the relay, in a way a single push wasn't. Named in FOUNDATION.md §6 (lines
   233-235, 489) as a hard open sub-problem for circles' group-key work; not addressed
   here (no padding, no delay-randomization, no batching).
g. **No receive-side consent gate** (unchanged from Slice 02) — anyone holding your
   public card can still cause a note to be pushed, decrypted, verified, and stored
   under your routing key; labeled Unknown if unpinned, never blocked.
h. **Broadcast membership is resolved at post time, not live** (unchanged from the prior
   draft) — pinning a peer after a broadcast note was posted does not retroactively
   address them for that earlier note.
i. **No peer delete.** Combined with no-key-mutation (D4), a peer pinned under the wrong
   key has no in-product undo beyond a fresh data directory — unchanged in spirit from
   Slice 02's accepted limitation (b), now explicitly extended to say relabeling a
   *label* is possible but removing a *peer* is not.
j. **A card's X25519 half is trusted on import, unverified against its Ed25519 half**
   (Adjustment 1). Nothing in this slice — or in Slice 01/02 before it — binds the two
   keys in a card together; a corrupted or maliciously substituted X25519 key in an
   otherwise-valid card is accepted at `add_peer` exactly as readily as a legitimate one,
   first pin included, with no check at all (the prior draft's hard reject on a
   *re-pinned* key's X25519 half changing is cut, and there was never a check on first
   pin in any draft). The fix — self-signing the card so substitution fails verification
   at import — is named in NON-GOALS as a dedicated future hardening slice, not
   something this rework happens to provide as a side effect.
   **Closed by SLICE-05.md**: a card's Ed25519 key now signs its paired X25519 key,
   verified at `add_peer` before anything is written, first pin included.

## Zero-diff set

`crypto.rs`, `content.rs`, `sync.rs`, and the entire `relay` crate: zero diff,
unconditionally — none of this slice's changes touch sealing/opening, content
addressing/signing, the relay's protocol or storage, or `sync.rs`'s envelope/transport
functions (the fan-out push loop calls `sync.rs`'s existing functions repeatedly from
the CLI/app, it doesn't change them — see Components).

`trust.rs`: zero diff, **confirmed**, not merely hoped for (D5) — `classify_author`
already matched by `peer.ed25519_pubkey`, never by label, so re-keying the peers table's
primary key changes nothing it does; the fingerprint is computed by display code outside
this module from data (`StoredNote::author_pubkey`) it already had no part in producing.
Verified by inspection of `classify_author`'s body (no label-uniqueness assumption
anywhere) ahead of implementation, and to be re-confirmed by `git diff` at closeout, same
discipline as SLICE-02 AC10.

## Scope note

This slice now bundles two interlocking changes: the peer-identity model (key-as-PK,
labels non-unique, collision handling, fingerprints, relabel) and multi-recipient send
(broadcast/directed, per-recipient send state, partial-delivery retry). They are kept
together deliberately rather than split into two slices: multi-peer send is *why* the
label-as-PK model breaks in the first place (Slice 02's cap existed specifically because
"more than one peer" and "what does a label even identify" were never separately
answered), so splitting them would mean shipping multi-peer send on a model already
known to be wrong, then immediately redoing it. The one piece kept deliberately out
to bound scope is the *policy/tier* layer (a persisted, user-facing strict/default
setting) — only the engine seam plus one concrete exercise of it (a CLI flag, an app
confirm dialog) ships here; an actual settings surface is explicitly a non-goal.

## Status

**Code-complete and headless-verified.** `cargo test --workspace` (95 tests: 16 app, 71
engine, 8 relay, 0 cli-unit) and `cargo clippy --workspace --all-targets -- -D warnings`
are clean; `cargo build -p sympoden-app` succeeds; the extended `scripts/demo.sh`
demonstrates AC1-AC8 end to end against a live relay — multi-peer-by-key, label
collision (warned and `--strict`-refused), relabel, the same-key-different-label loud
no-op, broadcast, directed (positive and negative), and the partial-delivery retry with
no duplicate. `git diff 50a85a9..HEAD` (the commit at the start of this slice) confirms
`crypto.rs`, `content.rs`, `trust.rs`, `sync.rs`, and the entire `relay` crate are
byte-for-byte unchanged.

**GUI-verified (2026-06-23).** A manual walkthrough on the laptop, in a running Tauri
window, confirmed relabel-by-key (the label changes, the key stays put, no "no pinned
peer matches" error), the collision-confirm dialog, the loud same-key-different-label
no-op, and the core renders: Own/Known/Unknown classification, the 20-hex grouped
fingerprint, broadcast vs. directed delivery, and a sender flipping from unknown to
known immediately on pin. This closes the gap Slice 01/02's closeout held to the same
standard — only headless/command-level coverage until now.

## Invariant check for this slice

No personal data collected — peer labels, fingerprints (derived, not stored separately),
and send-state are all user-created/derived data, encrypted at rest, nothing new
collected ✓ · no ads/engine — fan-out is explicit per-post addressing ✓ · no point of
compulsion — relay untouched ✓ · client verifiable — no new dependencies, no telemetry ✓
· no content inspection — collision/resolution/send-state logic operates on labels and
keys, never note bodies ✓ · crypto: vetted crates only, none added — fingerprinting
reuses the existing, already-vetted `sha2`/`content_address` (called, not modified, from
`identity.rs`); no new dependency, no rolled-own primitive; `prepare_outgoing`/
`receive_incoming` reused unmodified ✓ · facts/opinions distinct — N/A. **Caveat, not a
pass, carried from the prior draft:** fan-out's traffic-shape correlation surface (limit.
f) and the sharper TOFU edge from default-allow collisions (limit. a) are real, named
trade-offs of "defaulted low," not absences of a problem. If implementation surfaces a
further conflict with any of these, stop and surface it before proceeding.
