# Slice 02 — Trust-On-First-Use (author↔peer binding)

Closes the **identification** half of Slice 01's accepted limitation (a): a received note
is verified (it really was signed by the key it claims) but not bound to anyone you
actually recognize — it displays by raw key with no link to a peer you've added. This
slice makes a received note's author *meaningful*: bound to a peer you pinned, or clearly
flagged when it isn't.

**This is not sender authorization and must not be called that.** It does not close the
**delivery** half of limitation (a): anyone holding your public card can still deliver a
note that lands under your routing key and gets decrypted and verified — that note is now
*labeled* unknown rather than blocked. Blocking delivery would require changes to the
relay/routing-key protocol, which is explicitly out of scope (see NON-GOALS). This slice
is honest labeling of who you're actually hearing from, nothing more.

This is a trust/identity-binding layer on top of Slice 01's primitives. It does **not**
touch the envelope format, the relay, the wire protocol, or any crypto primitive.

## The property this slice adds

> For every note displayed to the user, the author is shown either as a specific,
> previously-pinned peer (by label) or as explicitly unrecognized — never ambiguously,
> and never as a pinned peer's label unless its `author_pubkey` exactly matches that
> peer's pinned key.

A second, narrower property guards the pin itself:

> Pinning a label to a key happens once, on trust *(first use)*. Re-presenting the same
> label with a *different* key is never silently accepted as an update to the pin.

## Design decisions — RULED (approved 2026-06-20, with amendments below)

D1, D2, and D3 are approved as drafted, each with the amendments folded in throughout this
revision. No longer open for sign-off; recorded here for why, not for debate.

**D1 — Where the binding lives. APPROVED, with a non-bypassability requirement.**
`receive_incoming` (`sync.rs`) stays exactly what it is today: decrypt + verify the note's
self-signature, nothing else. It gains no new parameter and no knowledge of peers. A new,
separate, pure function — `trust::classify_author(author_pubkey, my_verifying_key,
&[PinnedPeer]) -> AuthorTrust` — is added to the engine and called by the CLI/app *after*
`receive_incoming` succeeds and again whenever notes are listed for display. Rationale:
keeps the one function with actual crypto content unchanged (zero risk to its existing
tests/properties), and makes the new trust-policy logic its own small, headless-testable
unit with no I/O.

**Non-bypassability requirement (added on ruling):** every display/print path takes a
*trust-annotated* note — a wrapper that pairs a `StoredNote` with its `AuthorTrust` — as
its input type, never a bare `StoredNote`. There must be no function signature in the CLI
or app display paths that accepts a `StoredNote` (or a list of them) without also
requiring an `AuthorTrust`/wrapper alongside it. Concretely: `cmd_list`/`cmd_sync` in the
CLI and `list_notes`/`sync_now` in the app only ever format/return the wrapper type, and
the only way to construct that wrapper is through `classify_author`. This makes it
structurally impossible — a type error, not a discipline — for a future display path to
render a note without having classified its author first.

**D2 — Data model. APPROVED, with the cap's rationale and the peer.json transition made
explicit.** Peers move from the plaintext `peer.json` file into a new `peers` table in
the existing SQLCipher store (`label TEXT PRIMARY KEY, ed25519_pubkey TEXT NOT NULL,
x25519_pubkey TEXT NOT NULL, first_seen INTEGER NOT NULL`). This is a real behavioral
change, not just internal refactoring: **`add-peer` now requires the identity to be
unlocked** (it needs `db_key` to open the store), which it did not before. This is
recommended because a peer's label (e.g. "Mom") is exactly the kind of thing invariant #1
implies should be encrypted at rest like everything else, not left in a plaintext file
next to the keyfile.

**Why the cap at one peer is deliberate, not incidental:** allowing more than one
configured peer immediately opens a *send-side* question this slice does not answer —
`post`/`prepare_outgoing` address a single recipient; with N pinned peers, "post" would
need a way to pick which one (or broadcast to all), which is a real design surface
(addressing/recipient-selection) that belongs with Phase 1's circles/follow/friend work,
not bolted on here. Capping at one peer sidesteps that question entirely rather than
answering it implicitly. The `peers` table is still shaped to hold a set (so Phase 1
doesn't need a second migration), but Slice 02 enforces, at the `add-peer` layer, that at
most one peer is configured at a time. Adding a peer under a second, different label
while one is already configured is rejected with a typed error. Proving TOFU does not
require more than one peer: "known" vs. "unknown" vs. "rejected re-pin" are all exercised
against a single pinned correspondent.

**What happens to an existing `peer.json`:** it is **abandoned, not migrated.** Slice 02
never reads `peer.json`; the file is simply ignored if present (and the code path that
wrote/read it is deleted, not left dormant). Anyone with a Slice-01-era `peer.json` must
re-run `add-peer <label> <card>` once under Slice 02 to re-pin. This is a one-time,
acceptable break for a prototype with no real users yet — consistent with not building a
migration shim or back-compat shim for data that predates any real deployment.

**D3 — What "unknown" and "changed" mean, concretely. APPROVED, reframing confirmed
correct, with the escape hatch made a conscious choice and the scope of what this
resolves stated plainly.** A received note carries only a raw `author_pubkey` (Ed25519)
— it carries no claimed label. So "a note claims to be a known peer but presents a
different key" cannot occur *per note*; there is nothing in the wire format for it to
claim. The three real states at **receive/display time** are (own-note `Own` added below
under Correctness):
  - **Known** — `author_pubkey` exactly matches the single pinned peer's Ed25519 key.
    Displayed with that peer's label.
  - **Unknown** — matches no pinned peer (including the case where no peer is pinned at
    all yet). Displayed distinctly and **unmistakably** — e.g. `⚠ unknown sender
    <hex prefix>` with a visual treatment (not merely the absence of a label) that cannot
    be confused with a known-peer label at a glance. This distinctness is the entire
    security point of the slice and is non-negotiable. The note is still **accepted and
    stored** — not rejected or quarantined. Rationale: this matches Slice 01's
    already-accepted threat model (anyone holding your card can deliver to you); the new
    behavior is honest labeling of identity, not a new delivery gate (see the
    identification-vs-delivery framing at the top of this doc).

  Key continuity ("changed key") is therefore a **re-pin-time event, at `add-peer`**, not
  a per-note classification: if `add-peer` is called with a label that already has a pin,
  and the new card's Ed25519 *or* X25519 key differs from what's pinned, it is **rejected**
  by default with a typed error — never silently overwritten. Re-adding the *same* label
  with the *same* keys is a no-op success (idempotent).

  **Escape hatch — ruled, conscious choice, not an accident:** there is **no** override
  flag and **no** delete/replace-peer command in this slice. Combined with the
  one-peer-per-identity cap (D2), this means a mistyped card or a legitimately rotated key
  permanently sticks a label once pinned: the only path to change it is deleting the local
  data directory and starting over (a fresh identity, fresh peer pin). This is deliberately
  narrow rather than half-building a revocation/rotation feature — see NON-GOALS and Known
  Limitation (b). A real re-pin/rotate operation is Phase 1 contact-management work, done
  properly (with whatever confirmation UX that deserves), not improvised here.

  Classification is **recomputed at display time** against the current `peers` table
  (joining `notes.author_pubkey` against the pinned key), not frozen into the note at
  receive time. Concretely this means: if a peer is pinned *after* some of their notes
  already arrived as Unknown, those notes show as Known on the next listing; trust shown
  is always "what we currently know," not "what we believed when this arrived." This is
  the simpler implementation (no notes-schema change — `author_pubkey` is already stored)
  and is the one that best satisfies the non-negotiable that a changed/mismatched key must
  never be shown as trusted: a frozen-at-receipt judgment would keep showing a peer's *old*
  notes as trusted under a label even after that label's pin was changed (e.g. because the
  old key was known to be compromised); recompute does not have this stale-trust problem.

## Correctness addition — the user's own notes (ruled)

`classify_author` must also recognize the identity's **own** `author_pubkey` and return a
third, distinct variant — `AuthorTrust::Own` (named `Own`, not `Self` — `Self` is a Rust
keyword and cannot be an enum variant) — displayed as "you," never as "unknown."
Without this, every note the user posted themselves would misclassify as Unknown (their
own key is not, and must never need to be, in the `peers` table), which would both be
wrong and would dilute the unknown-marker's signal. `classify_author` therefore takes the
caller's own `VerifyingKey` as a parameter alongside the pinned-peers list, checked before
the peers-table lookup.

## What it must prove

- A note from a pinned peer is shown bound to that peer's label, not a raw key.
- A note from anyone else is shown distinctly as unrecognized, never confused with a
  pinned peer.
- A peer's pin, once set, cannot be silently changed by a later, different card showing
  up under the same label.
- All of this holds without touching the envelope, the relay, the wire protocol, or any
  crypto primitive — signature verification is still the only cryptographic gate; trust
  classification is a separate, non-cryptographic, local-only judgment applied after it.

## Components

**Engine:**
- `store.rs`: new `peers` table (`label`, `ed25519_pubkey`, `x25519_pubkey`,
  `first_seen`) alongside the existing `notes` table. CRUD: `add_peer` (idempotent on
  exact match, typed-error on mismatch or on a second distinct label), `get_peer`,
  `list_peers` (returns 0 or 1 row, but typed as a `Vec` so the shape survives Phase 1's
  real multi-peer work without another migration).
- New module, `trust.rs`: `enum AuthorTrust { Own, Known(String), Unknown }` (label is
  the `String`) and `fn classify_author
  (author_pubkey: &VerifyingKey, my_verifying_key: &VerifyingKey, peers: &[PinnedPeer]) ->
  AuthorTrust`. Pure, no I/O, fully unit-testable headlessly. Also defines the
  trust-annotated wrapper type (e.g. `TrustedNote { note: StoredNote, trust: AuthorTrust
  }`) that display paths are required to use (see D1's non-bypassability requirement).
- `error.rs`: a new `PeerError` (or an addition to an existing enum) with variants for
  "already configured under a different label" and "key mismatch on re-pin," each typed,
  no panics.
- `identity.rs`, `sync.rs`, `crypto.rs`, `content.rs`: **unchanged.**

**CLI (`sympoden-cli`):**
- `add-peer` gains a required `label` argument and now prompts for/uses the unlocked
  identity's `db_key` to open the store before writing the pin (mirrors `cmd_post`'s
  shape). `peer.json` is removed outright — **no migration shim** (no real users yet to
  migrate; consistent with not building backwards-compatibility hacks for a prototype).
- `sync` and `list` both classify each note's author against the current `peers` table
  and print the label or an explicit "unknown sender" marker instead of (or alongside)
  the raw key prefix they print today.

**App (`sympoden-app`):**
- `add_peer` Tauri command changes shape to require an unlocked `Session` (like
  `post_note`/`sync_now`/`list_notes` already do) instead of being usable identity-less,
  and gains a `label` parameter.
- `list_notes` and `sync_now`'s `received` field return trust-annotated results (a small
  serializable wrapper carrying the existing `StoredNote` plus an `AuthorTrust`) instead
  of bare `StoredNote`s.

**Tests / demo:**
- `scripts/demo.sh` updated: `add-peer` calls gain a label argument, and — this is the
  part the current sketch was missing — **Bob now also adds Alice as a peer** (captures
  `ALICE_CARD` via Alice's `whoami`, runs `add-peer alice "$ALICE_CARD"` on Bob's side).
  Without this, the one note that flows in the existing demo (Alice → Bob) classifies as
  *Unknown* to Bob, and the demo would never demonstrate the Known path — which is AC1
  and the actual point of the slice. With it, Bob's `list` output is asserted to show the
  note under the label "alice," not a raw key. A second new section then adds a
  peer-not-yet-known note (e.g. from a throwaway third identity Alice never pinned, synced
  to Alice) and asserts it's labeled unknown, then asserts a re-pin attempt with a
  different key for the same label is rejected and does not overwrite the working pin.
- Existing CLI/app tests that call `add_peer`/`add_peer_card`/`AddPeer` (notably
  `sympoden-app`'s `full_two_session_sync_exchange_via_relay` and
  `add_peer_rejects_a_malformed_card_cleanly`) updated for the new signature and
  unlock-required precondition — extended, not replaced, per the brief.
- New unit test: posting a note and then classifying/listing it shows `AuthorTrust::Own`
  ("you"), not "unknown" — proves AC11 directly against `trust::classify_author` and
  against the CLI/app's own-note listing path.

## Acceptance criteria

1. A note whose `author_pubkey` exactly matches the single pinned peer's Ed25519 key is
   displayed (CLI `list`/`sync`, app `list_notes`/`sync_now`) bound to that peer's label.
2. A note whose `author_pubkey` matches no pinned peer (including when none is pinned
   yet) is displayed distinctly as unrecognized, and is never shown under a peer's label.
   The note is still accepted, verified, and stored — Slice 01's signature check is
   unaffected.
3. `add-peer <label> <card>` with no existing pin for that label succeeds and persists
   `(label, ed25519_pubkey, x25519_pubkey, first_seen)` in the encrypted store.
4. `add-peer <label> <card>` with the *same* label and *identical* keys to what's already
   pinned succeeds as a no-op (idempotent); it does not error and does not duplicate.
5. `add-peer <label> <card>` with the *same* label but a *different* Ed25519 or X25519 key
   than what's pinned is **rejected** with a typed error; the existing pin is unchanged.
6. `add-peer <label> <card>` for a *second, different* label while one peer is already
   configured is rejected with a typed error (single-correspondent scope for this slice).
7. `add-peer` requires an unlocked identity; calling it without one fails cleanly (no
   panic), the same way `post`/`sync` already do.
8. Trust classification reflects the *current* `peers` table at the moment of display —
   pinning a peer after their notes arrived as unknown causes those same notes to show as
   known on the next listing (no notes-schema change, no frozen-at-receipt trust field).
9. All Slice 01 acceptance criteria (signature verification, blind relay holding only
   ciphertext + routing key + expiry, at-rest encryption, clean wrong-passphrase failure,
   no telemetry/hidden network calls) still hold, demonstrated by the extended
   `scripts/demo.sh` and `cargo test --workspace`. The extended demo must demonstrate
   *both* states this slice adds — Known (Bob has pinned Alice) and Unknown (a sender
   Alice never pinned) — not just one of them.
10. No change to `Envelope`, `RelayRequest`/`RelayResponse`, `Note`'s wire bytes, or any
    crypto primitive — verifiable by inspection of `sync.rs`, `crypto.rs`, `content.rs`,
    and `sympoden-relay`'s unchanged diff.
11. A note authored by the identity's own key (e.g. one's own posted note, listed locally)
    classifies as `AuthorTrust::Own`, displayed as "you" — never as unknown and never
    requiring the identity's own key to appear in the `peers` table.
12. No display/print function in the CLI or app accepts a bare `StoredNote` (or list
    thereof) for rendering to the user — every such function's signature requires a
    trust-annotated wrapper, so omitting classification before display is a compile error,
    not a possible bug.

**Status:** code-complete and headless-verified — `cargo test --workspace` and
`cargo clippy --workspace --all-targets -- -D warnings` are clean across every crate
(engine, cli, relay, app), and the extended `scripts/demo.sh` demonstrates AC1-AC10
end to end against a live relay (known-peer binding, unknown-sender labeling,
recompute-at-display after pinning, the single-peer cap, rejected re-pin, and
idempotent re-add), plus all of Slice 01's original criteria unchanged. AC11 (own-note
`Own` classification) and AC12 (no bare-`StoredNote` display path) are covered by
engine/app unit tests. The app's webview frontend (`ui/main.js`, `ui/index.html`) was
updated for the new `{note, trust}` IPC shape and that shape was checked against the
real serializer output (not assumed), but the actual two-instance GUI click-through on
a real desktop has **not yet** been performed — see `sympoden-app/README.md`'s
"Slice 02 GUI status" section. That manual step, not anything in this codebase, is
what's left before this slice's UI can be called fully done.

## Explicit NON-GOALS (do not build these in Slice 02)

Out-of-band key verification (safety numbers / QR fingerprint comparison) · revocation of
a previously-pinned peer · a "force re-pin" / override-the-pin operation · a delete- or
replace-peer command (this slice has no path to un-stick a mistyped or rotated pin other
than a fresh data directory — a conscious, ruled choice, not an oversight; see D3 and
Known Limitation (b)) · multi-device (pins are local to one keyfile's store; no
cross-device pin merging) · multiple simultaneous distinct peers / a contacts list
(`list-peers`, `remove-peer` — the table is shaped to allow this later; this slice
enforces and tests exactly one). **The one-peer cap is deliberate**: supporting more than
one pinned peer immediately raises a send-side question — which peer does `post` address?
— that this slice does not answer; recipient-selection on send is Phase 1 work alongside
circles/follow/friend, not something to improvise here · blocking/muting · general
contact management UI · changing how outgoing notes pick their recipient (`post`/`sync`
still address the one configured peer, same as Slice 01) · any change to the envelope,
relay, wire protocol, or crypto primitives · replay-window semantics (Slice 01's
limitation b) · active relay expiry/GC (Slice 01's limitation b) — both stay Phase 1 work
· **blocking or otherwise gating delivery of unknown-sender notes** — this slice changes
identification/display only; an unknown sender's note still reaches the recipient exactly
as in Slice 01 (see the identification-vs-delivery framing at the top of this doc).

## Known limitations (accepted for Slice 02)

a. **First contact is still trusted by default.** TOFU trusts whoever you pin *first*
   under a label. If an attacker is the first card you ever add for "Mom," they get
   pinned as Mom. Mitigated only by out-of-band care in choosing what to add as a peer —
   not solved here; out-of-band verification is an explicit non-goal above.
b. **No recovery path for a legitimate key change.** If a real peer's key legitimately
   changes (new device, lost keyfile), `add-peer` under their existing label will reject
   it (criterion 5) with no in-product way to accept the new key. The only path this
   slice leaves is removing and recreating the local data directory. A deliberate,
   explicit re-pin operation is Phase 1 contact-management work.
c. **Single correspondent only.** Exactly one peer can be configured per identity this
   slice (criterion 6). Real multi-peer support is Phase 1.
d. **Trust display is current-knowledge, not point-in-time.** Per D3, a note's shown
   trust state can change after the fact (e.g. a previously-unknown sender becomes known
   once pinned). Nothing here records "what we believed when this note arrived."

## Invariant check for this slice

No personal data beyond what the user explicitly added (a peer label is user-created, now
encrypted at rest, not collected) ✓ · no ads/engine ✓ · relay untouched, still blind and
stateless-ish ✓ · no content inspection — classification reads only the already-verified
`author_pubkey`, never the note body ✓ · verifiable/no-telemetry build — no new network
calls, no new dependencies beyond what's already in the workspace ✓ · honest scope — the
known-limitations section above is the same discipline Slice 01 used ✓ · vetted crypto
crates only / secrets zeroized — no crypto changes at all this slice ✓ · facts/opinions
structurally distinct — N/A, still a single note type. If any added feature would break
one of these, stop and surface it.
