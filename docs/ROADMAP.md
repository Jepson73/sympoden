# Roadmap

Phased build order. Each phase de-risks the next; **don't skip ahead.** The two
make-or-break unknowns are validated by *real use*, not by spec — they're flagged below.

## Guiding sequence

**Social wedge first, knowledge network emerges.** The family/circle social use case is
valuable at five users and needs no discovery — it carries adoption while the harder
knowledge/discovery layer is built and tested on top. Prototype on desktop; ship the
product on mobile.

---

## Phase 0 — Slices 01–02 (prototype)  → `docs/slices/SLICE-01.md`, `docs/slices/SLICE-02.md`

**Goal:** the smallest runnable thing, then make a received note's author meaningful.
Slice 01 (Tauri + Rust engine): create an encrypted identity, post a text note locally,
sync it to a second instance through one blind relay — the two instances **never online
at the same time**. Slice 02: bind a note's verified author to a pinned peer at display
time (trust-on-first-use), or flag it distinctly as unrecognized.

**Proves:** (1) async store-and-forward via a blind relay actually works; (2) the
identity-creation friction is tolerable; (3, Slice 02) TOFU author↔peer binding works
end to end and is non-bypassable at display.

**Shipped (Slice 02), with follow-ups it surfaced:**
- **Multi-peer + recipient selection** — Slice 02 caps at one peer per identity
  precisely because `post`/`prepare_outgoing` address a single recipient; supporting
  more peers needs a real addressing/recipient-selection answer. Phase 1 work, alongside
  circles/follow/friend.
- **Unknown-sender key fingerprint** — Slice 02 renders every unrecognized sender
  identically (`⚠ unknown sender`, no distinguishing mark). Showing a short key
  fingerprint per unknown sender (so two different unpinned senders read as different)
  is deferred to whenever multi-peer lands.
- **Peer delete/replace** — Slice 02 has no in-product way to un-stick a mistyped label
  or accept a peer's legitimately rotated key; the only path is a fresh data directory.
  A real, deliberate re-pin/rotate/delete operation is Phase 1 contact-management work,
  not something to improvise as a quick patch.

**Non-goals (Slice 01):** circles, media, discovery, DHT, Tor, mobile, automerge, group
keys, social recovery, polished UI. One screen, two buttons.
**Non-goals (Slice 02):** out-of-band key verification, revocation, multi-peer, blocking
unknown senders — see `docs/slices/SLICE-02.md`'s NON-GOALS for the full list.

---

## Phase 1 — Social wedge MVP  *(the ADOPTION frontier)*

**Goal:** a real family can use it for easy, private sharing.

**Build:** circles (mutual connection; audience enforced by encrypting to members' keys);
follow vs friend; the ephemeral presence-gated layer + blind relay buffer; the two-secret
model; **social recovery** (Shamir among trusted contacts); the **easy security tier**
with convenient recovery; the "My circles" channel; a real (still simple) UI; the
interaction-indexes / no-doomscroll feed behaviour; **multi-peer support, recipient
selection on send, peer delete/replace, and an unknown-sender key fingerprint** (the
follow-ups Slice 02's single-peer TOFU prototype surfaced — see Phase 0 above);
**relay memory management** — active expiry/GC plus request limits, building on
Slice 01's request-size cap (resolves Slice 01's accepted lazy-expiry gap); closing
Slice 01/02's accepted sender-authorization gap at the protocol level (today, an unknown
sender's note is labeled, not blocked — see `docs/ARCHITECTURE.md` §9).

**Tracked cleanup:** `notes.synced_at` (`StoredNote.synced_at`) has been dead since
Slice 03 — `note_sends` is sole source of truth for delivery state, and the column is
only ever written, never read back into a decision. Remove the column, the struct field,
and `content.rs::to_stored()`'s `synced_at: None` the next time a slice is already
touching `content.rs` for another reason; don't let it become permanent by default.

**Slice 04 candidate — receive-side consent surface:**
- *Block / mute*: a local deny-list of keys. Block drops/hides inbound from a key; mute
  receives but doesn't surface it. Applies equally to unknown senders (by key/fingerprint)
  and pinned peers. Fully local — the real anti-harassment lever, and the actual answer to
  Slice 01/02/03's accepted "no receive-side consent gate" limitation.
- *Delete / unpin peer*: remove a peer; their past notes reclassify to unknown via the
  existing recompute-at-display path (the pin-flip in reverse) but they can still reach
  you — delete forgets the name, block refuses the content; the two are orthogonal and
  both are needed. Settle at slice time what happens to pending `note_sends` rows and
  already-received notes addressed to/from the deleted peer (received notes stay and
  reclassify; pending sends need an explicit decision, not an accident).

**Forbid self-add:** reject `add_peer` when the card's key is the caller's own
(`"that's your own card"`). Slice 03's Own-beats-peer classification already makes
self-add harmless either way, so this is zero-risk tidiness, not a fix for a live bug.

**UX — render-on-pin:** refresh the rendered notes list on any peer-table change
(pin/unpin/relabel) without requiring a manual Sync Now — the unknown→known flip is a
local recompute against already-stored notes, no network round trip needed.

**UX — auto-sync-on-post:** posting should also push automatically; the current
manual-only Sync Now is correct for dev/testing but is a later convenience to add.

A related, still-open distinction to design deliberately here rather than improvise: peer
**exchange** UX when a channel already exists between two people (e.g. a QR code, a
`sympoden://` link, or a short pairing code, to make pinning a peer's card easier than
copy-pasting base64) is a friendly, bounded UX problem. Peer **discovery** — finding
someone you don't already have a channel to — is a different and much harder problem,
in direct tension with the no-central-directory privacy thesis (any discovery mechanism
is itself a place that could be ordered to log or surveil who's looking for whom). Keep
these two clearly separate: build (a) when it's useful; do not let it quietly grow into
(b) without a deliberate decision.

**Proves / validates the frontier:** can *nontechnical families* actually create
identities, share, and recover a "lost" phone via social recovery? Test with real
families, not assumptions. Group-key management (re-keying on member removal) is designed
carefully here.

**Non-goals:** the knowledge layer, topics/discovery, the world channel, Tor, mobile (port
after the core is proven on desktop).

---

## Phase 2 — Knowledge layer  *(the DISCOVERY / HOSTING frontier)*

**Goal:** the open commons for facts and science.

**Build:** content tiers + epistemics (lineage, knowledge-state, "lock the record, never
the verdict"); the durable content-addressed layer + **willing-peer replication** (hash-
verified); structured sources; topics (`#`) + seeded-not-gatekept areas; the DHT discovery
index; the "The world" channel with tier labels (News ≠ Facts); epistemic-standing ranking;
correction propagation along the interaction graph.

**Proves / validates the frontier:** can durable knowledge be *hosted and found* on a
network that is still small? Who hosts replicas, and does topic-browse return anything for
a newcomer early on? This is the genuine unknown — measure it; let the wedge carry the
network while you do.

**Non-goals:** Tor/Sanctuary hardening, advanced anti-abuse beyond the structural defaults.

---

## Phase 3 — Hardening & at-risk users

**Goal:** the protection the journalist/whistleblower tier needs — honestly bounded.

**Build:** the Sanctuary posture (Tor via `arti`, text-only, not discoverable);
forward-secret messaging; hardened self-custody recovery (no convenient path);
full reproducible-build verifiability; the honest "what we protect / don't / refuse"
surface shown to users.

**Non-goals:** promising more than the design delivers — every limit stays labelled.

---

## Cross-cutting (all phases)

Invariants enforced throughout (see `CLAUDE.md`). Reproducible builds and zero telemetry
from day one. Encryption in transit at every tier. The engine stays headless-testable and
independent of the UI. Mobile is a distinct, harder build (P2P background/serving/app-store
constraints) — plan it as its own effort, not a port.

## Honest note

Phases 1 and 2 each contain a frontier that a document cannot resolve. The roadmap is
deliberately ordered so that the *adoption* question (Phase 1) and the *discovery/hosting*
question (Phase 2) are each answered by a working system with real users — and so that the
social wedge keeps the project alive while the hardest part (Phase 2's cold-start) is
worked out.
