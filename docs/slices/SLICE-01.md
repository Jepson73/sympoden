# Slice 01 — First Prototype

The smallest runnable thing. Build *only* this; resist every temptation to add more.

## Goal

A **desktop** app (Tauri + Rust engine) where:
1. A user creates an encrypted identity (Ed25519 keyfile, Argon2id passphrase).
2. They post a plain-text note, stored locally (SQLite + SQLCipher).
3. The note syncs to a **second instance** through **one blind relay** —
   while the two instances are **never online at the same time**.

## What it must prove

- **Async store-and-forward works.** Two peers who never overlap can still exchange a
  note, via a relay that holds an encrypted blob and forwards it later. This is the core
  bet of the whole architecture — if it doesn't work cleanly here, the design must bend.
- **Identity friction is tolerable.** Creating and unlocking a keyfile-based identity is
  the first thing every user hits. Feel it early.

## Components

**Engine (Rust, headless-testable):**
- `identity`: generate Ed25519 keypair; encrypt the private key with an Argon2id-derived
  key from a passphrase; write/read a keyfile. Zeroize secrets.
- `store`: SQLite + SQLCipher; one table of notes `(id, author_pubkey, body, created_at,
  signature)`. `id` = SHA-256 content address.
- `crypto`: sign a note with Ed25519; verify on receipt; (for transport to the relay)
  encrypt the blob to the recipient's X25519 key with ChaCha20-Poly1305.
- A minimal **sync** routine: package a signed note as an encrypted blob addressed to the
  recipient; push to the relay; on the other side, pull, decrypt, verify signature, store.

**Relay (dead simple for the prototype):**
- Accepts an opaque, encrypted blob keyed by recipient ID; stores it with a short TTL;
  hands it to the recipient on request; deletes after delivery or expiry.
- **Sees no plaintext, ever.** Holds only ciphertext + a routing key + an expiry.
- A single small Rust binary is fine; no libp2p required yet (a plain socket/HTTP-ish
  endpoint is acceptable for Slice 01 — libp2p comes in Phase 1).

**UI (Tauri, one screen):**
- Create-identity (enter passphrase) · write-a-note · list of received notes.
- Two buttons: "Post" and "Sync now." That's the whole UI.

## Acceptance criteria

1. **Instance A** (Alice) creates an identity, writes a note, posts it (blob lands on the
   relay), then **goes fully offline**.
2. Later, **Instance B** (Bob) comes online, runs "Sync now," **fetches** Alice's blob,
   **decrypts** it, **verifies** Alice's Ed25519 signature, and **displays** the note.
3. At no point did the relay hold or log plaintext, the note body, or anything beyond an
   encrypted blob + routing key + expiry.
4. The client builds from source with **no telemetry, no analytics, no hidden network
   calls**.
5. A wrong passphrase fails to unlock the keyfile cleanly (no panic, typed error).

**Status:** code-complete, headless-verified, and GUI-verified — `cargo test`
(workspace) and `scripts/demo.sh` cover criteria 1, 2, 3, 5 end-to-end at the
engine/CLI level, and `sympoden-app`'s command layer (criteria 1, 2, 5 through the
Tauri commands themselves) is unit-tested the same way, with no display server
involved. The two-instance GUI click-through of criteria 1–2 on a real desktop
(sympoden-app/README.md has the walkthrough) was manually verified on 2026-06-18.

## Explicit NON-goals (do not build these in Slice 01)

Circles · audience encryption to groups · media · discovery · DHT · topics · Tor · mobile
· automerge/CRDT (a single-writer note is fine here) · group keys · social recovery ·
follow/friend relationships · the world channel · ranking · multi-device · pretty UI.

## Suggested crates

`ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `argon2`, `sha2`, `zeroize`,
`rusqlite` (with SQLCipher) or `sqlx`, `thiserror`, `serde`/`serde_json`, `tauri`.
(`rust-libp2p` and `automerge` are deliberately **not** here — they arrive in Phase 1.)

## Stretch (only after the above passes)

Two-way exchange; multiple notes; a second note type; a trivial one-way "follow" so B
auto-pulls A's future notes. Anything more belongs to Phase 1 — see `docs/ROADMAP.md`.

## Known limitations (accepted for Slice 01)

a. **No sender authorization.** Adding a peer only designates who *you* send to; on
   receive, any self-consistently-signed note sealed to your X25519 key and pushed
   under your routing key is accepted and shown by raw key. Anyone holding your public
   card can do this. Impersonating a *specific* peer is still impossible (that needs
   their signing key) — this is message authentication, not sender authorization,
   currently an emergent property and hereby an accepted one for this slice.
b. **Relay expiry is lazy-only.** Entries are reaped on access (push/pull), not by an
   active sweep, so relay memory is not yet bounded for keys that are never pulled
   again.
c. **Note ordering is author-chosen.** `created_at` is an author-signed timestamp; a
   writer can place their note anywhere in the recipient's timeline.
d. **Criterion 4 ("no hidden network calls") is partially evidenced, not proven.** It
   currently rests on (i) no named-analytics dependency and (ii) inspection showing the
   only network egress in engine+cli+relay is the relay protocol. It is *not yet*
   verified under network isolation. `sympoden-app`'s command layer is built,
   clippy-clean, and unit-tested headlessly (see Status above); its webview glue
   (JS `invoke()` calls, rendering) has no automated coverage but was exercised through
   an actual GUI session on 2026-06-18 (see Status above).

## Invariant check for this slice

No personal data (keyfile only) ✓ · no ads/engine ✓ · relay is blind and stateless-ish (encrypted, expiring) ✓ · no content inspection ✓ · verifiable/no-telemetry build ✓ · honest scope ✓ · vetted crypto crates only, secrets zeroized ✓ · facts/opinions structurally distinct — N/A this slice (single note type, no claims/corrections). If any added feature would break one of these, stop and surface it.
