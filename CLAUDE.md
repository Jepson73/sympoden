# CLAUDE.md — Working Context for Claude Code

This is a **privacy- and security-critical** project. Read this file fully before
writing code. When in doubt, an invariant beats convenience, and a security decision
gets flagged rather than guessed.

## What this is

A privacy-first, local-first, peer-to-peer social/communication network. Each user is
a cryptographic keyfile, not an account. Content lives on the user's own device; the
network is reached peer-to-peer with thin, blind relays for availability. Two purposes:
easy private sharing for families/circles, and an open, evolving commons for facts and
science. See `README.md` and `docs/FOUNDATION.md`.

## HARD CONSTRAINTS — never violate these

These are not preferences. Code that breaks one is wrong by definition.

1. **No personal data collected or stored by the system.** No accounts, email, phone,
   real-name profiles. Identity = a keyfile. The system persists only what a user creates.
2. **No ads. No engagement engine. No algorithmic amplification.** Nothing optimises
   for attention, time-spent, or virality. Feeds are composed of the user's explicit
   choices, never of an algorithm or of passive viewing history.
3. **No point of compulsion.** No central server that can be ordered to scan, log, hand
   over, or take down. The bootstrap is stateless introduction only. Relays hold only
   encrypted, expiring blobs they cannot read.
4. **The client is verifiable.** Open protocol + reproducible builds. No hidden network
   calls, no telemetry, no analytics SDKs — ever.
5. **No content inspection, ever.** Never scan content to enforce a rule. Enforcement is
   by *capability* (what a tier/protocol can carry) and by *people* (block, flag, refuse).
6. **Honest about limits.** Never let UI or copy overstate protection. Best-effort is
   labelled best-effort.
7. **Facts and opinions stay structurally distinct.** Corrections are first-class and
   visible. The record is immutable; the verdict on it stays open ("lock the record,
   never the verdict").
8. **Crypto: use vetted crates only. Never roll your own.** Zeroize secrets. Treat all
   key material as radioactive.

## Tech stack — RESOLVED. Do not re-litigate.

- **Language:** Rust (engine core).
- **Crypto:** the RustCrypto ecosystem — `ed25519-dalek` (identity/signing),
  `x25519-dalek` (key agreement), `chacha20poly1305` (AEAD), `argon2` (passphrase KDF),
  `sha2` (content addressing). **Do NOT use `sodiumoxide`** — it is deprecated
  (RUSTSEC-2021-0137). Named primitives must match the crate actually used.
- **Local storage:** SQLite via `rusqlite`/`sqlx` with **SQLCipher** (encrypted at rest).
- **CRDT (Phase 1+):** `automerge` (Rust) for shared/collaborative state.
- **Content addressing:** SHA-256 content IDs forming a Merkle DAG. **Not a blockchain.**
  Knowledge needs no global consensus and has no double-spend.
- **P2P (Phase 1+):** `rust-libp2p` — Kademlia DHT (discovery), gossipsub (propagation),
  Circuit Relay v2 + AutoNAT + DCUtR (relay & NAT traversal). Transport security via Noise.
- **Anonymity (Phase 3):** `arti` (Rust Tor) for the hardened "Sanctuary" tier.
- **UI shell:** **Tauri** (Rust-native, system webview, reproducibly buildable). Web tech
  for the front-end, inside a native app — **never** a browser pointed at localhost.
- **Social recovery (Phase 1+):** a Shamir secret-sharing crate (e.g. `sharks`).

## Architecture in one breath

Two cleanly separated layers: an **engine** (Rust core — identity, crypto, storage,
sync, network) and a **UI** (Tauri shell, just the view). The data model has two
sub-layers: **ephemeral** (presence-gated, host-from-source, vanishes; the social layer)
and **durable** (content-addressed, peer-replicated, DHT-indexed; the knowledge layer).
Visibility is per-post and enforced by encryption (open / circle / private). Full detail
in `docs/ARCHITECTURE.md`.

## What to build first

**`docs/slices/SLICE-01.md`** — and nothing beyond it yet. Identity + local note +
async sync between two non-simultaneous instances through one blind relay, on desktop.
Follow the roadmap (`docs/ROADMAP.md`); do not build ahead of the current phase.

## What is OPEN — do NOT over-engineer

These are genuine unknowns to be answered by experiment, not solved speculatively in code:
- **Discovery + durable-layer hosting + cold-start** (the open frontier). Do not attempt
  a global discovery/hosting solution in early phases. Keep it minimal until there's a
  network to test against.
- **Group-key management for circles** (re-keying on member removal) is hard; design it
  deliberately in Phase 1, don't improvise it early.
- **Mobile P2P** (background/serving/app-store constraints) is a Phase-1+ problem and a
  different beast from desktop. Prototype on desktop.

## Coding conventions

- Idiomatic Rust. No `unwrap()`/`expect()`/`panic!` on any engine or network path —
  return `Result` with typed errors (`thiserror`). Panics only in tests and truly
  unreachable invariants.
- Keep the **engine** independent of the **UI**; the engine must be usable headless
  (and testable without Tauri).
- Security-critical code (crypto, key handling, network framing) lives in clearly
  isolated modules with thorough unit tests and property tests where feasible. Crypto
  test coverage target: ~100%.
- Zeroize key material (`zeroize`); never log secrets, never log plaintext content, never
  log IP-level peer data.
- Every new capability: check it against the HARD CONSTRAINTS above before implementing.
  If a task seems to require breaking one, stop and surface the conflict.
- Commits/PRs: small, reviewable, with a one-line note on which invariant(s) the change
  touches if any.

## Definition of done for Slice 01

Two desktop instances, never running at the same time, exchange a signed text note via a
relay that never sees plaintext; the receiver verifies the sender's signature and
displays the note; the client builds from source with no telemetry. See SLICE-01 for the
precise acceptance criteria and the explicit non-goals.

## Doc map

`README.md` (orientation) · `docs/FOUNDATION.md` (vision/why) · `docs/ARCHITECTURE.md`
(how) · `docs/ROADMAP.md` (what next) · `docs/slices/SLICE-01.md` (first build) ·
`docs/RECONCILIATION.md` (ADR mapping) · `docs/GLOSSARY.md` (terms).
