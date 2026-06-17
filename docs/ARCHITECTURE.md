# Architecture

Concrete technical architecture. The *why* lives in `FOUNDATION.md`; this is the *how*.
Anything marked **[FRONTIER]** is a genuine unknown to be validated by building, not
over-specified now.

## 1. Two layers: engine and UI

- **Engine** — a Rust core library: identity, crypto, local storage, sync/CRDT,
  networking, content/tiers, epistemics, discovery. Security-critical; must build
  reproducibly (invariant #4); must run and be tested **headless**, independent of any UI.
- **UI** — a **Tauri** shell (system webview, web-tech front-end) that is *only a view*
  onto the engine. No security logic in the UI. Never a browser-at-localhost (bad for
  nontechnical users and a security liability).

The engine exposes a local API to the UI (Tauri commands / a local IPC boundary). Mobile
later reuses the same Rust core via FFI behind a native UI.

## 2. Engine modules

| Module | Responsibility |
|--------|----------------|
| `identity` | Keyfile (Ed25519), passphrase unlock (Argon2id), recovery (Shamir, Phase 1+), multiple/compartmentalised identities |
| `crypto` | Signing, key agreement (X25519), AEAD (ChaCha20-Poly1305), hashing (SHA-256), audience encryption, secret zeroizing |
| `store` | Local encrypted DB (SQLite + SQLCipher): posts, events, circles, cursors, collections |
| `sync` | CRDT merge (`automerge`, Phase 1+); read cursors; conflict-free convergence |
| `content` | Post model, content-addressed IDs, tiers (Private/Opinion/Reference/Fact), lineage links |
| `epistemics` | Knowledge-state (strengthened/superseded/contested/reversed/retracted), evidence-state computation, the discovery/standing ranker |
| `net` | `libp2p` transport (Noise), peer dialing, NAT traversal |
| `relay` | Blind store-and-forward of encrypted, expiring blobs for async/offline delivery **[FRONTIER for scale]** |
| `discovery` | Kademlia DHT: topic → content hashes → hosting peers; seeded areas **[FRONTIER]** |
| `anon` | `arti`/Tor integration for the Sanctuary tier (Phase 3) |

## 3. Tech stack & rationale

- **Rust** — memory safety for a security-critical, long-lived codebase.
- **RustCrypto** (`ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `argon2`, `sha2`)
  — one coherent, maintained ecosystem. Replaces the deprecated `sodiumoxide`. Keep the
  named primitive and the actual crate in sync.
- **SQLite + SQLCipher** — robust, embedded, encrypted-at-rest local store.
- **automerge** — mature Rust CRDT; gives offline-first convergence without a server.
- **SHA-256 content addressing → Merkle DAG** — tamper-evident records and verified
  replication. **Not a blockchain:** no global consensus, no double-spend, no token, and
  full replication would reopen unbounded growth. Hash-verified selective replication
  instead.
- **rust-libp2p** — batteries-included P2P: Kademlia (DHT), gossipsub (pub/sub),
  Circuit Relay v2 + AutoNAT + DCUtR (relay & hole-punching). Avoids hand-rolling P2P.
- **arti** — Rust Tor for the hardened tier.
- **Tauri** — native app, controlled webview, small attack surface, reproducible builds.

## 4. Data model

### Two sub-layers (this is the key structural idea)
- **Ephemeral** (social/casual): host-from-source, presence-gated, vanishes on
  departure. Delivered directly when peers overlap, else buffered by a blind relay for a
  bounded window. No permanent replication. Most volume lives here.
- **Durable** (knowledge): content-addressed, replicated by willing peers, DHT-indexed,
  survives its author. The author opts in by elevating to Reference/Fact — which is also
  the consent to permanence. Small and deliberate by design.

### Content tiers (per post)
`Private → Opinion → Reference → Fact`. A tier is a *commitment level*, not a truth
verdict. Fact obliges sources + signature + durability + acceptance of dispute/reversal.

### Epistemics ("lock the record, never the verdict")
The artifact is immutable from publication; its standing is live and reversible. Lineage
links + typed movements (strengthened/superseded/contested/reversed/retracted) record
*what it came from* and *why it changed*. The chain — how understanding moved — is the
valuable object. The same standing signals rank discovery (no engagement ranker).

### Visibility & audience (per post; encryption-enforced)
- **Open** — anyone can see; indexing happens on *interaction* (like/dispute/reply/
  bookmark), not on viewing. Followers index the author's open stream.
- **Circle** (Friend/Family/custom) — visible only to members, enforced by **encrypting
  to members' keys** (visibility = decryptability). Circles require a *mutual connection*;
  the private *labels* may be asymmetric.
- **Private** — self only; never leaves the device.

### Relationships
Passerby (sees open, indexes nothing) · Follow (one-way, indexes the open stream) ·
Friend/circle (mutual, encrypted audience, may hold a leased copy).

### Retention
- **Automatic** (leased friend-copy, relay buffer) — runs on the **owner's** clock
  (first-owner authority); graduated absence purge (≈6mo heads-up → ≈1yr) as a safety net;
  signed "leaving" = immediate purge.
- **Deliberate** (explicit save/export) — available to anyone who can *see* it; once made
  it's the saver's own copy, outside any lease (the screenshot limit — physical, honest).

## 5. Identity, recovery & tiered security

- Identity = Ed25519 keyfile, unlocked by an Argon2id passphrase. Two secrets, two jobs:
  the **passphrase** decrypts local data; the **identity key** proves who you are to the
  network. Key loss costs *identity continuity*, not content (this is **not a backup
  drive**).
- **Security is a ladder, defaulted low.** Recovery convenience scales with the tier:
  easy tier → convenient social/family recovery (Shamir among trusted contacts);
  hardened tier → self-custody, no convenient recovery (convenience = an attack surface).
- **Escalation is forward-only.** It protects future activity, not past metadata. Serious
  threat models start a *fresh compartmentalised identity*, never upgrade a casual one.
- The floor: even the easy tier keeps all invariants (no ads/data/central-store; encrypted).

## 6. Networking

- Direct peer connections when peers overlap (libp2p + Noise).
- **NAT traversal** via AutoNAT + DCUtR + Circuit Relay v2.
- **Async/offline delivery** via a **blind store-and-forward relay**: holds encrypted,
  expiring blobs it cannot read, forwards on the recipient's next sync, then forgets.
  (Circuit Relay v2 handles *live* relaying; offline store-and-forward of opaque blobs is
  an additional behaviour to build on top.) **[FRONTIER: reliability at small scale.]**
- **Sanctuary tier:** route over Tor (`arti`); text-only; not publicly discoverable.

## 7. Surfaces

- **Two channels:** "My circles" (people, ephemeral, recency-ordered — connection) and
  "The world" (open, topic-organised, epistemic-standing-ordered — information).
  Foreground/background by user choice. The world channel is pull, not push, and bounded.
- **Discovery:** content-addressed topics (`#`) + a small set of *seeded-not-gatekept*
  broad areas as a newcomer map and DHT anchor; emergent topics beneath. Onboarding is
  topic-first/durable-first, never a livefeed. **News ≠ Facts:** every item shows its tier.
  **[FRONTIER: this only populates at scale.]**

## 8. Cross-cutting

Reproducible builds; zero telemetry; encryption in transit at every tier; secrets
zeroized; the engine headless-testable; invariants checked at every layer.

## 9. The open frontier (read before scaling anything)

Discovery, durable-layer hosting, and cold-start are **one** problem: you can only find
durable content that someone hosts and that's findable, and all of it is weakest when the
network is smallest. No rule resolves it — a running small network does. Keep these
modules minimal until there's something real to measure. The **social wedge** (Phase 1)
deliberately does not depend on this, which is what buys time to solve it.
