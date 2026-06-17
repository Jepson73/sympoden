# Roadmap

Phased build order. Each phase de-risks the next; **don't skip ahead.** The two
make-or-break unknowns are validated by *real use*, not by spec — they're flagged below.

## Guiding sequence

**Social wedge first, knowledge network emerges.** The family/circle social use case is
valuable at five users and needs no discovery — it carries adoption while the harder
knowledge/discovery layer is built and tested on top. Prototype on desktop; ship the
product on mobile.

---

## Phase 0 — Slice 01 (prototype)  → `docs/slices/SLICE-01.md`

**Goal:** the smallest runnable thing. Desktop (Tauri + Rust engine): create an encrypted
identity, post a text note locally, sync it to a second instance through one blind relay —
the two instances **never online at the same time**.

**Proves:** (1) async store-and-forward via a blind relay actually works; (2) the
identity-creation friction is tolerable.

**Non-goals:** circles, media, discovery, DHT, Tor, mobile, automerge, group keys, social
recovery, polished UI. One screen, two buttons.

---

## Phase 1 — Social wedge MVP  *(the ADOPTION frontier)*

**Goal:** a real family can use it for easy, private sharing.

**Build:** circles (mutual connection; audience enforced by encrypting to members' keys);
follow vs friend; the ephemeral presence-gated layer + blind relay buffer; the two-secret
model; **social recovery** (Shamir among trusted contacts); the **easy security tier**
with convenient recovery; the "My circles" channel; a real (still simple) UI; the
interaction-indexes / no-doomscroll feed behaviour.

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
