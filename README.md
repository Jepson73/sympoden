# Private Social Platform — Project Documentation

> A privacy-first, local-first, peer-to-peer communication network. No ads, no
> personal-data harvesting, no central content store. A place for families and
> circles to share privately, and for facts and science to live and evolve in the
> open — built to be honest about exactly what it does and does not protect.

## Status

**Design complete; pre-implementation.** The design has been worked through in depth
(see `docs/FOUNDATION.md`, currently v0.16). The next step is the first running slice,
not more design. Everything in these docs is a *draft to be tested against reality* —
the two genuinely unsolved problems can only be answered by building (see below).

## The non-negotiables (invariants)

These hold at every layer, every tier, every phase. If a design or implementation
decision contradicts one, the decision is wrong — not the invariant. Full text in
`docs/FOUNDATION.md` §1; enforced as hard rules in `CLAUDE.md`.

1. No personal data — keyfile identity only; the system stores only what a user makes.
2. No ads, no engagement engine, no algorithmic amplification.
3. No point of compulsion — no entity that can be ordered to scan, log, or hand over.
4. The client is verifiable — open protocol + reproducible builds.
5. No content inspection — ever. Rules are enforced by capability and by people.
6. Honest about limits — never overstate what is protected.
7. Facts and opinions stay structurally distinct; corrections are first-class.

## How to navigate these docs

| File | What it is | Read it when |
|------|------------|--------------|
| `README.md` | This file — orientation and index | First |
| `CLAUDE.md` | Working context + hard rules for Claude Code | Before writing any code |
| `docs/FOUNDATION.md` | The vision: invariants, ladder, persistence, epistemics, interaction, discovery, ease/recovery, client architecture, open questions | To understand *why* |
| `docs/ARCHITECTURE.md` | Concrete technical architecture + tech stack | To understand *how* |
| `docs/ROADMAP.md` | Phased build order | To understand *what next* |
| `docs/slices/SLICE-01.md` | The first prototype spec — build this first | To start building |
| `docs/RECONCILIATION.md` | Maps the original 24 ADRs to this foundation | When touching an ADR |
| `docs/GLOSSARY.md` | Shared vocabulary | When a term is unclear |

## The one honest open problem

Almost everything is resolved or has a chosen approach. **One problem is genuinely
unsolved and cannot be solved on paper:** can durable knowledge be *hosted and found*
on a *small* network — discovery + durable-layer hosting + cold-start are one problem,
weakest exactly when the network is smallest. The strategy that buys time to solve it:
**the social wedge** — the family/circle use case is valuable at five users, needs no
discovery, and carries adoption while the knowledge commons fills. See `ROADMAP.md`.

A second make-or-break (the *adoption* frontier — can nontechnical families use a
keyfile/P2P system) has a chosen approach (tiered security, social recovery,
not-a-backup) but is likewise only proven by real users.

## Tech stack (one line)

Rust engine (RustCrypto, libp2p, automerge, SQLite/SQLCipher) + Tauri desktop shell;
arti/Tor for the hardened tier. Details and rationale in `docs/ARCHITECTURE.md`.

## Starting point

Build `docs/slices/SLICE-01.md`: a desktop app that creates an encrypted identity,
posts a text note, and syncs it to a second instance through one blind relay — while
the two instances are never online at the same time. A few hundred lines. It tests the
core bet (async store-and-forward) and the identity friction, and nothing else.
