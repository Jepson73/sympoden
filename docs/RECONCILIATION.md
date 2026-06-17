# Reconciliation Pass — ADRs vs Foundation v0.3

> One pass over every existing decision, judged against the foundation doc.
> This is a *worklist*, not new decisions. Verdicts:
>
> - ✅ **ALIGNED** — consistent; some are now *more* central than before (marked ↑).
> - ✏️ **REVISE** — mostly fine, one specific change needed.
> - ⚠️ **FIX** — contains a real contradiction (with itself or the foundation). Resolve before code.
> - ↩️ **RESCOPED** — the foundation changed what this decision covers.

---

## Verdict table

| ADR | Topic | Verdict | What to do |
|-----|-------|---------|------------|
| 001 | Key version field | ✅ | Keep. Note: "old key signs new key" migration creates a linkage that fights clean departure — only matters for the durable layer now, so low priority. |
| 002 | Content-addressed IDs | ✅↑ ⚠️ | Now the backbone of epistemics ("lock the record") *and* durable replication (hash-verified copies). **Fix the contradiction:** a random `nonce` breaks the "automatic dedup / same post = same ID" claim. Drop the nonce (pure content address) unless a concrete grinding threat is named. |
| 003 | Automerge schema versioning | ✏️ | Keep the versioning rules. Revise the assumption that *everything* lives in one ever-growing `SharedDocument` — ephemeral content is now presence-gated/host-from-source, not permanently replicated. Unbounded-growth (H-004) now scoped to the durable layer + event log only. |
| 004 | Read cursor (OpId) | ✅ | Keep. Connect to correction-propagation: the feed is where a reversal should surface on revisit. |
| 005 | Multiple identity policy | ✅↑ | Keep — this *is* the persona-level departure mechanism. |
| 006 | Full event storage | ✏️ | Keep "compute standing from events, never counts" (it's the epistemics engine). Revise: event permanence should **follow the tier of its subject** — endorsements/disputes on a durable Fact persist; reactions to ephemeral posts vanish with them. Not all events live forever. |
| 007 | Structured source schema | ✅↑ | Keep. Sources are the evidence layer that makes "Fact = commitment, not verdict" enforceable. Text-only archive option dovetails with Sanctuary. |
| 008 | Immutability policy | ⚠️ | "No silent edits, corrections are new linked posts" = aligned, keep. **Delete the 5-minute minor-correction window:** it contradicts content-addressing (an edit changes the ID) and "zero engagement" is unknowable in a P2P/CRDT setting. Corrections are *always* new posts. |
| 009 | Bootstrap server trust | ✏️ | Keep signed/multi-operator/stateless intro. **Soften the overclaim** — you can't continuously verify a third party logs nothing (invariant #6). Add reproducible-builds framing (invariant #4). Reframe as pure stateless introduction, distinct from relays (now core). |
| 010 | Account deletion | ↩️ ⚠️ | **Major rewrite.** Presence-gating dissolves most of this: ephemeral content vanishes on quit — no five-step flow, no tombstones. Five-step + FORMER_MEMBER re-attribution now applies **only to the durable layer**. **Fix GDPR:** retaining `original_author_id` contradicts erasure — either drop it or replace with a non-reversible proof of voluntariness. |
| 011 | Private messaging | ⚠️ ✏️ | PrivateDocument storage = aligned. **Fix the crypto:** the "`for_sender` SealedBox decryptable by sender" misuses sealed boxes, and deniability + SealedBox don't compose as written. **Bring forward secrecy forward** if at-risk users are Phase 1. Store-and-forward = the availability buffer (now core, see 019). |
| 012 | Post elevation | ✅↑ | Keep. Elevation to Fact *is* the foundation's single gesture = knowledge claim + persistence + permanence-consent. Annotate that link. |
| 013 | Lateral movement | ✅↑ | Keep. This *is* the epistemics engine: the typed movement is the "why it changed"; the chain is "history is the artifact." |
| 014 | Shared/Private split | ✅↑ ✏️ | Keep the type-enforced split (it's how invariants #1/#5 are guaranteed). Revise: add the ephemeral-vs-durable distinction *within* shared content — not everything public is a permanent replicated doc anymore. |
| 015 | Topic model | ✅↑ | Keep. Content-addressed `TopicId` directly feeds the DHT discovery layer (open question). |
| 016 | Reply model | ✅ | Keep. First-class replies, `parent_id` in hash, `lineage_root`. Consistent. |
| 017 | Tone nudge | ✏️ ⚠️ | Keep "a mirror, never a gate." **Carve-out for invariant #5:** tone detection is content analysis, permitted *only* if purely on-device, never transmitted, never gating, user-disablable — state this explicitly. Remove the reference to the now-deleted 5-min edit window. Tone flags on ephemeral posts should be ephemeral. |
| 018 | Partial deletion | ↩️ | Rescope like 010: ephemeral withdrawal is free (stop hosting); durable re-attribution remains and inherits the `original_author_id` fix. |
| 019 | Relay node trust | ✏️↑ | **Promote from Phase 2 to Phase 1 core.** The thin, blind, stateless, expiring-blob relay is the *required* availability buffer for async/offline delivery — not optional for the consumer case. Constraints already align. |
| 020 | Security model | ✏️ ⚠️ | Connection presets → folded into the Safety Ladder. **Fix the crypto stack:** `sodiumoxide` is deprecated (RUSTSEC-2021-0137) and the stated AES-256-GCM doesn't match its primitives; Cargo also mixes in RustCrypto. Pick one ecosystem (recommend RustCrypto) and make named primitives match dependencies. |
| 021 | USB modes | ↩️ | Subsumed into the ladder's storage axis. Keep Local/Hybrid/Full as implementation detail under Sanctuary/Standard; unify the vocabulary so there aren't two parallel "modes" languages. |
| 022 | Tor transport | ✅ | Aligned, subsumed into the ladder (Sanctuary = Tor default). Honest "what Tor does/doesn't protect" matches invariant #6. Keep; reference the ladder. |
| 023 | Open protocol | ✅↑ ✏️ ⚠️ | Now invariant #4. **Extend:** open protocol ≠ verifiable binary — add **reproducible builds** to defeat a slipped-in scanner. **License conflict:** CC0 protocol is good, but the non-commercial reserved-rights reference-impl license fights the gift/public-interest decision — rewrite to invite contributors/operators. |
| 024 | Feed modes | ✅ | Keep. Minor: feeds must surface KnowledgeState/reversal updates so corrections reach readers (correction-propagation). |

### Non-ADR artifacts
| Artifact | Verdict | What to do |
|----------|---------|------------|
| LICENSE | ⚠️ | Conflicts with the gift/public-interest decision. Drop the liquidated-damages/penalty clause and reserved-commercial-rights model; adopt an OSI-recognised license that invites contributors and operators. |
| PROJECT.md (matrix + hazards) | ✏️ | Add a **Status** column (planned/partial/built) so the present-tense matrix stops implying things exist. Update H-004 (scoped to durable layer) and the deletion hazards (simplified by ephemerality). |
| 3× overview docs + filename typo | ✏️ | Merge into one; FOUNDATION.md is now the canonical core. Fix `Socail_…` typo. |
| ABUSE_MODEL.md | ✅ ✏️ | Local block / PoW / community ban / tone nudge align. Reconcile tone-nudge with the invariant #5 carve-out. PoW remains weak vs determined actors (already acknowledged). |

---

## Cross-cutting changes (the themes behind the table)

1. **The persistence/ephemerality split is the biggest new lens.** Several ADRs
   (003, 006, 014) silently assume "everything public lives in one permanent,
   fully-replicated SharedDocument." That's no longer true — ephemeral content is
   presence-gated and host-from-source. These three need to absorb that.
2. **Relays are promoted from Phase 2 to core** (019, 011). Without the blind
   buffer, async delivery doesn't work on mobile/NAT.
3. **Three open crypto items must be reconciled together** (002 nonce, 008 edit
   window, 011 messaging, 020 stack). Best handled as one "crypto cleanup" pass.
4. **Deletion is rescoped to the durable layer** (010, 018, 006) and carries one
   real GDPR fix (`original_author_id`).
5. **Verifiable client = open protocol + reproducible builds** (023, 009) — the
   structural answer to Chat-Control-style mandates.
6. **License rewrite** (LICENSE, 023) follows from the gift decision.

---

## Suggested order of attack (cheap → load-bearing)

1. **Housekeeping** — Status column, merge overviews, fix typo, mark subsumed ADRs
   (021, 022 → ladder). Low effort, removes false signals.
2. **Delete contradictions on paper** — 008 edit window; 002 nonce. Free now,
   expensive after peers sync.
3. **Rescope deletion** — rewrite 010/018 around ephemerality + fix GDPR field.
4. **Crypto cleanup pass** — one sitting: pick RustCrypto, fix 020 stack, redesign
   011 messaging, decide forward-secrecy timing.
5. **Promote relays + absorb persistence** — 019 to core; revise 003/006/014.
6. **License + verifiability** — rewrite LICENSE; add reproducible builds to 023.

Nothing here is new design — it's making the existing 24 decisions agree with the
core you've already settled. After this pass the spec stops contradicting itself,
which is the precondition you set for writing any code.
