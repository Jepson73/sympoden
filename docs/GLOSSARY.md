# Glossary

Shared vocabulary. Keep these consistent across docs and code.

**Invariant** — a non-negotiable property that holds at every layer/tier/phase. If a
decision breaks one, the decision is wrong. (See `FOUNDATION.md` §1, `CLAUDE.md`.)

**Engine** — the Rust core (identity, crypto, storage, sync, network). Security-critical;
headless-testable; reproducibly built.

**UI** — the Tauri shell; only a view onto the engine. No security logic.

**Ephemeral layer** — social/casual content: host-from-source, presence-gated, vanishes
on departure; buffered briefly by a blind relay when peers don't overlap.

**Durable layer** — knowledge content (Reference/Fact): content-addressed, replicated by
willing peers, DHT-indexed, survives its author. Opt-in via elevation.

**Content tiers** — `Private / Opinion / Reference / Fact`. A *commitment level*, not a
truth verdict. Fact obliges sources + signature + durability + acceptance of revision.

**Lock the record, never the verdict** — the artifact is permanent and tamper-evident
from publication; its truth standing stays open and reversible forever.

**Knowledge-state / lineage** — typed movements between linked records
(strengthened / refined / superseded / reversed / retracted / contested) recording *what
a claim came from* and *why it changed*. The chain is the valuable object.

**Visibility / audience** — per post: **Open** (anyone), **Circle** (members only,
enforced by encryption), **Private** (self). Visibility = decryptability.

**Circle** — a closed audience (Friend / Family / custom). Requires a *mutual connection*;
private *labels* may be asymmetric. Posts are encrypted to members' keys.

**Passerby / Follow / Friend** — relationship states. Passerby sees open content but
indexes nothing; Follow indexes a person's open stream (one-way); Friend/circle is mutual,
gets the encrypted audience and may hold a leased copy.

**Seeing vs indexing** — *seeing* is transient and open (no relationship needed);
*indexing* (a persistent pointer for follow-up) requires a relationship, or — for open
posts — an *interaction* (like/dispute/reply/bookmark). Looking never indexes.

**Automatic vs deliberate retention** — *automatic* copies (leased friend-copy, relay
buffer) run on the **owner's** clock (first-owner authority) and purge on departure;
*deliberate* saves are available to anyone who can see the content and become the saver's
own copy (the screenshot limit — physical, honest).

**Lease / first-owner authority** — a friend-held copy is tethered to the source's
existence; the source sets the purge window. Departure = signed tombstone (immediate
purge) or graduated absence (≈6mo heads-up → ≈1yr purge) as a safety net.

**Two-secret model** — the **passphrase** decrypts local data; the **identity key** proves
who you are to the network. Key loss costs *identity continuity*, not content.

**Not a backup drive** — the platform is not where your canonical photos/files live; this
lowers the stakes of key loss.

**Social recovery** — recover a lost identity key via Shamir shares held by trusted
contacts (the family circle doubles as the recovery network).

**Security ladder / tiered security** — setup burden and recovery convenience scale with
the posture. Easy tier (families) = convenient recovery; hardened tier (at-risk) =
self-custody, no convenient recovery. Escalation is forward-only.

**Safety ladder** — **Standard** (media allowed, discoverable, direct/Tor) and
**Sanctuary** (text-only, Tor, not discoverable, hardened).

**Two channels** — **My circles** (people, ephemeral, recency — connection) and **The
world** (open, topic-organised, epistemic-standing-ordered, pull-not-push — information).

**Relay (blind)** — a thin, stateless-ish node holding *encrypted, expiring* blobs it
cannot read, for async/offline delivery. Many, refusable. Not a point of compulsion.

**Bootstrap** — stateless peer introduction at first contact; holds nothing afterward.

**Content addressing / Merkle DAG** — SHA-256 IDs; records linked by hash; tamper-evident;
verified replication. **Not a blockchain** (no global consensus, no double-spend).

**DHT** — distributed hash table (Kademlia, via libp2p): maps topic → content hashes →
hosting peers. The discovery index.

**Topic (#) / area** — content-addressed topic tag; **areas** are a small set of
seeded-not-gatekept broad categories used as a newcomer map and DHT anchor.

**The wedge** — the family/circle social use case: valuable at five users, needs no
discovery, carries adoption while the knowledge layer fills.

**The frontier** — the one genuinely unsolved problem: discovery + durable-layer hosting
+ cold-start, weakest when the network is smallest. Validated only by a running network.

**Sanctuary vs Standard** — see *Safety ladder*.

**Verifiable client** — open protocol + reproducible builds, so "no scanner, no backdoor"
is checkable, not merely promised.
