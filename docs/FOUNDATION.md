# Foundation — Invariants & Safety Ladder (v0.17, draft to be torn apart)

> This is the *stable core* the rest of the plan hangs off. Everything here should
> survive every rewrite. If a later design decision contradicts an invariant, the
> decision is wrong — not the invariant. Everything *not* in this file is revisable.

---

## 1. Invariants (true at every layer, every rung, every phase)

1. **No personal data.** No accounts, no profiles tied to real identity, no email,
   no phone. Identity is a keyfile and nothing more. The system stores only what a
   user creates, on their device.
2. **No ads. No engagement engine.** No algorithmic amplification, no feed
   optimisation, no "time spent" metric. Nothing in the system is designed to
   maximise attention.
3. **No point of compulsion.** No central entity exists that can be ordered to
   scan, log, hand over, or take down. The bootstrap server is stateless and does
   introduction only — it holds nothing it could be compelled to produce.
4. **The client is verifiable.** Open protocol + reproducible builds, so "no
   scanner, no backdoor" is something a user can *check*, not something they must
   *believe*. (This is the direct structural answer to Chat-Control-style mandates.)
5. **No content inspection — ever.** Rules are enforced by *capability* (what a tier
   can physically carry) and by *people* (block, flag, operator refusal), never by
   the system reading content. The moment the system inspects content to enforce a
   rule, it has become the thing this project exists to refuse.
6. **Honest about limits.** The platform states plainly what it does NOT and CANNOT
   protect. A security tool that overstates itself is more dangerous than one that
   understates itself.
7. **Facts and opinions stay structurally distinct.** Corrections are first-class
   and visible. The network tilts toward facts through *structure and community*,
   not through a central arbiter of truth.

---

## 2. What we protect / don't protect / refuse to be

**We protect:** the content of private text; identity-data minimisation (there is
almost nothing to leak); absence of central logs/metadata; censorship-resistance of
public knowledge once shared.

**We do NOT protect against:** behavioural correlation (writing style, posting
times, topic focus); a compromised device or coerced passphrase; someone reading
over your shoulder; text-based grooming or harm inside a private channel (same blind
spot as any end-to-end messenger); anything you link out to on the open internet.

**We refuse to be:** plumbing for CSAM (the safest tier physically cannot carry
media; operators may refuse media elsewhere); an amplification engine; a data
broker; a single point of state compulsion; a tool that lies about its own safety.

---

## 3. The Safety Ladder

Two axes, kept deliberately separate. **Resist adding rungs or dials until each one
that exists is actually built** — sprawl is the enemy here.

### Axis A — Safety posture (session/identity level)
This collapses what the old ADRs split across three places (ADR-020 transport
presets, ADR-021 USB modes, and an unwritten media axis) into ONE ladder:

| Rung | Media | Transport | Storage | Visibility | Who it's for |
|------|-------|-----------|---------|------------|--------------|
| **Sanctuary** | **Text only** — no media field exists in the protocol; links are inert text, never followed or rendered | Tor by default | Local or Full-USB | Minimal metadata; not publicly discoverable | At-risk users: journalists, lawyers, whistleblowers |
| **Standard** | Media allowed | Direct or Tor | Local | Public, discoverable, socially moderatable | Everyone else, ordinary discussion |

- "More open" means **publicly visible and moderatable — NOT unencrypted.** Crypto
  in transit is on at every rung. What changes down the ladder is metadata exposure
  and discoverability, never whether encryption exists.
- The coupling that does the work: **media ⇒ visibility ⇒ social moderation has
  something to grip.** The tier that can carry the worst content is the tier the
  community can actually see and refuse.
- The Sanctuary tier's child-safety property is *purely structural* (no media
  transport). Its residual harm profile equals any E2E messenger's, and that is
  stated honestly rather than papered over.

### Axis B — Content tier (per-post, orthogonal to posture)
Unchanged from the existing knowledge model — this is the product's thesis:

`Private → Opinion → Reference → Fact` (+ lineage / knowledge-state on Fact).

A post has *both* a posture (which rung it was made under) and a content tier.

---

## 4. Persistence & Availability

**Principle: ephemeral by default; permanence is chosen, not automatic.**
The usual platform hoards everything forever. Invert that. The vast majority of what
people share — daily life, home photos, chatter — does not need to outlive the
moment, and the masses do not need it preserved. That content is *ephemeral by
nature*, not by limitation. The small, deliberate subset *meant* to last — science,
facts, sourced references — opts into durability. **Permanence is earned by intent,
not granted by default.**

### Availability model — how "serverless" actually works
- Content is hosted **from the source**: it lives on the creator's device; viewers
  hold only an **index pointer**, not a copy.
- Most delivery is **direct**, leaning on the real-world fact that people are mostly
  online when they engage.
- For the async gap (creator offline when a follower comes online), delivery falls
  back to **thin, stateless relays** that hold an **encrypted, expiring blob they
  cannot read**, hand it on, and forget it. This is the ADR-019 / ADR-011 machinery
  reframed: not a backbone, just a buffer.
- "Serverless" therefore means **no server that can read content or be compelled** —
  not literally zero infrastructure. Relays are many, refusable, and blind. (Holds
  invariant #3.)
- Reality check still open: mobile OSes won't let a backgrounded app serve reliably,
  and home devices need NAT brokering — so the relay buffer is *required*, not
  optional, for the consumer case. See open questions.

### Persistence is a property of the content tier
| Tier | Persistence | On departure | Consent moment |
|------|-------------|--------------|----------------|
| Private / Opinion (casual social) | **Ephemeral** — presence-gated, host-from-source | Vanishes when you go offline / quit. No deletion machinery needed. | none — it was never meant to last |
| Reference / Fact (knowledge) | **Durable** — author opts in; content replicated so it survives the author | Persists as an anonymous contribution | The "permanent, cannot be fully withdrawn" warning fires *here* |

- The single gesture **"I'm making this a Fact"** is at once the knowledge claim, the
  decision to persist, and the consent to permanence. One action, three jobs.
- This dissolves the old departure problem for the ephemeral layer (vanishing is
  free) and confines it to the durable layer, where the user explicitly chose it.

---

## 5. Epistemics — what "Fact" means

**Principle: lock the record, never the verdict.**
- *"A wheel wasn't a wheel until it was a wheel."* Fact-ness is emergent and named in
  retrospect — there is no moment a claim graduates to Permanent Truth, here or in
  science.
- The **record** (the exact claim, key, sources, lineage position) is permanent and
  tamper-proof from publication — content-addressing locks it. The **verdict**
  (is it true) is permanently open. Locking a verdict would have locked in the 1998
  Wakefield paper as Fact; the most pro-science property a system can have is cheap,
  visible revision — not permanence of truth.
- The **Fact tier is a commitment level, not a truth verdict.** Posting as Fact
  accepts the obligations of a fact — cite structured sources, sign it, place it in
  the durable contestable layer, accept dispute / supersession / reversal, let your
  track record ride on it. Opinion owes none of this. The line is enforceable without
  an arbiter: you can check sources, signature, and tier; you cannot check "truth".
- **No arbiter decides truth.** The system makes the *evidence state legible* —
  independent sources, endorsements/disputes weighted by follow-graph and track
  record, retracted sources, time-stood-unrefuted — and the reader judges. A claim's
  standing is live and reversible; both disinformation and once-settled facts change.

**The history is the artifact — not the current state.**
- Every change is a new immutable record linked to its predecessor (ADR-013). The
  chain shows **what it came from** (the lineage link) and **why it changed** (the
  typed movement — Strengthened / Refined / Superseded / Reversed / Retracted /
  Contested — plus the new post's evidence).
- The valuable object is the **chain of how understanding moved**, including where it
  was wrong and why — an epistemic provenance graph, not a fact database.

**Honest limit (same family as the abuse model):** the system cannot *prevent* a
community from labelling disinformation "Fact". Defence is structural — checkable
sources, dissent attached via the Contested state, propagating retractions,
follow-graph weighting — never enforcement. The project's wager is that legible
evidence + cheap, visible revision beats confident certification over time. Make the
wager knowingly.

---

## 6. Interaction & availability (async)

**Model: a postal system with a shared ledger — not live connections.** Nobody needs
to be online at the same moment. Every social action — follow, post, reply, endorse,
dispute — is a *signed, addressed object* that propagates and merges (CRDT, ADR-003).
You act now; it reaches the other party and merges on their next sync. Prior art:
Secure Scuttlebutt, Nostr. The existing read-cursor and feed design (ADR-004,
ADR-024) already assumes this catch-up model — async is baked in, not bolted on.

**Principle: each device stores mostly its owner's own data.** Foreign content is
transient, minimized, and weakly held. This extends invariant #1 — minimal personal
data of *others*, too. Concrete payoff: a seized device exposes mostly *you*, not a
cache of everyone you follow (the opposite of full-replication designs like SSB).
Tradeoff: less caching = less available when people are offline — negotiated by the
relationship tiers below.

**Visibility is per-post, scoped by audience.** The poster picks who each post is for:
- **Open** — anyone can see it. **Indexing is triggered by *interaction*, not by
  viewing.** Looking leaves no trace and creates no follow-up; the moment you *act* on
  an open post — like, dislike, fact-check, reply, or privately bookmark — your client
  indexes that post/thread so future updates flow back to you. Following a *person*
  indexes their whole open stream; interacting with a *single* post indexes just that
  thread, without following the author. Standard posture only — Sanctuary content isn't
  discoverable.
  - *Public* interactions (like, fact-check, reply) also emit a signed event (ADR-006).
    *Private* ones (bookmark / save to a collection, ADR-014) index for you alone and
    tell no one. Either one creates the follow-up thread — so re-finding something never
    forces a public reaction.
  - **Anti-doomscroll by construction:** your feed is composed only of *your choices* —
    people you follow, posts you touched, circles you're in — never an algorithm's
    choices or your own passive history. Nothing grows from lurking; nothing is
    optimised to pull you back (invariant #2). And looking is private: lurking leaves no
    record anywhere — not on your device, not as an edge to the author.
- **A circle** — Friend, Family, or a custom group — visible *only* to members.
- **Private** — self only; never leaves the device.

**Enforcement is cryptographic, not a UI gate.** With no server to refuse access,
"only family can see this" must mean "only family can *decrypt* this." A circle-scoped
post is encrypted to its members' keys; non-members can't read the bytes even if they
obtain them. **Visibility = decryptability.** Open posts are signed but not secret.
This reuses the messaging key machinery (ADR-011) and composes with the relay buffer,
which already holds encrypted blobs it can't read.

**This contains the screenshot/save limit to the chosen audience** — a real gain. Only
those who can *decrypt* a post can see it to save it; a Family post can be screenshotted
only *by family*, because no one else can read it. The unstoppable-save reality is now
bounded to the circle the poster picked, not the whole network.

**Circle = the single axis for audience *and* retention.** Closeness sets both who sees
and who keeps — collapsing passerby/follow/friend and open/friend/family into one
ladder of intimacy:

| Circle | Sees | Indexes | Leased copy |
|--------|------|---------|-------------|
| **Private** (self) | only you | — | n/a |
| **Family / Friend / custom** | members only (encrypted) | members | yes — owner-timed lease |
| **Open / Public** | anyone | followers | no (passersby see transiently) |

On a circle source's departure: dead index = signal to purge the leased copy, *unless*
a member deliberately saved their own.

**Circles require a mutual connection; labels stay private.** You can't unilaterally
add someone and push private content at them — the **connection** is a two-way accepted
handshake (the consent gate). And you can't *surveil* anyone either: you only ever see
what they encrypted to you, so categorizing someone gives you zero access to their
content — the scary direction is closed by construction. What stays asymmetric and
private is each side's **labels**: I may file you under "family" while you file me under
"friend"; my label never leaves my device. One-way following remains fine for **open**
posts (public needs no consent).

**Still not free — group keys.** A post encrypted to an N-member circle means managing
N keys and **re-keying when a member is removed** (an ex, a fallout), plus deciding
whether members may see *who else* is in the circle (recipient-set metadata). Same hard
problem as secure group messaging; design it now, not later.

**Receive-side consent on the direct (point-to-point) path — block / mute / delete.**
Circles above solve consent for *audience* (who a post is encrypted to); this is the
companion piece for consent on *receipt* — what happens to mail from a key you've
pinned, once it's landing in your own mailbox. Recorded here, ahead of code, as the
near-term basis for **Slice 04** (the direct level only — the room level below is
later, but its governing principle is stated now so that slice inherits it instead of
improvising one).

- *Delete a peer (forget the name).* The peer is removed from your local table.
  Trust classification is never stamped onto a message at receive time — it is always
  recomputed from the *current* table at display time. So deleting unwinds in one
  stroke: every message from that key, old and new, reclassifies to `unknown`,
  because there is no before/after-delete distinction anywhere in storage. The
  history itself is never erased — nothing is deleted from the device, only
  reclassified. Re-adding the same card later matches by key, not by when it arrived,
  so the newly chosen label repaints *every* message from that key at once, past and
  future. **This recompute-always property is to be preserved, not redesigned.**
- *Block (refuse the content).* While active, anything arriving from that key on the
  direct path is discarded at receipt — pulled from your own routing-key mailbox,
  identified as a blocked author, dropped unstored. Nothing is kept, so nothing can
  resurface later. This is invariant #5's "enforced by people" in its most literal
  form: a block is a person refusing, not the system inspecting content to decide.
- *Mute.* Received and kept, exactly as an unblocked peer's mail would be, but
  display-suppressed. The distinction from block is the whole point: muted content
  still exists on your device; blocked content never arrives at all.
- **Default coupling, separable underneath.** Deleting a peer, by default, also
  blocks them — "I removed them, they shouldn't keep reaching me" is the behavior
  users expect from one action. But the two stay separable in the engine: *block
  without delete* (keep recognizing them, keep their history, just stop new mail
  landing) and *delete without block* (tidy the name off your list, indifferent to
  whether they write again) are both legitimate single-sided cases that must remain
  expressible. Couple the two at the UI's default action; never weld them together
  underneath.

**The level-split principle — one key, different consent per layer, by architecture,
not by rule.** A direct message is sealed to you specifically and pushed to your own
routing-key mailbox; you alone pull that slot — block/mute/delete act only here. A
room message, once rooms exist, arrives because you chose to pull a room's shared log
off a board — a different address, a different act, with no mailbox involved at all.
A key you have blocked or deleted on the direct path therefore stays fully visible in
a room you both happen to read, rendered `unknown` (or under its self-signed nickname,
if it carries one) — because the room-pull path never consults your direct-path
labels or block-list at all. This is not a gap to be closed later: the DM block lives
entirely on the mailbox path and never touches the room-pull path, so it cannot reach
into rooms even in principle. State the principle now so the rooms slice
inherits a stated split rather than discovering — or worse, "fixing" — it under
deadline. Room-level mute is deferred to that slice; even there it can only ever be a
*display* mute in your own view: you cannot drop-at-receipt a shared log you pulled
wholesale, and you cannot remove a participant from a room for anyone but yourself —
that is moderation of a shared space, which is per-board policy, never a single
reader's call.

**Honesty edges (invariant #6 — say this plainly, do not gloss it):**
- *Block is local and cooperative on the sender's side only.* Deleting or blocking a
  peer never reaches their device — they keep your card and keep sealing-and-pushing
  exactly as before, unaware anything changed. The blind relay structurally cannot
  filter by sender (it does not know who sent what); the same blindness that protects
  everyone now cuts the other way. Block stops *your client from keeping* what
  arrives — it does not stop them sending, and it does not stop the relay from
  holding their blob in your mailbox slot. A user who reads "block" as "they can no
  longer reach me" has a false model of what just happened; the UI must say so, not
  let the word imply more than the mechanism delivers.
- *The straggler.* "Nothing from the blocked/deleted period exists" is true only
  because block discards at receipt *while active*. The one gap: a message that
  reached the relay during the block, but is pulled for the first time only *after*
  you unblock or re-add, is treated as an ordinary current message — nothing marks it
  as belonging to the past window, and a sender-claimed timestamp is not trustworthy
  enough to gate on. This is narrow — it only fires if the re-add lands between their
  send and your next sync — and it is named here, not solved here.

**Open scoping question (recorded, not resolved here).** The mutual-connection
handshake that circles already use is the eventual completion of this consent
surface — real two-way awareness, beyond one-sided block/mute/delete. Whether that
handshake belongs inside Slice 04 or is its own later slice is an open fork; decide it
at slice-planning time.

**Two kinds of retention, cleanly split:**
- *Automatic* — the leased friend-copy and the relay buffer — runs on the **owner's**
  clock (first-owner authority). The owner decides the time.
- *Deliberate* — an explicit local save / export — is available to **anyone who can
  see the content at all**, passerby included, not just followers or friends. Seeing
  is enough; you don't have to index something to save it, exactly like a screenshot.
  Once made, that copy is *theirs* — outside any lease, beyond the owner's reach,
  universal and unstoppable by design.

The owner governs the automatic lifecycle; never what a viewer chooses to keep. This
is why the permanent-post / before-you-share understanding matters: you control when
your *automatic* traces expire, not what others deliberately save.

**The hold is deliberately weak — best-effort, never enforced.** Same class of limit
as "delete for both is a request" (ADR-011): you cannot force a purge on a device you
do not control without a backdoor, which the invariants forbid. Therefore:
- Removal reaches *honest, online* clients only. A modified client, an offline
  device, or one that never returns keeps its copy. Purge is eventual and best-effort.
- Screenshots and explicit saves cannot be prevented — and aren't, by design. What is
  minimized is *incidental, automatic* retention, not deliberate copying.
- The honesty is the feature: the system promises minimization, never erasure.

**Detecting a friended source's departure — graduated and configurable.**
- **Signed "I'm leaving" tombstone → immediate hard purge** of friend-copies. The
  clean goodbye; the user chose to go now.
- **Absence ladder (the safety net)** for departures with no goodbye — coerced, dead,
  key lost, or simply drifted away. The friend's device escalates by how long the
  source's index has been unreachable. Long, user-adjustable defaults:
  - ~6 months unreachable → **a heads-up to the friend** (last chance to save, below).
  - ~1 year, or no answer to the prompt → **purge by default**.
- **The 6-month mark is a heads-up, not a negotiation.** "This person's been gone a
  while; their content purges at ~12 months per *their* settings — save anything you
  want to keep now." A deliberate save promotes the copy to the friend's own data —
  outside the lease, same status as a screenshot, not reclaimable by the source. That
  deliberate copy is the *one* thing first-owner authority can't reach, because the
  limit is physical, not chosen.
- **The window belongs to the original owner.** The *source* sets it ("purge my
  friend-copies if I'm gone X"); the recipient gets no retention timer. First owner,
  first authority — deliberately, even where it feels harsh. This governs the
  *automatic leased copy* only (the deliberate-save limit above still holds), and it
  applies to the ephemeral/friend-copy layer only — not durable Facts, whose author
  already consented to permanence.
- Long windows double as **noise tolerance** — a downed relay or flaky Tor link
  rarely lasts months, so short timeouts would mis-fire; long ones don't.
- The absence net is also the ultimate backstop when an emergency wipe (ADR-010)
  couldn't broadcast its signal: eventually the silence itself does the work.
- The 6-month prompt must stay a **rare, quiet, dismissible** check — once per
  long-absent friend, for the user's own data hygiene — never a notification stream
  (invariant #2).

---

## 7. Discovery & onboarding (async)

**Discovery splits by layer — like everything else.**
- **Durable knowledge (Reference/Fact)** *is* findable when you weren't there: it
  persists, is content-addressed, hosted by willing peers, and indexed by topic via the
  DHT (ADR-015). The durable layer is precisely "what's there when you weren't."
- **Ephemeral/social content** is found *live* (what's active in a topic now) or through
  your circles — never a searchable archive. You can't dredge up everyone's vanished
  daily posts; the hard-to-discover thing is the thing meant to disappear. Feature, not gap.

**Topics (#) are the primitive — already specified (ADR-015):** content-addressed,
normalised TopicId, used in DHT queries. Two levels:
- A small set of broad **areas** shipped in the binary (Science, Health, Tech, Arts…) as
  a *default map* for newcomers and a DHT anchor — **seeded, not gatekept.** The protocol
  doesn't enforce them; anyone can extend or ignore them. Same spirit as hardcoded
  bootstrap keys: a default, not an authority.
- Freely **emergent #topics** beneath and around them — no one approves a tag.

**Onboarding is topic-first and durable-first — never the live feed.** A newcomer with no
graph picks areas/topics → browses the *durable knowledge* there (persistent, well-sourced
Facts/References) → finds people and threads → follows, interacts, builds a graph. The
settled-knowledge layer is the entry surface; the live social layer is what you graduate
into. A better, calmer first run than a firehose of strangers — and on-brand.

**Ranking inside a topic = epistemic standing, not engagement.** With no attention engine
(invariant #2), order comes from signals you already have — corroborating sources,
follow-graph-weighted endorsements, knowledge state. The epistemics engine (§5) *is* the
discovery ranker. The truth model is the ranking model.

**Two channels, not one anxious flow: "My circles" vs "The world."** Connection and
information are different modes of attention; mixing them (a friend's dinner next to a
war headline) is part of what makes mainstream feeds anxious. Split them:
- **My circles** — your people: circle + followed content, mostly ephemeral, ordered by
  recency. *Connection.*
- **The world** — open content organised by area/#topic, ordered by *epistemic standing*
  (§5), not engagement. *Information.*
Either can be foregrounded or backgrounded; the user picks the default (no algorithm
composes it). The world channel is **pull, not push** and **bounded** (catch up to your
cursor, then it ends — ADR-024), so news never ambushes you and never becomes infinite
scroll.

**News ≠ Facts — the tier label is what keeps them apart.** "What's being written about"
(politics, sports, breaking events) is fast, contested, opinion-heavy — the *opposite* of
the settled durable layer. A world feed therefore surfaces much Opinion and unverified
claims, which is fine *only if every item visibly wears its tier*, so a trending claim
reads as a claim, not a fact. Flattening "news" into apparent truth would rebuild the
exact disinformation engine this project exists to replace. The tier system is the
safeguard; the world feed must show it, loudly.

**The honest hard part — the open frontier.** Discovery and durable-layer *hosting* are
the **same problem**: you can only find durable content that someone hosts and that's
findable. And both are **weakest exactly when the network is smallest** — early Phase 1
has little durable content, few peers, no real DHT, so a newcomer's topic-browse is thin
to empty. This is the network's cold-start problem; no rule resolves it, because it's
about whether enough peers exist to host, serve, and index. A prototype must probe it.

---

## 8. Ease of use, recovery & the social wedge

**Ease of use is the top priority — *within* the invariants, not above them.** The whole
reason this exists is the privacy architecture; if ease came first at any cost, the answer
would be "use WhatsApp." So the goal is *the easiest product that doesn't break the
invariants* — ease ranks just under the non-negotiables, and where they conflict (often),
the invariant wins and the UX absorbs the cost as gracefully as it can.

**The social layer has no cold-start problem — it's the wedge.** A family of five is
useful at five users: they post to each other, needing no populated topics, no discovery,
no network effect. The long stretch before the knowledge commons fills is carried by the
*social* use case — easy, private, ad-free family/circle sharing, valuable from day one.
The facts/science commons grows *on top* as more families join. This is the sequencing
answer to the scope question: **social wedge first, knowledge network emerges.** It also
means the discovery frontier (§7) gates the eventual payoff, not adoption.

**The hardest usability problem is identity recovery — and the family is the answer.**
Keyfile identity with no central recovery is the #1 thing that kills privacy products:
nontechnical users lose keys, and a 24-word paper code is not a real safety net. Levers,
best fit first:
- **Social / family recovery** (Shamir secret sharing among trusted contacts): e.g.
  3-of-5 family members together reconstruct a lost key. The circle a user is *already in*
  doubles as their recovery network — no central server, perfect fit for the wedge. The
  single highest-value usability investment.
- **Pre-provisioned hardware** (the USB idea): keyfile + recovery code set up in advance.
- **One technical helper per household** sets up and holds backups — every family has one.
- **All crypto invisible**: one passphrase, everything else automatic (ADR-020). The
  concepts (argon2id, SQLCipher, relays, group keys, Tor) never surface.

**Not a backup drive — which lowers the stakes of key loss.** This is not where your
canonical photos or files live; your phone and your own backups are. Two secrets do two
jobs: the **passphrase** decrypts your local data (have device + passphrase → content is
fine; encrypting your own drive never *loses* it), and the **identity key** proves who you
are to the network. Losing the identity key costs *identity continuity* — your verified
persona and your link to your followers — **not your content**, which is on your disk (and
elsewhere). So social recovery rescues *who you are to the network*, not data. The only
real loss modes are forgetting the passphrase or losing the device outright — and the
latter is exactly what "not a backup drive" defangs.

**Security — and its setup burden — is a ladder, defaulted low.** Don't make one setup
serve both audiences. Casual users start easy; the hardened apparatus (Tor, self-custody,
hardened storage) is only for those who escalate. Two linked rules make it work:
- **Recovery convenience *is* part of the tier.** Easy tier → convenient recovery
  (social/family recovery on by default, or a convenient encrypted key backup) —
  acceptable because the family's adversary is "ads and data harvesting," not a state.
  High tier → self-custody, *no* convenient recovery, because any convenience is an attack
  surface a state could subpoena, coerce, or compromise. **Ease goes to who needs ease;
  burden to who needs security.** This is the resolution of the ease-vs-privacy tension.
- **Escalation is forward-only; serious threat models start fresh.** Bumping the app's
  posture protects *future* activity, not the metadata already emitted in easy mode. So
  "upgrade as you go" is fine for a family wanting a bit more privacy — but a journalist
  must NOT graduate a casual identity into a high-security one (its history is exposed);
  they start a *new, compartmentalised* identity at the right level (ADR-005). Upgrade the
  setting, not the identity. The at-risk are typically motivated/technical enough for it.

**The floor:** even the easy tier keeps the invariants — no ads, no data harvesting, no
central content store, encrypted in transit. "Low security" = less hardening / more
convenience, never "we became Facebook." The privacy floor sits well above mainstream social.

**The honest ceiling:** no-central-recovery at the high tier will never be as forgiving as
"click to reset your password." The achievable target there is *self-custody a motivated
person can manage* — and at the easy tier, *easy enough for a family with social recovery* —
not *as easy as Instagram* for the hardened case.

---

## 9. Client architecture (the UI question)

**Two layers, cleanly separated.** The **engine** — the Rust core (identity, crypto, P2P,
storage, sync) — is the security-critical, reproducible-build part (invariant #4). The
**UI** is just the view onto it. They talk locally. The spec already has the engine
modules; the UI is the unbuilt layer.

**Web tech yes; a browser pointed at localhost no.** Web *technology* for the UI is fine,
but "open your browser to localhost" fails both priorities — a nontechnical family can't do
it, and a browser's attack surface (extensions, telemetry) undercuts the hardening. Use web
tech *inside a native app shell* — **Tauri** fits best (Rust-native, controlled system
webview not a full browser, real installable app, reproducibly buildable = verifiable
client). Electron does the same job, heavier. Either way: a real app, no localhost address.

**Platform sequencing — prototype on desktop, ship on mobile.** The wedge audience is
mobile families, but mobile is the *hardest* platform here (OS kills background, can't
serve, app-store compulsion point). Desktop is the *easiest* to build and iterate (always-on
daemon, can serve, Tauri+Rust). So: prototype on desktop to test the engine and the
discovery frontier cheaply; build the mobile product for the actual audience once the core
is proven. Honest gap: desktop-prototype ≠ mobile-product — mobile is a different, harder
beast (all the P2P-on-mobile constraints), not a quick port.

**This is the threshold.** "Where does the UI start" has no better answer on paper than in
a prototype. Choosing the client shell and standing up a minimal window onto the engine *is*
the first act of building — the point where planning stops helping and code takes over.

---

## 10. Open questions (known unresolved forks — do NOT pretend these are decided)

- **Correction propagation — mostly answered (§6):** corrections ride the *interaction
  graph*. Anyone who acted on a claim (endorsed, disputed, fact-checked, replied,
  bookmarked) thereby indexed it, so a KnowledgeState update flows back to exactly the
  people who engaged — the ones who matter most. **Remaining seam:** a passive viewer
  who only *looked* left no trace and can't be reached — defensible (they didn't act on
  it, and reaching them would need the view-tracking the project refuses), but it means
  silent readers of a later-reversed Fact won't hear of the reversal.
- **Ease vs privacy — approach chosen (§8), validate with users:** resolved in
  principle by tiered security (recovery convenience scales with the tier), the
  not-a-backup stance (lowers key-loss stakes), forward-only escalation, and fresh
  identities for high threat models. Remaining: this is unproven with *real*
  nontechnical users — social recovery and the easy-tier flow need a prototype and
  actual families to confirm they clear the bar.
- **Scope — focused commons or everything-platform? (NEW, decide consciously):** "a
  calm place where facts and science matter" and "the world's real-time news feed for
  politics, sports, every portion of it" are very different sizes. The latter wants reach
  and speed, which fight the calm / async / no-amplification design and lean hard on the
  unsolved cold-start frontier. A real-time world feed is mostly the ephemeral-open layer,
  so it's a large-network feature — sparse to empty early, and gated by the frontier
  above. Pick which this is; it changes everything downstream.
- **Durable-layer hosting = discovery (THE open frontier, §7):** content-addressing
  answers *how* a replica is verified, but *who* hosts (followers? opt-in "knowledge
  keepers"? any interested peer?), how growth is bounded, and how a newcomer finds
  anything when the network is small — these are one unsolved problem, weakest exactly
  when the network is smallest. The thing a prototype must answer; no rule resolves it.
- **Departure detection — resolved (mechanism in §6):** signed tombstone = immediate
  purge; absence ladder (≈6mo heads-up → ≈1yr purge) as the safety net; the window is
  set by the original owner (first-owner authority, source only); the heads-up is the
  friend's last chance to deliberately save — the one copy the source can't govern,
  since that limit is physical.
- **Departure model — mostly resolved:** presence-gating makes the ephemeral layer
  vanish for free; friend-copies self-purge via the weak lease (§6). Durable layer:
  content persists anonymously by prior consent. Remaining sub-question: persona-level
  vs key-level unlinkability, scoped to durable contributions only.
- **Business model — resolved:** this is a gift / public-interest project, not a
  business. Sustainability via grants, donations, and at-cost hardware; rewrite the
  LICENSE to *invite* contributors and operators rather than fence them off.
- **Discovery mechanism — structured (§7), core still open:** topics (ADR-015) +
  seeded-not-gatekept areas + epistemic ranking give the *shape*; the unsolved core is
  the hosting/cold-start frontier above. DHT + content-addressing (a Merkle DAG, **not**
  a blockchain — no global consensus, no double-spend). Keep the ephemeral/private layer
  out of the index entirely.
- **Circle group keys (NEW):** circle semantics resolved — mutual connection + private
  asymmetric labels, one-way follow for open posts (§6). Audience enforced by encrypting
  to members' keys. Open: group-key management / re-keying on member removal, and whether
  circle membership (the recipient set) should be hidden from members — same class as
  secure group messaging (ADR-011).
- **Mode reconciliation:** retire/merge the redundant ADR axes into the ladder above.
- **Lineage vs unlinkability:** how coherent a durable body of work stays vs how
  cleanly a person can vanish. These fight; pick the balance deliberately.
  **Open-layer hosting** boards vs source (refines the frontier): because open content 
  is public and signed, a federated-board model (many refusable aggregators you post to and 
  read from, à la Nostr relays / Mastodon instances) is on-thesis and scales reading far 
  better than pure source-hosting + DHT, at the cost of partial chokepoints. Keep boards 
  many and refusable. Decide source-hosting vs federated-boards consciously when the open 
  layer is built.
