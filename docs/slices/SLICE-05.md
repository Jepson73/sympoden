# Slice 05 — Self-signed peer cards (bind X25519 to Ed25519)

A card-signing hardening slice, named and deliberately deferred by `docs/slices/
SLICE-03.md`'s Adjustment 1 (D2): "the genuine fix for card tampering — binding the
X25519 key to the Ed25519 key by signature, so substitution fails at import, first-pin
included — is self-signing the card, which is its own hardening slice... not this one."
This is that slice.

**The hole this closes.** Today a peer card carries an Ed25519 identity key and an
X25519 encryption key with nothing binding the two together. A card is handed between
people out-of-band (forwarded, copy-pasted, relayed through a third channel) — anyone
on that path can swap the X25519 half and become a silent decrypting middle for every
sealed note addressed to that "peer." Note-signature verification still passes,
because the Ed25519 key is untouched; only the encryption key was substituted, and
nothing today checks that it belongs with the signing key at all.

This slice makes a card a *self-verifiable claim*: the card's own Ed25519 key signs
its paired X25519 key, so anyone holding the card — independent of who handed it
over — can confirm the two keys were issued together, not assembled from parts along
the way.

This slice does **not** touch the envelope format, the relay, the wire protocol, key
rotation, or any crypto primitive beyond composing the existing Ed25519 sign/verify
over new bytes.

## The current card format, as found in the code

Reported before proposing anything, so the spec below is written against the real
surface, not a guess:

- **The type**, `sympoden-engine/src/identity.rs:100`:
  ```rust
  pub struct PublicCard {
      pub ed25519_public: String, // base64
      pub x25519_public: String,  // base64
  }
  ```
  No version field. No signature. Nothing binds the two fields to each other.

- **Emission.** `Identity::public_card()` (identity.rs:308) is a bare struct literal —
  base64 of each raw 32-byte key, no signing. The CLI's `cmd_whoami`
  (`sympoden-cli/src/main.rs:208`) does `BASE64.encode(serde_json::to_vec(&card))`
  server-side and prints the result — the pasteable "card text" is `base64(JSON)`. The
  app's `whoami` Tauri command (`sympoden-app/src/main.rs:443`) instead returns the
  **bare JSON string** (no base64 wrapping in Rust at all); `ui/main.js`'s `enterApp()`
  does `myCardEl.value = btoa(card)` — the base64 layer happens client-side, in JS, for
  the app, but server-side, in Rust, for the CLI. Both surfaces end up producing the
  same artifact (`base64(JSON)`), by different code paths — an asymmetry that matters
  once card generation gains a signing step (see D-E(2) below).

- **Parsing/pinning.** The CLI's `cmd_add_peer` (main.rs:251) does
  `BASE64.decode(card.trim())` then `serde_json::from_slice` into `PublicCard`, then
  calls `parsed.ed25519_verifying_key()` / `parsed.x25519_public_key()`
  (identity.rs:331-349) to confirm the two fields decode into real curve points — the
  only validation that exists today. The app's `add_peer_card` (main.rs:204) does
  **not** base64-decode at all; it calls `serde_json::from_str(card)` directly, because
  `ui/main.js`'s `doAddPeer()` already ran `atob()` client-side before invoking. Same
  end state, opposite side of the Rust/JS boundary doing the decode.

- **No binding, confirmed live.** `PublicCard::from_pinned_peer` (identity.rs:320)
  reconstructs a card from a stored `PinnedPeer` row purely by hex-decoding whatever is
  in the `peers` table — no re-derivation, no check. And `Store::add_peer`
  (`sympoden-engine/src/store.rs:198`) never compares an incoming `x25519_pubkey`
  against an already-pinned peer's stored one when the `ed25519_pubkey` matches — this
  is SLICE-03.md Adjustment 1's cut, confirmed still exactly in place: re-adding an
  existing key under any card, tampered X25519 or not, is `AlreadyPinned` or
  `AlreadyPinnedUnderLabel`, full stop, no comparison ever happens.

- **A structural fork this slice must resolve** (see D-E(1)): `PublicCard` is doing
  double duty today. `sync.rs`'s `prepare_outgoing` (sync.rs:20) takes `peer:
  &PublicCard` and calls only `.x25519_public_key()` / `.ed25519_verifying_key()` on
  it, fed by `PublicCard::from_pinned_peer` — a purely internal reconstruction of
  *"this pinned peer's two keys"* from already-trusted local data, used only to seal
  an outgoing envelope. It is never transmitted, never re-verified, and — critically —
  **cannot** carry a valid signature: signing a peer's card would require *their*
  private Ed25519 key, which this device never has and must never have. If
  `PublicCard` itself grows a required `signature` field, `from_pinned_peer` has no way
  to fill it honestly. The wire artifact (self-signed, received from a peer,
  verified) and this internal reconstruction (already-trusted, local-only, structurally
  unsignable by us) are two different things wearing one name. See D-A/D-E(1) for the
  resolution.

## The property this slice adds

> A card's X25519 key cannot be substituted, in transit or at rest before pinning,
> without detection by anyone holding the card. The card's own Ed25519 key signs a
> domain-separated claim over its paired X25519 key; `add peer` verifies that claim
> before anything is written, and a card whose signature does not verify — because a
> key was swapped, corrupted, or the signature itself was tampered with — is rejected,
> never partially stored, never silently accepted.

> A card from before this slice (no signature field) is rejected with a plain,
> friendly message pointing at getting a fresh card — never silently accepted, never
> patched through a compatibility path. Existing pins from before this slice are
> unaffected: nothing about an already-pinned peer is re-verified or re-checked at
> rest.

> A validly-signed card for an already-pinned Ed25519 key that carries a *different*
> X25519 key than the one on file is rejected loudly — naming the peer once (its one
> shared Ed25519 fingerprint) and both the stored and offered X25519 fingerprints — this
> is SLICE-03.md Adjustment 1's cut, resurrected in its proper home now that "different
> X25519, same Ed25519" is no longer ambiguous (either the signature fails — forgery —
> or it validly claims a new key — real rotation, not supported yet, so still refused).

## Design decisions

### D-A — card format v2: two types, not one field-set bolted onto the old struct

**The old `PublicCard` type stays exactly as it is today** — same two fields, same
methods, zero diff to its own definition — because it is not the wire card anymore, it
is (and, looking at `sync.rs`, always really was) just "a peer's two keys,
reconstructed from a pinned row for sealing purposes." `sync.rs` imports it by name and
calls two methods on it; touching its name or shape would touch `sync.rs`'s text,
which the hard constraints hold at zero diff. Leaving it alone is the cheapest way to
guarantee that.

**A new type, `SignedCard`, is the wire artifact** — the only thing that travels
out-of-band as "a card" from this slice on:

```rust
const CARD_DOMAIN_TAG: &[u8] = b"sympoden-card-v2\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCard {
    pub version: u8,             // = 2, always. Absent or any other value is rejected.
    pub ed25519_public: String,  // base64 — same encoding PublicCard already uses
    pub x25519_public: String,   // base64
    pub signature: String,       // base64, ed25519 signature over canonical_bytes below
}
```

Signed bytes — follows `content.rs`'s `Note::canonical_bytes` *style* (domain tag,
then fields, concatenated with no length-prefix needed because every field here is
fixed-length), but is not identical to it: **the signed bytes cover `domain_tag ‖
version ‖ ed25519_public ‖ x25519_public` — all four, including the version byte.**
This is the crux of the format and is non-negotiable:

```rust
fn canonical_bytes(
    version: u8,
    ed25519_public: &VerifyingKey,
    x25519_public: &X25519PublicKey,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CARD_DOMAIN_TAG.len() + 1 + 32 + 32);
    bytes.extend_from_slice(CARD_DOMAIN_TAG);
    bytes.push(version);
    bytes.extend_from_slice(ed25519_public.as_bytes());
    bytes.extend_from_slice(x25519_public.as_bytes());
    bytes
}
```

No length-prefixing needed: the domain tag is constant, `version` is a single fixed
byte, and both keys are fixed 32-byte arrays, so concatenation is unambiguous (unlike a
variable-length field, which is why `content.rs`'s `body` — the one variable-length
field in `Note` — has to go last; here there's nothing variable-length to be ambiguous
with). `signature = crypto::sign(signing_key, &canonical_bytes(version, ed25519_public,
x25519_public))` — the identity's own Ed25519 key signs a claim that binds *its own
version tag and both public keys* together, using `crypto::sign`/`crypto::verify`
unchanged, no new primitive.

**Why the version goes under the signature, not just in the domain tag name (unlike
`content.rs`'s `-v1` note tag, which encodes its version only in the constant string):**
a card format is handed out-of-band and re-encoded by intermediate steps in a way a
locally-produced note never is, so the version needs to be a real field an attacker
could try to edit — and putting it under the signature is what makes editing it
detectable. If `version` were only implicit in which domain tag was used to verify (as
`content.rs` does), a future v3 card's `(ed25519, x25519)` pair, still validly signed
under a v3 tag, could have its `version` field rewritten from 3 to 2 by an intermediary
without touching the signature at all — the field would then claim v2 while having been
verified against nothing, or worse, get fed to a v2 verifier that never learns it was
truncated from a richer v3 claim. Signing the version byte closes that: any edit to
`version` — up or down — invalidates the signature, full stop. **The Ed25519 key is
under the signature too**, not left to "well, it signed with itself, that's implicit" —
so the signature covers everything an on-path attacker could touch (domain, version,
identity key, encryption key), with no field left for a "but it wasn't technically
signed" argument.

`CARD_DOMAIN_TAG` is distinct from `content.rs`'s `b"sympoden-note-v1\0"` and
`identity.rs`'s existing `FINGERPRINT_DOMAIN_TAG` (`b"sympoden-fingerprint-v1\0"`), so a
card signature can never be replayed as a note signature or vice versa. The `-v2` in
the tag names the *card format generation* this slice introduces — there never was a
`-v1` card tag, because the old shape was never signed at all; "v1" only exists in
prose (the old unsigned shape), never encoded anywhere. The struct's own `version:
u8 = 2` field is the explicit, forward-compatible discriminator a future v3 would bump
— checked first, before anything else is trusted, so a v3 card (whenever/if it exists)
fails with a precise "unsupported version" rather than a confusing signature error.

**Emission:** `Identity::card_encoded(&self) -> String` builds a `SignedCard`, signs
it, and returns the ready-to-paste base64 string directly — both `cmd_whoami` and the
app's `whoami` command call this one function and hand the result straight to the user
(print / return), no per-surface encoding logic left anywhere (closes D-E(2)). The old
`Identity::public_card()` method becomes dead once both callers move to
`card_encoded()`, and is removed — the `PublicCard` *type* it returned stays, still
used by `from_pinned_peer`.

**Parsing/verification:** one function, detailed under D-D.

**Recommendation: adopt this two-type split.** The alternative — add `version`/
`signature` to `PublicCard` directly — looks smaller but is a dead end the moment
`from_pinned_peer` tries to construct one: it cannot sign for a key it doesn't hold the
private half of. Splitting the types is not extra layering for its own sake; it's the
only shape that lets "the thing a peer sends me" (must be signed, must be verified) and
"my own reconstruction of a pinned peer's keys" (can never be signed by me, doesn't
need to be) coexist without one of them lying about having a signature it can't have.

### D-B — legacy unsigned cards: hard cut, confirmed

Confirmed against the real code (see "current card format" above): no compatibility
shim exists today, `Store` never re-verifies a pinned peer's keys against anything at
rest, and every environment this project runs in starts from a fresh data dir per test.
A compatibility path for unsigned cards would be a forgery-acceptance path with a
maintenance tail (an eventual "and now remove the shim" slice) for a threat this whole
slice exists to close. **Hard cut, as proposed.**

Old-format and garbage input get two *different* messages, not one generic reject —
worth distinguishing because they mean different things to the person reading the
error:
- Valid JSON, no `version` field at all (today's exact shape, or an old build's
  output): `CardError::LegacyUnsigned` → "this card is from an older version of
  sympoden — ask for a fresh one." This is the common, unremarkable case (a peer on an
  old build), and should read as routine, not alarming.
- Not valid base64, or not valid JSON at all: `CardError::NotBase64`/`CardError::
  NotJson` → a plain "that doesn't look like a card" message. Not routine; more likely
  a copy-paste mistake than a peer on an old build, but still not a security alarm on
  its own.
- A `version` field present but wrong, or a signature that fails to verify: see D-D —
  these get their own, more pointed messages, because unlike the two above they *are*
  worth a beat of suspicion (a version mismatch could be a future build; a signature
  failure could be exactly the tampering this slice exists to catch).

**Already-pinned peers from the unsigned era: nothing changes at rest.** The `peers`
table has never stored a signature (there was nothing to store) and gains no new
column this slice — nothing is re-verified for an existing pin, nothing re-prompts,
nothing breaks. Verification is a gate on *new* pins only, at the moment a card is
parsed, never a check run against rows already sitting in the table.

**Confirmed: three distinguishable failure categories, never collapsed into each
other**, matching the approval's framing exactly —
1. *legacy-unsigned* (`CardError::LegacyUnsigned`) — friendly, routine: an older
   version, get a fresh card.
2. *malformed* (`CardError::NotBase64`/`NotJson`/`Malformed`/`UnsupportedVersion`/
   `MalformedKey`/`MalformedSignature`) — a structural/parse problem, plainly worded,
   more likely a copy-paste slip or a future build than an attack.
3. *signature-invalid* (`CardError::SignatureInvalid`) — the serious one: the card's
   binding check failed; do not pin it; get a card directly from the peer.

(1) has more than one enum variant behind it above only in the sense that "malformed"
covers several distinct structural failure *shapes* — they are never worded or treated
as (1) or (3). The one property that must hold, restated from D-D: **(3) is only ever
reached by a card that passed every structural check**, so a tampered card can never be
misreported as merely an old one, and an old card can never be alarmed over as if it
were tampered.

**Recommendation: adopt as specified.**

### D-C — a validly-signed card for a pinned key with a *different* X25519 key

The resurrected SLICE-03.md Adjustment 1 cut. With signatures in place this case is no
longer ambiguous: it is either a forged card (signature fails — ordinary reject, no
special handling needed, covered by D-D) or a **validly** signed card whose X25519 key
genuinely differs from what's on file for that Ed25519 key — meaning the key's real
owner issued a new encryption key (rotation) or, less charitably, someone captured the
Ed25519 private key and is presenting a fresh pair signed with it. Either way, this
prototype has no rotation story, no re-sealing of pending sends, no notification path —
supporting it for real is its own slice (NON-GOALS).

**Recommendation: loud reject, naming the peer and both X25519 fingerprints (exact
format below), rotation deferred — as I lean, and as SLICE-03.md already committed to
when it cut this check ("its own hardening slice", not "solve it a different way").**
The alternative (update-the-pin)
drags in exactly the consequences SLICE-03.md's Adjustment 1 flagged and declined to
solve inline: pending `note_sends` rows already sealed to the old X25519 key would need
resealing or explicit invalidation, and there's no design for that here. Loud reject
keeps this slice's surface area to "verify and refuse," nothing more.

**Where this check lives — revised: a pure engine function, not a call-site guard.**
Unlike SLICE-04.md's self-add check (one equality: "is this Ed25519 key mine?"), this
check has to fetch a pin, compare a specific field, and build a message with two
distinct fingerprint displays — that's enough moving parts for two independent
implementations (CLI, app) to drift on wording, field choice, or ordering. So this
follows the `resolve_peer_query` precedent, not the self-add-guard one: a pure function
in `identity.rs`, next to `SignedCard`/`parse_and_verify` — data in, `Result` out, no
`Store` access, no I/O, no identity of *the caller* baked in:

```rust
pub fn check_card_against_pin(
    card: &VerifiedCard,
    pinned: &crate::store::PinnedPeer,
) -> Result<(), CardError> {
    let offered_x25519_hex = hex::encode(card.x25519_pubkey.as_bytes());
    if offered_x25519_hex != pinned.x25519_pubkey {
        return Err(CardError::PinnedKeyConflict {
            label: pinned.label.clone(),
            ed25519_fingerprint: format_fingerprint(&fingerprint_hex(&pinned.ed25519_pubkey)),
            existing_x25519_display: format_fingerprint(&fingerprint_hex(&pinned.x25519_pubkey)),
            offered_x25519_display: format_fingerprint(&fingerprint_hex(&offered_x25519_hex)),
        });
    }
    Ok(())
}
```

(The ruling's sketch named this `check_card_against_pin(&SignedCard, &PinnedPeer)`;
this spec takes `&VerifiedCard` instead — the typed output `parse_and_verify` already
produced — so the function isn't re-decoding base64 it just decoded a moment earlier.
Same placement, same purity, same call-site contract; only the parameter type changes,
from "the still-encoded wire struct" to "the already-verified typed keys.")

Both call sites run it identically: after `SignedCard::parse_and_verify` succeeds and
yields a `VerifiedCard`, look up `store.get_peer_by_key(&hex::encode(card.ed25519_pubkey
.to_bytes()))`; if a pin exists, call `check_card_against_pin(&card, &existing)` and
propagate its error *before* the self-add check or the label-collision check run.
`Store::add_peer`'s signature does not change — this is a call-site *sequencing*
decision (call the engine function, then proceed), not new `Store` coupling, so
`store.rs` stays at zero diff either way.

**Message contents, precisely (so AC7 is testable as written):** the Ed25519 key is
*identical* on both sides of this conflict by construction — that's what "already
pinned under this Ed25519 key" means — so naming two Ed25519 fingerprints would be
misleading (it would imply two different identities, when there is exactly one). The
message instead names the **peer** once (`label` + the single, shared Ed25519
`fingerprint_hex`/`format_fingerprint` display, matching how a pinned peer is named
everywhere else in the app/CLI) and then shows **two X25519 displays**, both produced
by feeding the raw X25519 key bytes through the *same* `fingerprint_hex`/
`format_fingerprint` machinery already used for Ed25519 fingerprints (domain-separated
SHA-256 truncated to `FINGERPRINT_HEX_LEN`, grouped in fours) — `fingerprint_hex` is
generic over any hex-encoded 32-byte key today; this is its first caller for an X25519
key rather than an Ed25519 one, no new hashing logic:
- `existing_x25519_display`: `format_fingerprint(fingerprint_hex(pinned.x25519_pubkey))`
  — the key already on file.
- `offered_x25519_display`: same function, over the card's X25519 key — the key this
  card is offering.

`CardError::PinnedKeyConflict`'s `Display` impl renders all three pieces (label,
shared Ed25519 fingerprint, both X25519 displays) so the user sees, unambiguously: *this
is peer X (fingerprint …); the key on file for their encryption key is …; this card
offers …; they don't match.*

### D-D — where card verification lives: one engine function, both surfaces call it

**Engine-shared, in `identity.rs`, next to `SignedCard`:**

```rust
impl SignedCard {
    pub fn parse_and_verify(card_base64: &str) -> Result<VerifiedCard, CardError> { ... }
}

pub struct VerifiedCard {
    pub ed25519_pubkey: VerifyingKey,
    pub x25519_pubkey: X25519PublicKey,
}
```

This is real logic that could genuinely diverge if re-implemented per surface —
signature verification has several ordered gates that must all run, in order, every
time, or a bug in one surface silently accepts what the other correctly rejects.
Exactly the situation SLICE-04.md's D-D named as the case *for* engine-sharing
(distinguished there from the self-add guard, which isn't this kind of logic — and see
D-C above, revised to the same engine-shared treatment for the same reason:
`check_card_against_pin` turned out to have more moving parts than SLICE-04's self-add
equality once the message format was specified precisely). `SignedCard`/`VerifiedCard`
are pure data + crypto — no `Store`, no identity of *the caller* — so this does not
reintroduce identity concerns into `Store`; it lives in `identity.rs`, the same module
that already owns `PublicCard`'s decode/validate methods, not a new module (minimal
churn — see D-E(1) for why a full new `card.rs` module wasn't necessary once the
two-type split is in place). `check_card_against_pin` lives here too, for the same
reason.

**Exact gate order inside `parse_and_verify`,** so an independent implementation could
reproduce it from this spec alone:

1. Trim whitespace, base64-decode → `CardError::NotBase64` on failure.
2. Parse as a raw `serde_json::Value` (not straight into `SignedCard`) →
   `CardError::NotJson` on failure.
3. Check `value.get("version")`: absent → `CardError::LegacyUnsigned`.
4. Deserialize into `SignedCard` proper → any remaining shape mismatch →
   `CardError::Malformed(String)`.
5. `card.version != 2` → `CardError::UnsupportedVersion(card.version)`.
6. Decode `ed25519_public`/`x25519_public` into real keys (reusing the same decode
   logic `PublicCard`'s methods already use) → `CardError::MalformedKey` (wraps
   `IdentityError`) on failure.
7. Decode `signature` from base64 into a 64-byte `Signature` → `CardError::
   MalformedSignature` on bad length/format.
8. `crypto::verify(&ed25519_key, &canonical_bytes(card.version, &ed25519_key,
   &x25519_key), &signature)` → `CardError::SignatureInvalid` on failure.
9. Return `VerifiedCard { ed25519_pubkey, x25519_pubkey }`.

**As a property, not just a list order:** every structural check — base64 validity
(1), JSON validity (2), the legacy-vs-versioned distinction (3), full shape (4), known
version (5), and key/signature field lengths and encoding (6, 7) — completes before
step 8 attempts any cryptographic operation. Equivalently: **no signature verification
runs on a card that fails a structural check.** This is what makes the legacy/malformed/
signature-invalid distinction (D-B) real rather than accidental — a legacy card is
rejected at step 3, before `crypto::verify` is ever reached, so "old card" and "tampered
card" can never be confused with each other by an implementation detail of gate
ordering. This property is directly testable: for every `CardError` variant other than
`SignatureInvalid` (and `MalformedKey`/`MalformedSignature`, which are structural
decode failures on the key/signature bytes themselves, not crypto failures), a card
triggering it must never reach `crypto::verify`.

Both `cmd_add_peer` and `add_peer_card` call step 0 through 9 as one function call, then
run (in this order): a `store.get_peer_by_key` lookup and, if a pin exists,
`check_card_against_pin` (D-C, also engine-shared), the existing self-add guard
(SLICE-04.md D-D), the existing label-collision pre-check (SLICE-03.md D3), then
`Store::add_peer` — stated explicitly so the two surfaces can't drift on ordering.

New typed error, `CardError` in `error.rs` (thiserror, matching the rest of the
codebase's discipline — replacing the two surfaces' ad hoc `CliError::InvalidCard
(String)` / `AppError::InvalidCard(String)`, which were the only string-typed error
variants left in either enum):

```rust
#[derive(Debug, Error)]
pub enum CardError {
    #[error("card text is not valid base64: {0}")]
    NotBase64(String),
    #[error("card is not valid JSON: {0}")]
    NotJson(String),
    #[error("this card is from an older version of sympoden - ask for a fresh one")]
    LegacyUnsigned,
    #[error("card is malformed: {0}")]
    Malformed(String),
    #[error("unsupported card version {0}")]
    UnsupportedVersion(u8),
    #[error("card key material is malformed: {0}")]
    MalformedKey(#[from] IdentityError),
    #[error("card signature is malformed")]
    MalformedSignature,
    #[error("card signature does not verify - it may be corrupted or tampered with")]
    SignatureInvalid,
    #[error(
        "{label} ({ed25519_fingerprint}) is already pinned with a different encryption key: \
         on file {existing_x25519_display}, this card offers {offered_x25519_display}"
    )]
    PinnedKeyConflict {
        label: String,
        ed25519_fingerprint: String,
        existing_x25519_display: String,
        offered_x25519_display: String,
    },
}
```

`PinnedKeyConflict` is D-C's reject (`check_card_against_pin`'s `Err` case), grouped
into the same enum as the parse/verify failures above rather than a separate error type
— both are "the card was rejected before `add_peer`," and `CliError`/`AppError`
already flatten to one `Card(#[from] CardError)` variant each, so callers don't need to
match two different error types for "this card didn't pin."

`CliError`/`AppError` each gain `#[error(transparent)] Card(#[from] CardError)`,
replacing their `InvalidCard(String)` variant.

### D-E — found by reading the real code

1. **`PublicCard`'s double duty, and why it forced the two-type split (D-A).** Covered
   above under "current card format" and D-A — surfaced because the naive
   design (bolt `version`/`signature` onto the existing struct) is a dead end the
   moment `from_pinned_peer` tries to construct one without a private key it can never
   hold. This is the one finding that actually changes the shape of D-A, not just a
   footnote.

2. **The base64 boundary is handled on opposite sides of the Rust/JS split, per
   surface.** Today the CLI base64-encodes/decodes in Rust; the app base64-encodes/
   decodes in JS (`btoa`/`atob` in `ui/main.js`), and its Rust side never sees base64 at
   all. Once emission needs to sign (Rust-only, needs the `SigningKey`) and parsing
   needs to verify (Rust-only, needs `crypto::verify`), both steps are naturally
   Rust-side work — the asymmetry is worth collapsing while both surfaces are already
   being touched for this slice, rather than carrying it forward as an accident of
   history. **Recommendation:** "a card is a base64 string, full stop" — `parse_and_
   verify` takes the pasted base64 text directly; `cmd_add_peer` passes `card.trim()`
   straight through (drops its own separate `BASE64.decode` call); `add_peer_card` also
   takes raw base64 text now, and `ui/main.js`'s `doAddPeer()` stops calling `atob()`
   before invoking — the textarea's raw value goes straight to the backend. Symmetric
   on emission: `Identity::card_encoded()` returns the final base64 string; `cmd_whoami`
   prints it verbatim; the app's `whoami` command returns it verbatim; `ui/main.js`'s
   `enterApp()` stops calling `btoa()` — `myCardEl.value = card` directly. Net effect:
   less code on the JS side, not more, and one unambiguous rule everywhere instead of
   two surfaces quietly agreeing by accident.

3. **Card generation is engine-shared too — made explicit.** It follows from D-A/D-E(2)
   but is worth stating as its own point since it's a testable property, not just an
   implication: after this slice, a `SignedCard` is assembled and signed in exactly one
   place, `Identity::card_encoded`, in `identity.rs`. The app's "Your card" text
   arrives from the engine via the Tauri IPC boundary **already signed** — the app's
   `whoami` command is a thin call-through, and `ui/main.js` receives a finished
   opaque string and only ever displays or copies it. **JS never composes, encodes, or
   signs a card**, before or after this slice — it holds no signing key and never will
   (D-A's whole reason `PublicCard`/`from_pinned_peer` can't produce a `SignedCard`
   applies doubly to JS, which doesn't even have engine-level key access). Any card
   assembly that currently lives in `main.js` (there is none today — the app's Rust
   side already builds the JSON; JS's `btoa()` is base64 encoding, not assembly) stays
   that way: the JS-side change this slice makes is strictly subtractive (drop `atob`/
   `btoa`, per D-E(2)), never additive.

4. **SLICE-03.md's Known Limitation (j)** names this exact gap ("a card's X25519 half
   is trusted on import, unverified against its Ed25519 half... Adjustment 1") and
   points at this slice by description. Closeout should add a one-line note to
   SLICE-03.md marking (j) closed-by-SLICE-05, matching the cross-referencing already
   used between shipped slices (a docs-only addition, not code).

5. **`scripts/demo.sh` compatibility.** Every existing pin flow (Slice 01 through
   Slice 04's fixtures) keeps working unchanged once `whoami` emits v2 signed cards and
   `add-peer` verifies them — this is purely additive to the happy path, zero behavior
   change for a legitimate card. New coverage is additive: a tampered-X25519 card
   rejects, a tampered-signature card rejects, a hand-built legacy-shaped (no
   `version`) card rejects with the friendly message, and the D-C same-key-different-
   X25519 case rejects loudly.

## Components

**Engine (`sympoden-engine`):**
- `identity.rs`:
  - New `CARD_DOMAIN_TAG`, `SignedCard` struct, `SignedCard::parse_and_verify`,
    `VerifiedCard` struct, `check_card_against_pin` (D-A/D-C/D-D). Card generation
    (D-E(2)/D-E(3)) also lives here: `Identity::card_encoded` is the only place a
    `SignedCard` is ever assembled or signed.
  - New `Identity::card_encoded(&self) -> String` (D-A). `Identity::public_card()`
    removed (dead once both callers move to `card_encoded()`); the `PublicCard` type
    itself is untouched and keeps being used by `from_pinned_peer`.
  - `PublicCard`, `PublicCard::from_pinned_peer`, `fingerprint_hex`, `format_
    fingerprint`: **zero diff** — this is the point of the D-A split.
    `check_card_against_pin` calls `fingerprint_hex`/`format_fingerprint` unchanged,
    now over an X25519 key as well as Ed25519 (their first non-Ed25519 caller, no
    signature change needed since both already take a hex string).
- `error.rs`: new `CardError` enum, including `PinnedKeyConflict` for D-C (D-D). No
  changes to `StoreError`, `SyncError`, `ContentError`, `IdentityError` —
  `CardError::MalformedKey` wraps `IdentityError` via `#[from]` rather than extending
  it.
- `store.rs`: **zero diff.** `add_peer`'s signature and `AddPeerOutcome`'s variant set
  are untouched (D-C, D-D) — `check_card_against_pin` and `parse_and_verify` both run
  entirely before `add_peer` is ever called, mirroring how Slice 04's self-add guard
  kept `store.rs` at zero diff.
- `crypto.rs`, `content.rs`, `sync.rs`, `trust.rs`, the `relay` crate: **zero diff.** No
  new primitive (D-D reuses `crypto::sign`/`crypto::verify` as-is); `sync.rs` imports
  `PublicCard` by name and calls the same two methods on it, untouched by the D-A
  split.

**CLI (`sympoden-cli`):**
- `cmd_whoami`: calls `identity.card_encoded()`, prints the result directly — no more
  local `BASE64.encode(serde_json::to_vec(...))`. No card assembly of any kind left in
  `main.rs`.
- `cmd_add_peer`: calls `SignedCard::parse_and_verify(card.trim())` in place of today's
  `BASE64.decode` + `serde_json::from_slice` + separate key-format calls. On success,
  looks up any existing pin by the verified Ed25519 key and, if found, calls the engine
  function `check_card_against_pin` (new; replaces the call-site-guard sketch from the
  earlier draft), then the existing self-add guard (unchanged), then the existing
  label-collision pre-check (unchanged), then `store.add_peer` (unchanged call).
- `CliError`: `InvalidCard(String)` replaced by `Card(#[from] CardError)`, which now
  also covers the D-C reject via `CardError::PinnedKeyConflict` — no separate variant
  needed in `CliError` itself.

**App (`sympoden-app`):**
- `whoami_card`/`whoami` Tauri command: replaced by a call to `session.identity.
  card_encoded()`, returned as-is (no `serde_json::to_string` wrapping needed — it's
  already the final string). No card assembly of any kind left in `main.rs` or
  `ui/main.js`.
- `add_peer_card`: calls `SignedCard::parse_and_verify(card)` (now receiving raw
  base64 text, per D-E(2)) in place of today's `serde_json::from_str` + separate
  key-format calls. Same post-verification order as the CLI: `check_card_against_pin`
  (if a pin exists for the Ed25519 key), then self-add guard, then collision pre-check,
  then `add_peer`.
- `AppError`: `InvalidCard(String)` replaced by `Card(#[from] CardError)` — the D-C
  reject surfaces through the same variant (`CardError::PinnedKeyConflict`'s `Display`),
  to the frontend as a plain status message; no separate `AddPeerResult` variant needed.
- Frontend (`ui/main.js`): `doAddPeer()` drops its `atob()` call, passes the pasted
  textarea value straight through (D-E(2)). `enterApp()` drops its `btoa()` call,
  assigns `myCardEl.value = card` directly. JS composes, encodes, or signs nothing
  card-related, before or after this slice — it only ever moves an opaque string
  produced by the engine.

**Tests / demo:**
- Engine unit tests (identity.rs): a freshly signed card verifies; tampering the
  X25519 field after signing fails verification; tampering the `version` byte after
  signing fails verification (proves the version is under the signature, not just
  gated by the pre-check at step 5); tampering the signature bytes fails verification;
  a hand-built legacy-shaped JSON (no `version`) yields `LegacyUnsigned`; a `version: 3`
  card yields `UnsupportedVersion(3)`; garbage base64/JSON yields `NotBase64`/`NotJson`;
  a card round-trips through `card_encoded()` → `parse_and_verify()` back to the same
  two keys; `check_card_against_pin` returns `Ok` for a matching X25519 key and
  `Err(PinnedKeyConflict { .. })` with the three specified display fields for a
  mismatched one.
- CLI/app tests: the D-C conflict case (pin a key, then feed a validly-signed card for
  the same Ed25519 key but a different X25519 key — rejected via
  `CardError::PinnedKeyConflict`, message naming the peer's label, its one shared
  Ed25519 fingerprint, and both X25519 displays, no write); the self-add guard and
  label-collision pre-check still fire correctly downstream of a verified card
  (ordering test).
- `scripts/demo.sh`: extend (not replace) — a valid v2 card pins normally through the
  existing flows (implicit, since every existing step already goes through `whoami`/
  `add-peer`); a hand-tampered card (edit the base64 blob's decoded X25519 field, or
  its signature field, then re-encode) is fed to `add-peer` and rejected; the D-C
  case (re-present a different card for an already-pinned identity) is rejected
  loudly and the pin's stored X25519 key is unchanged.

## Acceptance criteria

1. A fresh `whoami`/`card_encoded()` output pins successfully via `add-peer`/
   `add_peer_card` — signature verifies, the stored `x25519_pubkey` matches the card
   exactly, behavior otherwise identical to before this slice for a legitimate card.
2. A card whose `x25519_public` field is altered after signing (so it no longer
   matches what was signed) is rejected at parse time (`CardError::SignatureInvalid`)
   before `add_peer` is ever called; nothing is written.
3. A card whose `version` field is altered after signing to another *known* version
   value (edited in place, signature untouched) is also rejected at parse time
   (`CardError::SignatureInvalid`, not silently accepted as the edited version) —
   proves the version byte is genuinely inside the signed bytes (D-A's crux), not
   merely gated by the separate version check at gate 5.
4. A card whose `signature` field is altered/corrupted (keys untouched) is rejected
   the same way (`SignatureInvalid`).
5. A card missing `version`/`signature` entirely (today's legacy shape, or an old
   build's output) is rejected with the friendly "ask for a fresh card" message
   (`CardError::LegacyUnsigned`) — distinct from a generically malformed/garbage blob
   (`CardError::NotBase64`/`NotJson`). Neither is silently patched through.
6. A card carrying a `version` value other than 2 (and not tampered — a freshly
   hand-built v3-shaped card, hypothetically) is rejected, naming the unsupported
   version (`CardError::UnsupportedVersion`), and this check happens before any
   signature verification is attempted (gate order, D-D).
7. A validly-signed card for an already-pinned Ed25519 key, carrying a **different**
   X25519 key than the one on file, is rejected loudly via `check_card_against_pin`
   returning `CardError::PinnedKeyConflict` — before `add_peer` is called; the pinned
   peer's stored X25519 key is left untouched (D-C). The rejection message names the
   peer once (label + the single Ed25519 fingerprint, shared by construction on both
   sides of this conflict) and shows **two X25519 displays** — the key on file and the
   key the card offered — each produced via `format_fingerprint(fingerprint_hex(..))`
   over the raw X25519 key bytes, the same display machinery already used for Ed25519
   fingerprints elsewhere in the app/CLI.
8. A validly-signed card for an already-pinned Ed25519 key carrying the **same**
   X25519 key as on file behaves exactly as before this slice (`AlreadyPinned`/
   `AlreadyPinnedUnderLabel` via `add_peer`, unchanged).
9. Existing pins from before this slice (rows in `peers` with no signature anywhere,
   because none was ever stored) are unaffected: no re-verification is attempted at
   rest, no migration, no re-prompt, nothing breaks.
10. Self-add rejection (SLICE-04.md AC7) and label-collision handling (SLICE-03.md D3)
    continue to work exactly as before, now running strictly after signature
    verification rather than after a bare parse (D-D's stated gate order), and strictly
    after `check_card_against_pin` where a pin already exists (D-C).
11. Both CLI and app produce and consume cards through one base64 boundary (D-E(2)):
    `cmd_whoami`/`whoami` emit one ready-to-paste string; `cmd_add_peer`/
    `add_peer_card` accept that exact string un-decoded by the caller, calling
    `SignedCard::parse_and_verify` themselves. No card is composed, encoded, or signed
    in `ui/main.js` or in either `main.rs`, before or after this slice — assembly and
    signing happen only inside `Identity::card_encoded` (D-E(3)).
12. **Zero-diff:** `git diff <slice-start>..HEAD -- sympoden-engine/src/crypto.rs
    sympoden-engine/src/content.rs sympoden-engine/src/sync.rs
    sympoden-engine/src/trust.rs sympoden-engine/src/store.rs sympoden-relay/` is
    empty.
13. `cargo test --workspace` green, `cargo clippy --workspace --all-targets -- -D
    warnings` clean, `cargo build -p sympoden-app` succeeds. `scripts/demo.sh` green,
    extended with the tampered-card and D-C reject cases end to end against a live
    relay.

## Explicit NON-GOALS (do not build these in Slice 05)

- **Key rotation.** Whatever D-C decides, actually *supporting* a peer changing their
  X25519 key (re-sealing pending sends, notifying, history) is its own future slice —
  named explicitly by SLICE-03.md's Adjustment 1 as out of scope here too.
- **Self-signed nicknames / any rooms machinery.** The signing *shape* (a key signing
  an attribute of itself, domain-separated) is reusable for `FOUNDATION.md` §7's
  public-rooms nickname idea — confirmed while reading §7 for this slice — but
  building it is the rooms layer's job, not this one's.
- **Re-verifying already-pinned peers at rest.** Existing pins stay trusted-as-pinned;
  nothing scans or re-checks the `peers` table for this slice.
- **The mutual-connection handshake.** Still its own deferred slice (SLICE-04.md
  already named this).
- **Card revocation or expiry.** Out — a card is valid or it isn't, forever, as far as
  this slice is concerned.
- Out-of-band key verification, multi-device, peer **exchange** UX (QR/pairing-code) —
  all out, as in prior slices.

## Honesty section

- **Signing proves binding, not goodness.** A card generated entirely by an attacker —
  who freshly generates *both* an Ed25519 and an X25519 keypair and signs the one with
  the other — is perfectly internally valid. This slice guarantees the two keys in a
  card were issued together by whoever holds that Ed25519 private key; it says nothing
  about whether that person is who they claim to be. That was true before this slice
  and stays true after it — self-signing closes the *substitution-in-transit* gap, not
  the *out-of-band identity verification* gap, which remains explicitly unsolved (as in
  every prior slice).
- **The D-C reject is conservative by design, not exhaustive.** A real key-rotation
  event (a peer legitimately generating a new X25519 key) looks identical, from this
  client's point of view, to an attacker who captured the Ed25519 private key and is
  presenting a fresh pair — both produce a validly-signed card with a changed X25519
  half for a known Ed25519 key. This slice cannot and does not try to distinguish them;
  it refuses both, equally, until a rotation slice exists to handle the legitimate case
  deliberately.
- **This slice changes nothing about the relay, the envelope, or note-signature
  verification.** A tampered X25519 key that somehow made it into a pin before this
  slice shipped (impossible to detect retroactively, per NON-GOALS) would still work
  exactly as it does today — this is a forward-looking gate on new pins, not a scan of
  history.

## Status

**Approved — implementation go-ahead given 2026-07-14.** D-A through D-E all approved,
with refinements folded into this document: D-A's signed bytes now explicitly cover
`domain_tag ‖ version ‖ ed25519_public ‖ x25519_public` (the crux); D-B's three failure
categories confirmed distinguishable; D-C's pinned-key-conflict check moved from a
call-site guard to the engine-shared `check_card_against_pin`, with the message format
specified exactly (one shared Ed25519 fingerprint, two X25519 fingerprints); D-D's gate
order restated as a testable property ("no signature verification runs on a card that
fails structural checks"); D-E's card-generation-is-engine-shared point made explicit.
No code has been written yet — implementation begins from this revision.
