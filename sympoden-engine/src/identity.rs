//! Identity: an Ed25519 signing keypair plus an X25519 key-agreement keypair, sealed
//! in a passphrase-protected keyfile. Two independent keypairs are generated (not one
//! key reused via clamping) so signing and key-agreement stay cryptographically
//! separate.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CardError, IdentityError};
use crate::kdf::{self, Argon2Params, DerivedKeys, KEY_LEN, SALT_LEN};

const NONCE_LEN: usize = 12;
const SEALED_PLAINTEXT_LEN: usize = 32 /* ed25519 seed */ + 32 /* x25519 secret */;
const KEYFILE_VERSION: u8 = 1;

/// Domain-separates the display fingerprint's hash from `crypto::routing_key_for`'s
/// hash of the same key — they're unrelated concerns (a human-facing disambiguation aid
/// vs. a protocol-level routing address) that happen to both be SHA-256 of an Ed25519
/// key; tagging keeps a future change to one from silently changing the other. Mirrors
/// `content.rs`'s `DOMAIN_TAG` pattern for signed bytes.
const FINGERPRINT_DOMAIN_TAG: &[u8] = b"sympoden-fingerprint-v1\0";

/// Domain-separates a `SignedCard`'s signed bytes from a note's (`content.rs`'s
/// `DOMAIN_TAG`) and from a fingerprint hash (`FINGERPRINT_DOMAIN_TAG`) — a card
/// signature can never be replayed as either. The `-v2` names the *card format
/// generation* this slice introduces; there never was a signed `-v1` card (the old
/// shape, `PublicCard`, was never signed at all — "v1" only exists in prose).
const CARD_DOMAIN_TAG: &[u8] = b"sympoden-card-v2\0";

/// The only card version this build understands. See `SignedCard::parse_and_verify`.
const CARD_VERSION: u8 = 2;

/// 80 bits (SLICE-03.md D5/Adjustment 2): a slice of an already-computed hash, so the
/// extra bits over a shorter prefix cost nothing in compute or storage. Used uniformly
/// everywhere a fingerprint is shown — there is no shorter "casual" tier.
pub const FINGERPRINT_HEX_LEN: usize = 20;

// Bounds on the Argon2id parameters read from an on-disk keyfile. The keyfile is
// local user data, but it can still be hand-edited, corrupted, or (via backup/
// restore/import in a later phase) come from somewhere less trusted than "this
// process wrote it" — and `m_cost_kib` is, unguarded, an attacker-controlled
// allocation size handed straight to argon2's hasher. Validate before any of that
// runs, so an absurd value is rejected with a typed error instead of attempting a
// multi-gigabyte (or u32::MAX-KiB ≈ 4 TiB) allocation.
//
// - Floor 19 MiB: this is the OWASP-acceptable minimum and the value every keyfile
//   this codebase has ever shipped was created with (the original
//   `Argon2Params::default()`, before it was later raised further), so no existing
//   keyfile is excluded. It doubles as a downgrade guard: a keyfile (hand-edited,
//   corrupted, or restored from somewhere less trusted) cannot claim an m_cost
//   weaker than the OWASP minimum and still be accepted.
// - Ceiling 1 GiB: far beyond any cited Argon2id profile (OWASP's highest is 2 GiB
//   for latency-insensitive, HSM-backed use), while nowhere near enough to OOM a
//   desktop on its own.
const M_COST_KIB_FLOOR: u32 = 19456;
const M_COST_KIB_CEILING: u32 = 1024 * 1024;

// t_cost: RFC 9106 minimum is 1 pass. A ceiling of 10 is already well past any
// recommended profile (OWASP's highest cited t_cost is 4) and bounds unlock latency.
const T_COST_FLOOR: u32 = 1;
const T_COST_CEILING: u32 = 10;

// p_cost: RFC 9106 minimum is 1 lane. A ceiling of 64 bounds thread/lane fan-out far
// beyond any realistic core count, without constraining legitimate high-end configs.
const P_COST_FLOOR: u32 = 1;
const P_COST_CEILING: u32 = 64;

#[derive(Serialize, Deserialize)]
struct KdfParamsFile {
    algorithm: String,
    salt: String,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

#[derive(Serialize, Deserialize)]
struct KeyfileV1 {
    version: u8,
    kdf: KdfParamsFile,
    nonce: String,
    sealed_secret: String,
    ed25519_public: String,
    x25519_public: String,
}

/// An unlocked identity: signing key, key-agreement key, and the SQLCipher database
/// key derived alongside them. All secret fields zeroize on drop.
pub struct Identity {
    pub signing_key: SigningKey,
    pub x25519_secret: StaticSecret,
    pub db_key: Zeroizing<[u8; KEY_LEN]>,
}

/// The public half of an identity — what gets shared with a peer out-of-band so they
/// can verify your signatures and encrypt notes to you. Publishing this is publishing
/// your own public key, not personal data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicCard {
    pub ed25519_public: String, // base64
    pub x25519_public: String,  // base64
}

/// The wire artifact from Slice 05 on: a card is a self-verifiable claim, not just a
/// pair of keys — the identity's own Ed25519 key signs its paired X25519 key, so
/// anyone holding the card can confirm the two were issued together (SLICE-05.md D-A).
/// This is the only thing that travels out-of-band as "a card"; `PublicCard` above is
/// kept, unchanged, purely as `sync.rs`'s internal "a pinned peer's two keys"
/// reconstruction, which can never carry a signature (it is never built from a private
/// key this device holds).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCard {
    pub version: u8,             // = CARD_VERSION, always. Absent or other is rejected.
    pub ed25519_public: String,  // base64 — same encoding PublicCard already uses
    pub x25519_public: String,   // base64
    pub signature: String,       // base64, ed25519 signature over canonical_bytes below
}

/// A `SignedCard` that has passed every structural and cryptographic check in
/// `SignedCard::parse_and_verify` — real curve points, a signature that verifies over
/// them. Deliberately holds typed keys, not the base64 strings `SignedCard` carries,
/// so a caller can't accidentally skip back to unverified data.
#[derive(Debug, Clone)]
pub struct VerifiedCard {
    pub ed25519_pubkey: VerifyingKey,
    pub x25519_pubkey: X25519PublicKey,
}

/// The signed bytes for a card: `domain_tag ‖ version ‖ ed25519_public ‖ x25519_public`
/// — all four under the signature, non-negotiable (SLICE-05.md D-A). The version is
/// signed, not just implied by which domain tag verified, so an on-path edit to it
/// (up or down) invalidates the signature instead of silently downgrading/upgrading a
/// future format; the Ed25519 key is signed too, so nothing an attacker could touch is
/// left uncovered. No length-prefixing needed: the tag is constant, `version` is one
/// fixed byte, and both keys are fixed 32-byte arrays.
fn card_canonical_bytes(
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

impl Identity {
    /// Generate a fresh identity and write a new passphrase-sealed keyfile. Errors if
    /// a keyfile already exists at `path`.
    pub fn create(path: &Path, passphrase: &str) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let x25519_secret = StaticSecret::random_from_rng(OsRng);

        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let params = Argon2Params::default();

        let DerivedKeys {
            keyfile_seal_key,
            db_key,
        } = kdf::derive_keys(passphrase, &salt, params)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut plaintext = Zeroizing::new([0u8; SEALED_PLAINTEXT_LEN]);
        plaintext[..32].copy_from_slice(signing_key.to_bytes().as_ref());
        plaintext[32..].copy_from_slice(&x25519_secret.to_bytes());

        let cipher = ChaCha20Poly1305::new(Key::from_slice(keyfile_seal_key.as_ref()));
        let sealed_secret = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &[],
                },
            )
            .map_err(|_| IdentityError::KeyDerivation)?;

        let keyfile = KeyfileV1 {
            version: KEYFILE_VERSION,
            kdf: KdfParamsFile {
                algorithm: "argon2id".to_string(),
                salt: BASE64.encode(salt),
                m_cost_kib: params.m_cost_kib,
                t_cost: params.t_cost,
                p_cost: params.p_cost,
            },
            nonce: BASE64.encode(nonce_bytes),
            sealed_secret: BASE64.encode(sealed_secret),
            ed25519_public: BASE64.encode(signing_key.verifying_key().to_bytes()),
            x25519_public: BASE64.encode(X25519PublicKey::from(&x25519_secret).to_bytes()),
        };

        let serialized = serde_json::to_vec_pretty(&keyfile)
            .map_err(|e| IdentityError::Malformed(e.to_string()))?;

        // create_new fails atomically if a file already exists at `path`, so a second
        // `create` can never silently overwrite (and destroy) an existing identity.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => IdentityError::AlreadyExists,
                _ => IdentityError::Io(e),
            })?;
        file.write_all(&serialized)?;

        Ok(Self {
            signing_key,
            x25519_secret,
            db_key,
        })
    }

    /// Unlock an existing keyfile with a passphrase. A wrong passphrase fails the AEAD
    /// tag check and returns `IdentityError::InvalidPassphrase` — never panics.
    pub fn unlock(path: &Path, passphrase: &str) -> Result<Self, IdentityError> {
        let raw = fs::read(path)?;
        let keyfile: KeyfileV1 =
            serde_json::from_slice(&raw).map_err(|e| IdentityError::Malformed(e.to_string()))?;

        if keyfile.version != KEYFILE_VERSION {
            return Err(IdentityError::Malformed(format!(
                "unsupported keyfile version {}",
                keyfile.version
            )));
        }
        if keyfile.kdf.algorithm != "argon2id" {
            return Err(IdentityError::Malformed(format!(
                "unsupported kdf algorithm {}",
                keyfile.kdf.algorithm
            )));
        }

        // Bound-check before touching the salt, building `Argon2Params`, or calling
        // into argon2 — a keyfile with an out-of-range m_cost must never reach the
        // point of allocating memory for it.
        if !(M_COST_KIB_FLOOR..=M_COST_KIB_CEILING).contains(&keyfile.kdf.m_cost_kib) {
            return Err(IdentityError::Malformed(format!(
                "m_cost_kib {} outside allowed range [{}, {}]",
                keyfile.kdf.m_cost_kib, M_COST_KIB_FLOOR, M_COST_KIB_CEILING
            )));
        }
        if !(T_COST_FLOOR..=T_COST_CEILING).contains(&keyfile.kdf.t_cost) {
            return Err(IdentityError::Malformed(format!(
                "t_cost {} outside allowed range [{}, {}]",
                keyfile.kdf.t_cost, T_COST_FLOOR, T_COST_CEILING
            )));
        }
        if !(P_COST_FLOOR..=P_COST_CEILING).contains(&keyfile.kdf.p_cost) {
            return Err(IdentityError::Malformed(format!(
                "p_cost {} outside allowed range [{}, {}]",
                keyfile.kdf.p_cost, P_COST_FLOOR, P_COST_CEILING
            )));
        }

        let salt_bytes = BASE64
            .decode(&keyfile.kdf.salt)
            .map_err(|e| IdentityError::Malformed(e.to_string()))?;
        let salt: [u8; SALT_LEN] = salt_bytes
            .try_into()
            .map_err(|_| IdentityError::Malformed("salt has the wrong length".to_string()))?;

        let params = Argon2Params {
            m_cost_kib: keyfile.kdf.m_cost_kib,
            t_cost: keyfile.kdf.t_cost,
            p_cost: keyfile.kdf.p_cost,
        };

        let DerivedKeys {
            keyfile_seal_key,
            db_key,
        } = kdf::derive_keys(passphrase, &salt, params)?;

        let nonce_bytes = BASE64
            .decode(&keyfile.nonce)
            .map_err(|e| IdentityError::Malformed(e.to_string()))?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(IdentityError::Malformed(
                "nonce has the wrong length".to_string(),
            ));
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        let sealed_secret = BASE64
            .decode(&keyfile.sealed_secret)
            .map_err(|e| IdentityError::Malformed(e.to_string()))?;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(keyfile_seal_key.as_ref()));
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &sealed_secret,
                    aad: &[],
                },
            )
            .map_err(|_| IdentityError::InvalidPassphrase)?;

        if plaintext.len() != SEALED_PLAINTEXT_LEN {
            return Err(IdentityError::Malformed(
                "sealed secret has the wrong length".to_string(),
            ));
        }
        let mut plaintext = Zeroizing::new(plaintext);

        let mut ed25519_seed = [0u8; 32];
        ed25519_seed.copy_from_slice(&plaintext[..32]);
        let signing_key = SigningKey::from_bytes(&ed25519_seed);
        ed25519_seed.zeroize();

        let mut x25519_seed = [0u8; 32];
        x25519_seed.copy_from_slice(&plaintext[32..]);
        let x25519_secret = StaticSecret::from(x25519_seed);
        x25519_seed.zeroize();
        plaintext.zeroize();

        // Cross-check the public keys recorded in the keyfile against what we just
        // derived, so a corrupted/edited keyfile is rejected rather than silently
        // producing a mismatched identity.
        let expected_ed25519 = BASE64
            .decode(&keyfile.ed25519_public)
            .map_err(|e| IdentityError::Malformed(e.to_string()))?;
        if expected_ed25519 != signing_key.verifying_key().to_bytes().as_slice() {
            return Err(IdentityError::Malformed(
                "ed25519 public key does not match sealed secret".to_string(),
            ));
        }
        let expected_x25519 = BASE64
            .decode(&keyfile.x25519_public)
            .map_err(|e| IdentityError::Malformed(e.to_string()))?;
        if expected_x25519 != X25519PublicKey::from(&x25519_secret).to_bytes().as_slice() {
            return Err(IdentityError::Malformed(
                "x25519 public key does not match sealed secret".to_string(),
            ));
        }

        Ok(Self {
            signing_key,
            x25519_secret,
            db_key,
        })
    }

    /// The self-signed public identity card to share with a peer out-of-band, as a
    /// ready-to-paste base64 string — the only place a `SignedCard` is ever assembled
    /// or signed (SLICE-05.md D-E: JS never composes, encodes, or signs a card).
    pub fn card_encoded(&self) -> String {
        let ed25519_public = self.signing_key.verifying_key();
        let x25519_public = X25519PublicKey::from(&self.x25519_secret);
        let canonical = card_canonical_bytes(CARD_VERSION, &ed25519_public, &x25519_public);
        let signature = crate::crypto::sign(&self.signing_key, &canonical);
        let card = SignedCard {
            version: CARD_VERSION,
            ed25519_public: BASE64.encode(ed25519_public.to_bytes()),
            x25519_public: BASE64.encode(x25519_public.to_bytes()),
            signature: BASE64.encode(signature.to_bytes()),
        };
        // Infallible: every field is our own freshly-encoded data, never user input.
        BASE64.encode(serde_json::to_vec(&card).unwrap_or_default())
    }

    /// Kept, unremoved, deliberately: `sync.rs`'s own test module builds a `PublicCard`
    /// this way (`sync.rs:164`/`sync.rs:205`) and `sync.rs` is held at zero diff this
    /// slice (SLICE-05.md's terms) — removing this method would force editing sync.rs's
    /// tests to compile, which the zero-diff mandate forbids. SLICE-05.md's D-A assumed
    /// `cmd_whoami`/the app's `whoami` were `public_card`'s only callers; this third,
    /// test-only caller wasn't in that survey. Production code (CLI/app `whoami`) uses
    /// `card_encoded` exclusively from this slice on; this method is otherwise dead in
    /// production, kept alive only by sync.rs's tests.
    pub fn public_card(&self) -> PublicCard {
        PublicCard {
            ed25519_public: BASE64.encode(self.signing_key.verifying_key().to_bytes()),
            x25519_public: BASE64.encode(X25519PublicKey::from(&self.x25519_secret).to_bytes()),
        }
    }
}

impl PublicCard {
    /// Reconstruct the sendable card for a pinned peer, decoding the hex keys the
    /// `peers` table stores (matching `StoredNote::author_pubkey`'s encoding) back
    /// into the base64 a `PublicCard` carries.
    pub fn from_pinned_peer(peer: &crate::store::PinnedPeer) -> Result<Self, IdentityError> {
        let ed_bytes = hex::decode(&peer.ed25519_pubkey)
            .map_err(|e| IdentityError::Malformed(e.to_string()))?;
        let x_bytes = hex::decode(&peer.x25519_pubkey)
            .map_err(|e| IdentityError::Malformed(e.to_string()))?;
        Ok(Self {
            ed25519_public: BASE64.encode(ed_bytes),
            x25519_public: BASE64.encode(x_bytes),
        })
    }

    pub fn ed25519_verifying_key(&self) -> Result<VerifyingKey, IdentityError> {
        let bytes = BASE64
            .decode(&self.ed25519_public)
            .map_err(|e| IdentityError::Malformed(e.to_string()))?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            IdentityError::Malformed("ed25519 public key has the wrong length".to_string())
        })?;
        VerifyingKey::from_bytes(&bytes).map_err(|e| IdentityError::Malformed(e.to_string()))
    }

    pub fn x25519_public_key(&self) -> Result<X25519PublicKey, IdentityError> {
        let bytes = BASE64
            .decode(&self.x25519_public)
            .map_err(|e| IdentityError::Malformed(e.to_string()))?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            IdentityError::Malformed("x25519 public key has the wrong length".to_string())
        })?;
        Ok(X25519PublicKey::from(bytes))
    }
}

impl SignedCard {
    /// Parse and verify a pasted card, in one call — the only way `SignedCard` bytes
    /// are ever turned into trusted keys (SLICE-05.md D-D). Every structural check
    /// (base64, JSON, the legacy-vs-versioned distinction, shape, known version, key
    /// and signature lengths) completes before signature verification is even
    /// attempted: no signature verification runs on a card that fails a structural
    /// check, so "old card" and "tampered card" can never be confused with each other.
    pub fn parse_and_verify(card_base64: &str) -> Result<VerifiedCard, CardError> {
        let decoded = BASE64
            .decode(card_base64.trim())
            .map_err(|e| CardError::NotBase64(e.to_string()))?;

        let value: serde_json::Value =
            serde_json::from_slice(&decoded).map_err(|e| CardError::NotJson(e.to_string()))?;

        if value.get("version").is_none() {
            return Err(CardError::LegacyUnsigned);
        }

        let card: SignedCard =
            serde_json::from_value(value).map_err(|e| CardError::Malformed(e.to_string()))?;

        if card.version != CARD_VERSION {
            return Err(CardError::UnsupportedVersion(card.version));
        }

        let ed25519_pubkey = card.ed25519_verifying_key()?;
        let x25519_pubkey = card.x25519_public_key()?;

        let signature_bytes = BASE64
            .decode(&card.signature)
            .map_err(|_| CardError::MalformedSignature)?;
        let signature_bytes: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| CardError::MalformedSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

        let canonical = card_canonical_bytes(card.version, &ed25519_pubkey, &x25519_pubkey);
        crate::crypto::verify(&ed25519_pubkey, &canonical, &signature)
            .map_err(|_| CardError::SignatureInvalid)?;

        Ok(VerifiedCard {
            ed25519_pubkey,
            x25519_pubkey,
        })
    }

    /// Same decode logic `PublicCard::ed25519_verifying_key` uses — `SignedCard` and
    /// `PublicCard` carry the same base64 encoding for this field, only `SignedCard`
    /// also carries `version`/`signature`.
    fn ed25519_verifying_key(&self) -> Result<VerifyingKey, IdentityError> {
        let bytes = BASE64
            .decode(&self.ed25519_public)
            .map_err(|e| IdentityError::Malformed(e.to_string()))?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            IdentityError::Malformed("ed25519 public key has the wrong length".to_string())
        })?;
        VerifyingKey::from_bytes(&bytes).map_err(|e| IdentityError::Malformed(e.to_string()))
    }

    fn x25519_public_key(&self) -> Result<X25519PublicKey, IdentityError> {
        let bytes = BASE64
            .decode(&self.x25519_public)
            .map_err(|e| IdentityError::Malformed(e.to_string()))?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            IdentityError::Malformed("x25519 public key has the wrong length".to_string())
        })?;
        Ok(X25519PublicKey::from(bytes))
    }
}

/// D-C's engine-shared reject: does `card`'s X25519 key match the one already on file
/// for `pinned`'s Ed25519 key? Pure data in, `Result` out — no `Store` access, no I/O.
/// Takes the already-typed `VerifiedCard` (not the still-encoded `SignedCard`) so this
/// doesn't re-decode base64 `parse_and_verify` just decoded a moment earlier.
///
/// The Ed25519 key is identical on both sides of this conflict by construction (that's
/// what "already pinned under this key" means), so the message names the peer once
/// (label + its one shared Ed25519 fingerprint) and shows two X25519 fingerprints —
/// the key on file and the key this card offers — using the same
/// `fingerprint_hex`/`format_fingerprint` display machinery already used for Ed25519
/// fingerprints everywhere else (SLICE-05.md D-C).
pub fn check_card_against_pin(
    card: &VerifiedCard,
    pinned: &crate::store::PinnedPeer,
) -> Result<(), CardError> {
    let offered_x25519_hex = hex::encode(card.x25519_pubkey.to_bytes());
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

/// A short, stable, human-comparable fingerprint for an Ed25519 public key, given as
/// hex (matching `PinnedPeer::ed25519_pubkey`/`StoredNote::author_pubkey`'s encoding).
/// `FINGERPRINT_HEX_LEN` hex characters of `SHA-256(FINGERPRINT_DOMAIN_TAG ||
/// raw_key_bytes)` — a domain-separated hash, not a slice of the raw key (SLICE-03.md
/// D5). Calls `crypto::content_address`, an existing exported function, rather than
/// hashing inline — `crypto.rs` itself is held at zero diff this slice.
///
/// Infallible by design: a malformed `ed25519_pubkey_hex` (which should never happen —
/// every caller already has a key that round-tripped through `hex::encode`) falls back
/// to hashing nothing, rather than panicking on an engine path.
pub fn fingerprint_hex(ed25519_pubkey_hex: &str) -> String {
    let key_bytes = hex::decode(ed25519_pubkey_hex).unwrap_or_default();
    let mut tagged = Vec::with_capacity(FINGERPRINT_DOMAIN_TAG.len() + key_bytes.len());
    tagged.extend_from_slice(FINGERPRINT_DOMAIN_TAG);
    tagged.extend_from_slice(&key_bytes);
    let hash = crate::crypto::content_address(&tagged);
    hex::encode(hash)[..FINGERPRINT_HEX_LEN].to_string()
}

/// Group a fingerprint into fours for eyeball comparison, e.g.
/// `"a1b2c3d4e5f60718293a"` -> `"a1b2 c3d4 e5f6 0718 293a"`. Display-only; the raw,
/// ungrouped form from `fingerprint_hex` is what `resolve_peer_query` matches against.
pub fn format_fingerprint(fingerprint_hex: &str) -> String {
    fingerprint_hex
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn create_then_unlock_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.keyfile.json");

        let created = Identity::create(&path, "correct horse battery staple").unwrap();
        let unlocked = Identity::unlock(&path, "correct horse battery staple").unwrap();

        assert_eq!(
            created.signing_key.verifying_key(),
            unlocked.signing_key.verifying_key()
        );
        assert_eq!(
            X25519PublicKey::from(&created.x25519_secret).to_bytes(),
            X25519PublicKey::from(&unlocked.x25519_secret).to_bytes()
        );
        assert_eq!(*created.db_key, *unlocked.db_key);
    }

    #[test]
    fn wrong_passphrase_fails_cleanly() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.keyfile.json");

        Identity::create(&path, "correct horse battery staple").unwrap();
        let result = Identity::unlock(&path, "wrong passphrase");

        assert!(matches!(result, Err(IdentityError::InvalidPassphrase)));
    }

    #[test]
    fn unlock_rejects_tampered_keyfile() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.keyfile.json");

        Identity::create(&path, "passphrase").unwrap();
        let mut raw = fs::read(&path).unwrap();
        // Flip a byte inside the base64 sealed_secret field to simulate corruption.
        let idx = raw.len() / 2;
        raw[idx] ^= 0xFF;
        fs::write(&path, raw).unwrap();

        let result = Identity::unlock(&path, "passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn create_refuses_to_overwrite_an_existing_keyfile() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.keyfile.json");

        let first = Identity::create(&path, "first-passphrase").unwrap();
        let result = Identity::create(&path, "second-passphrase");

        assert!(matches!(result, Err(IdentityError::AlreadyExists)));

        // The original identity must still be intact and unlockable.
        let unlocked = Identity::unlock(&path, "first-passphrase").unwrap();
        assert_eq!(
            first.signing_key.verifying_key(),
            unlocked.signing_key.verifying_key()
        );
    }

    #[test]
    fn public_card_round_trips_through_base64() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.keyfile.json");

        let identity = Identity::create(&path, "passphrase").unwrap();
        let card = identity.public_card();

        assert_eq!(
            card.ed25519_verifying_key().unwrap(),
            identity.signing_key.verifying_key()
        );
        assert_eq!(
            card.x25519_public_key().unwrap().to_bytes(),
            X25519PublicKey::from(&identity.x25519_secret).to_bytes()
        );
    }

    #[test]
    fn from_pinned_peer_round_trips_a_card_through_the_hex_pin_encoding() {
        use crate::store::PinnedPeer;

        let dir = tempdir().unwrap();
        let bob = Identity::create(&dir.path().join("bob.json"), "bob-pass").unwrap();
        let card = bob.public_card();

        let pinned = PinnedPeer {
            label: "bob".to_string(),
            ed25519_pubkey: hex::encode(card.ed25519_verifying_key().unwrap().as_bytes()),
            x25519_pubkey: hex::encode(card.x25519_public_key().unwrap().to_bytes()),
            first_seen: 1_700_000_000,
        };

        let reconstructed = PublicCard::from_pinned_peer(&pinned).unwrap();
        assert_eq!(
            reconstructed.ed25519_verifying_key().unwrap(),
            bob.signing_key.verifying_key()
        );
        assert_eq!(
            reconstructed.x25519_public_key().unwrap().to_bytes(),
            X25519PublicKey::from(&bob.x25519_secret).to_bytes()
        );
    }

    fn make_identity(dir: &tempfile::TempDir, name: &str) -> Identity {
        Identity::create(&dir.path().join(name), "passphrase").unwrap()
    }

    /// Decode a `card_encoded()` string back into its `SignedCard` JSON `Value`, so a
    /// test can tamper a single field and re-encode - the same shape a hand-edited
    /// card sent by an attacker would have.
    fn decode_card_json(card_base64: &str) -> serde_json::Value {
        let bytes = BASE64.decode(card_base64.trim()).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn encode_card_json(value: &serde_json::Value) -> String {
        BASE64.encode(serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn a_freshly_signed_card_verifies() {
        let dir = tempdir().unwrap();
        let identity = make_identity(&dir, "id.json");

        let verified = SignedCard::parse_and_verify(&identity.card_encoded()).unwrap();

        assert_eq!(verified.ed25519_pubkey, identity.signing_key.verifying_key());
        assert_eq!(
            verified.x25519_pubkey.to_bytes(),
            X25519PublicKey::from(&identity.x25519_secret).to_bytes()
        );
    }

    #[test]
    fn card_round_trips_through_encode_and_verify() {
        let dir = tempdir().unwrap();
        let identity = make_identity(&dir, "id.json");
        let encoded = identity.card_encoded();

        let verified = SignedCard::parse_and_verify(&encoded).unwrap();
        assert_eq!(verified.ed25519_pubkey, identity.signing_key.verifying_key());
        assert_eq!(
            verified.x25519_pubkey.to_bytes(),
            X25519PublicKey::from(&identity.x25519_secret).to_bytes()
        );
    }

    #[test]
    fn tampering_the_x25519_field_after_signing_fails_verification() {
        let dir = tempdir().unwrap();
        let identity = make_identity(&dir, "id.json");
        let other = make_identity(&dir, "other.json");

        let mut value = decode_card_json(&identity.card_encoded());
        let swapped_x25519 =
            BASE64.encode(X25519PublicKey::from(&other.x25519_secret).to_bytes());
        value["x25519_public"] = serde_json::Value::String(swapped_x25519);
        let tampered = encode_card_json(&value);

        let result = SignedCard::parse_and_verify(&tampered);
        assert!(matches!(result, Err(CardError::SignatureInvalid)));
    }

    #[test]
    fn version_byte_is_genuinely_inside_the_signed_bytes() {
        // SLICE-05.md D-A's crux, proved directly against `card_canonical_bytes` and
        // `crypto::verify` - not through `SignedCard::parse_and_verify`. With only one
        // supported version defined (`CARD_VERSION == 2`), `parse_and_verify`'s gate
        // order (SLICE-05.md D-D: structural checks, including the version check,
        // before any crypto) means an edited version is always intercepted at gate 5
        // as `UnsupportedVersion` before `crypto::verify` ever runs - so this property
        // isn't observable as `SignatureInvalid` end to end today (see SLICE-05.md
        // AC3). What's actually being guaranteed - that the version byte is under the
        // signature, so a future v3 can't be downgraded to v2 by editing the field
        // alone - is exactly what this lower-level test checks.
        let dir = tempdir().unwrap();
        let identity = make_identity(&dir, "id.json");
        let ed25519_public = identity.signing_key.verifying_key();
        let x25519_public = X25519PublicKey::from(&identity.x25519_secret);

        let signed_bytes = card_canonical_bytes(2, &ed25519_public, &x25519_public);
        let signature = crate::crypto::sign(&identity.signing_key, &signed_bytes);

        // Verifies against the bytes it was actually signed over.
        assert!(crate::crypto::verify(&ed25519_public, &signed_bytes, &signature).is_ok());

        // The same signature must NOT verify against a claim with the version edited -
        // if the version weren't part of the signed bytes, this would wrongly succeed.
        let claimed_different_version = card_canonical_bytes(3, &ed25519_public, &x25519_public);
        assert!(
            crate::crypto::verify(&ed25519_public, &claimed_different_version, &signature)
                .is_err()
        );
    }

    #[test]
    fn tampering_the_signature_bytes_fails_verification() {
        let dir = tempdir().unwrap();
        let identity = make_identity(&dir, "id.json");

        let mut value = decode_card_json(&identity.card_encoded());
        let sig_b64 = value["signature"].as_str().unwrap().to_string();
        let mut sig_bytes = BASE64.decode(&sig_b64).unwrap();
        sig_bytes[0] ^= 0xFF;
        value["signature"] = serde_json::Value::String(BASE64.encode(sig_bytes));
        let tampered = encode_card_json(&value);

        let result = SignedCard::parse_and_verify(&tampered);
        assert!(matches!(result, Err(CardError::SignatureInvalid)));
    }

    #[test]
    fn a_hand_built_legacy_shaped_card_is_rejected_as_legacy_unsigned() {
        let dir = tempdir().unwrap();
        let identity = make_identity(&dir, "id.json");
        let legacy = identity.public_card(); // today's exact shape: no version field

        let encoded = BASE64.encode(serde_json::to_vec(&legacy).unwrap());
        let result = SignedCard::parse_and_verify(&encoded);
        assert!(matches!(result, Err(CardError::LegacyUnsigned)));
    }

    #[test]
    fn a_version_3_card_yields_unsupported_version() {
        let dir = tempdir().unwrap();
        let identity = make_identity(&dir, "id.json");

        let mut value = decode_card_json(&identity.card_encoded());
        value["version"] = serde_json::Value::Number(3u8.into());
        let card = encode_card_json(&value);

        let result = SignedCard::parse_and_verify(&card);
        assert!(matches!(result, Err(CardError::UnsupportedVersion(3))));
    }

    #[test]
    fn garbage_base64_yields_not_base64() {
        let result = SignedCard::parse_and_verify("not valid base64 at all!!!");
        assert!(matches!(result, Err(CardError::NotBase64(_))));
    }

    #[test]
    fn garbage_json_yields_not_json() {
        let garbage = BASE64.encode(b"not json");
        let result = SignedCard::parse_and_verify(&garbage);
        assert!(matches!(result, Err(CardError::NotJson(_))));
    }

    #[test]
    fn check_card_against_pin_accepts_a_matching_x25519_key() {
        use crate::store::PinnedPeer;

        let dir = tempdir().unwrap();
        let identity = make_identity(&dir, "id.json");
        let verified = SignedCard::parse_and_verify(&identity.card_encoded()).unwrap();

        let pinned = PinnedPeer {
            label: "bob".to_string(),
            ed25519_pubkey: hex::encode(verified.ed25519_pubkey.as_bytes()),
            x25519_pubkey: hex::encode(verified.x25519_pubkey.to_bytes()),
            first_seen: 1_700_000_000,
        };

        assert!(check_card_against_pin(&verified, &pinned).is_ok());
    }

    #[test]
    fn check_card_against_pin_rejects_a_different_x25519_key_with_full_display_fields() {
        use crate::store::PinnedPeer;

        let dir = tempdir().unwrap();
        let identity = make_identity(&dir, "id.json");
        let other = make_identity(&dir, "other.json");
        let verified = SignedCard::parse_and_verify(&identity.card_encoded()).unwrap();

        let pinned = PinnedPeer {
            label: "bob".to_string(),
            ed25519_pubkey: hex::encode(verified.ed25519_pubkey.as_bytes()),
            // A different X25519 key on file than the card offers.
            x25519_pubkey: hex::encode(
                X25519PublicKey::from(&other.x25519_secret).to_bytes(),
            ),
            first_seen: 1_700_000_000,
        };

        let result = check_card_against_pin(&verified, &pinned);
        match result {
            Err(CardError::PinnedKeyConflict {
                label,
                ed25519_fingerprint,
                existing_x25519_display,
                offered_x25519_display,
            }) => {
                assert_eq!(label, "bob");
                assert_eq!(
                    ed25519_fingerprint,
                    format_fingerprint(&fingerprint_hex(&pinned.ed25519_pubkey))
                );
                assert_eq!(
                    existing_x25519_display,
                    format_fingerprint(&fingerprint_hex(&pinned.x25519_pubkey))
                );
                assert_eq!(
                    offered_x25519_display,
                    format_fingerprint(&fingerprint_hex(&hex::encode(
                        verified.x25519_pubkey.to_bytes()
                    )))
                );
                assert_ne!(existing_x25519_display, offered_x25519_display);
            }
            other => panic!("expected PinnedKeyConflict, got {other:?}"),
        }
    }

    #[test]
    fn absurd_m_cost_is_rejected_cleanly() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.keyfile.json");

        Identity::create(&path, "passphrase").unwrap();
        let mut raw: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        // u32::MAX KiB is ~4 TiB. If this weren't bounds-checked before allocating,
        // attempting to unlock would OOM the process instead of returning an error.
        raw["kdf"]["m_cost_kib"] = serde_json::json!(u32::MAX);
        fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();

        let result = Identity::unlock(&path, "passphrase");
        assert!(matches!(result, Err(IdentityError::Malformed(_))));
    }

    #[test]
    fn unsupported_keyfile_version_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.keyfile.json");

        Identity::create(&path, "passphrase").unwrap();
        let mut raw: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        raw["version"] = serde_json::json!(99u8);
        fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();

        let result = Identity::unlock(&path, "passphrase");
        assert!(matches!(result, Err(IdentityError::Malformed(_))));
    }

    #[test]
    fn unsupported_kdf_algorithm_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.keyfile.json");

        Identity::create(&path, "passphrase").unwrap();
        let mut raw: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        raw["kdf"]["algorithm"] = serde_json::json!("argon2i");
        fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();

        let result = Identity::unlock(&path, "passphrase");
        assert!(matches!(result, Err(IdentityError::Malformed(_))));
    }

    #[test]
    fn different_identities_have_different_keys() {
        let dir = tempdir().unwrap();
        let a = Identity::create(&dir.path().join("a.json"), "pw").unwrap();
        let b = Identity::create(&dir.path().join("b.json"), "pw").unwrap();

        assert_ne!(a.signing_key.verifying_key(), b.signing_key.verifying_key());
    }

    #[test]
    fn fingerprint_hex_is_deterministic_and_key_sensitive() {
        let dir = tempdir().unwrap();
        let a = Identity::create(&dir.path().join("a.json"), "pw").unwrap();
        let b = Identity::create(&dir.path().join("b.json"), "pw").unwrap();
        let a_key_hex = hex::encode(a.signing_key.verifying_key().as_bytes());
        let b_key_hex = hex::encode(b.signing_key.verifying_key().as_bytes());

        let fp_a1 = fingerprint_hex(&a_key_hex);
        let fp_a2 = fingerprint_hex(&a_key_hex);
        let fp_b = fingerprint_hex(&b_key_hex);

        assert_eq!(fp_a1, fp_a2);
        assert_ne!(fp_a1, fp_b);
        assert_eq!(fp_a1.len(), FINGERPRINT_HEX_LEN);
    }

    #[test]
    fn fingerprint_hex_is_not_a_slice_of_the_raw_key() {
        // Domain separation (SLICE-03.md D5): the fingerprint must be a hash, not a
        // prefix of the key itself, so it never coincides with the routing key or the
        // raw key's own leading bytes.
        let dir = tempdir().unwrap();
        let identity = Identity::create(&dir.path().join("a.json"), "pw").unwrap();
        let key_hex = hex::encode(identity.signing_key.verifying_key().as_bytes());

        let fp = fingerprint_hex(&key_hex);
        assert_ne!(fp, key_hex[..FINGERPRINT_HEX_LEN]);
    }

    #[test]
    fn fingerprint_hex_handles_malformed_input_without_panicking() {
        let fp = fingerprint_hex("not hex at all");
        assert_eq!(fp.len(), FINGERPRINT_HEX_LEN);
    }

    #[test]
    fn format_fingerprint_groups_in_fours() {
        let formatted = format_fingerprint("a1b2c3d4e5f60718293a");
        assert_eq!(formatted, "a1b2 c3d4 e5f6 0718 293a");
    }
}
