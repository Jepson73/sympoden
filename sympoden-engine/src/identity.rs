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

use crate::error::IdentityError;
use crate::kdf::{self, Argon2Params, DerivedKeys, KEY_LEN, SALT_LEN};

const NONCE_LEN: usize = 12;
const SEALED_PLAINTEXT_LEN: usize = 32 /* ed25519 seed */ + 32 /* x25519 secret */;
const KEYFILE_VERSION: u8 = 1;

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

    /// The public identity card to share with a peer out-of-band.
    pub fn public_card(&self) -> PublicCard {
        PublicCard {
            ed25519_public: BASE64.encode(self.signing_key.verifying_key().to_bytes()),
            x25519_public: BASE64.encode(X25519PublicKey::from(&self.x25519_secret).to_bytes()),
        }
    }
}

impl PublicCard {
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
}
