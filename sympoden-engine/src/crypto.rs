//! Signing/verification, content addressing, and the sealed-envelope transport
//! format used to carry a note through the blind relay.
//!
//! Sealing is age-style: a fresh, single-use X25519 keypair is generated per
//! envelope and ECDH'd against the recipient's static public key, so the derived
//! AEAD key is unique per message. This avoids the static-static ECDH key reuse
//! that would make a fixed/random 96-bit nonce dangerous.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::CryptoError;

const ENVELOPE_KEY_INFO: &[u8] = b"sympoden-v1-envelope-key";
const EPHEMERAL_PUBLIC_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// Sign a message with the identity's Ed25519 key.
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

/// Verify a message's Ed25519 signature.
pub fn verify(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    verifying_key
        .verify(message, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// SHA-256 content address of arbitrary bytes.
pub fn content_address(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// The relay routing key for a recipient: SHA-256 of their Ed25519 public key. The
/// relay only ever sees this hash, never the raw public key.
pub fn routing_key_for(ed25519_public: &VerifyingKey) -> [u8; 32] {
    content_address(ed25519_public.as_bytes())
}

/// An encrypted, opaque blob the relay can store and forward without reading it.
/// Carries no static sender key — only the plaintext inside (a signed note) proves
/// authorship; the envelope's only job is to get it there unread.
pub struct Envelope {
    pub ephemeral_x25519_public: [u8; EPHEMERAL_PUBLIC_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EPHEMERAL_PUBLIC_LEN + NONCE_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.ephemeral_x25519_public);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < EPHEMERAL_PUBLIC_LEN + NONCE_LEN {
            return Err(CryptoError::Malformed("envelope is too short".to_string()));
        }
        let mut ephemeral_x25519_public = [0u8; EPHEMERAL_PUBLIC_LEN];
        ephemeral_x25519_public.copy_from_slice(&bytes[..EPHEMERAL_PUBLIC_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[EPHEMERAL_PUBLIC_LEN..EPHEMERAL_PUBLIC_LEN + NONCE_LEN]);
        let ciphertext = bytes[EPHEMERAL_PUBLIC_LEN + NONCE_LEN..].to_vec();
        Ok(Self {
            ephemeral_x25519_public,
            nonce,
            ciphertext,
        })
    }
}

fn derive_envelope_key(shared_secret: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(ENVELOPE_KEY_INFO, key.as_mut())
        .map_err(|_| CryptoError::Malformed("hkdf expand failed".to_string()))?;
    Ok(key)
}

/// Seal `plaintext` for `their_x25519_public` using a fresh ephemeral keypair.
pub fn seal_for_recipient(
    plaintext: &[u8],
    their_x25519_public: &X25519PublicKey,
) -> Result<Envelope, CryptoError> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(their_x25519_public);

    let key = derive_envelope_key(shared.as_bytes())?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Malformed("encryption failed".to_string()))?;

    Ok(Envelope {
        ephemeral_x25519_public: ephemeral_public.to_bytes(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Open an envelope sealed for us with our X25519 static secret.
pub fn open_envelope(
    envelope: &Envelope,
    my_x25519_secret: &StaticSecret,
) -> Result<Vec<u8>, CryptoError> {
    let their_ephemeral = X25519PublicKey::from(envelope.ephemeral_x25519_public);
    let shared = my_x25519_secret.diffie_hellman(&their_ephemeral);

    let key = derive_envelope_key(shared.as_bytes())?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let nonce = Nonce::from_slice(&envelope.nonce);

    cipher
        .decrypt(nonce, envelope.ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let message = b"hello, sympoden";
        let signature = sign(&signing_key, message);

        assert!(verify(&signing_key.verifying_key(), message, &signature).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let signature = sign(&signing_key, b"original message");

        let result = verify(
            &signing_key.verifying_key(),
            b"tampered message",
            &signature,
        );
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let other_key = SigningKey::generate(&mut OsRng);
        let signature = sign(&signing_key, b"message");

        let result = verify(&other_key.verifying_key(), b"message", &signature);
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn seal_and_open_roundtrip() {
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_public = X25519PublicKey::from(&recipient_secret);

        let plaintext = b"a private note";
        let envelope = seal_for_recipient(plaintext, &recipient_public).unwrap();
        let opened = open_envelope(&envelope, &recipient_secret).unwrap();

        assert_eq!(opened, plaintext);
    }

    #[test]
    fn open_fails_with_wrong_recipient_key() {
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_public = X25519PublicKey::from(&recipient_secret);
        let wrong_secret = StaticSecret::random_from_rng(OsRng);

        let envelope = seal_for_recipient(b"a private note", &recipient_public).unwrap();
        let result = open_envelope(&envelope, &wrong_secret);

        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn envelope_bytes_never_contain_the_plaintext() {
        // envelope.to_bytes() is exactly what gets pushed to, and stored on, the
        // relay - direct evidence the relay never holds plaintext, not just that
        // decryption later succeeds.
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_public = X25519PublicKey::from(&recipient_secret);

        let secret_body = b"the eagle has landed at midnight";
        let envelope = seal_for_recipient(secret_body, &recipient_public).unwrap();
        let on_the_wire = envelope.to_bytes();

        assert!(
            !on_the_wire
                .windows(secret_body.len())
                .any(|window| window == secret_body)
        );
    }

    #[test]
    fn open_fails_on_tampered_ciphertext() {
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_public = X25519PublicKey::from(&recipient_secret);

        let mut envelope = seal_for_recipient(b"a private note", &recipient_public).unwrap();
        let last = envelope.ciphertext.len() - 1;
        envelope.ciphertext[last] ^= 0xFF;

        let result = open_envelope(&envelope, &recipient_secret);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn each_seal_uses_a_fresh_ephemeral_key_and_nonce() {
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_public = X25519PublicKey::from(&recipient_secret);

        let a = seal_for_recipient(b"same plaintext", &recipient_public).unwrap();
        let b = seal_for_recipient(b"same plaintext", &recipient_public).unwrap();

        assert_ne!(a.ephemeral_x25519_public, b.ephemeral_x25519_public);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn envelope_bytes_roundtrip() {
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_public = X25519PublicKey::from(&recipient_secret);

        let envelope = seal_for_recipient(b"a private note", &recipient_public).unwrap();
        let bytes = envelope.to_bytes();
        let parsed = Envelope::from_bytes(&bytes).unwrap();

        assert_eq!(
            envelope.ephemeral_x25519_public,
            parsed.ephemeral_x25519_public
        );
        assert_eq!(envelope.nonce, parsed.nonce);
        assert_eq!(envelope.ciphertext, parsed.ciphertext);

        let opened = open_envelope(&parsed, &recipient_secret).unwrap();
        assert_eq!(opened, b"a private note");
    }

    #[test]
    fn envelope_from_bytes_rejects_too_short_input() {
        let result = Envelope::from_bytes(&[0u8; 10]);
        assert!(matches!(result, Err(CryptoError::Malformed(_))));
    }

    #[test]
    fn content_address_is_deterministic_and_input_sensitive() {
        let a1 = content_address(b"hello");
        let a2 = content_address(b"hello");
        let b = content_address(b"hellp");

        assert_eq!(a1, a2);
        assert_ne!(a1, b);
    }

    #[test]
    fn routing_key_is_deterministic_per_public_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let a = routing_key_for(&signing_key.verifying_key());
        let b = routing_key_for(&signing_key.verifying_key());

        assert_eq!(a, b);
    }
}
