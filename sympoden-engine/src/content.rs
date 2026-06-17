//! The note: canonical encoding for signing/content-addressing, and the wire
//! representation that travels (encrypted) through the relay and is stored locally.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::ContentError;
use crate::store::StoredNote;

/// A signed, content-addressed text note — the only post type Slice 01 has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub author_pubkey: VerifyingKey,
    pub created_at: i64, // unix seconds
    pub body: String,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize)]
struct NoteWire {
    author_pubkey: String, // hex
    created_at: i64,
    body: String,
    signature: String, // hex
}

impl Note {
    /// Canonical bytes that get hashed (content address) and signed. Deliberately not
    /// JSON: field order/whitespace in a serialized format would make the signed
    /// bytes ambiguous, which would make signature verification fragile.
    fn canonical_bytes(author_pubkey: &VerifyingKey, created_at: i64, body: &str) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 8 + body.len());
        bytes.extend_from_slice(author_pubkey.as_bytes());
        bytes.extend_from_slice(&created_at.to_be_bytes());
        bytes.extend_from_slice(body.as_bytes());
        bytes
    }

    /// Create and sign a new note.
    pub fn new(signing_key: &SigningKey, body: String, created_at: i64) -> Self {
        let author_pubkey = signing_key.verifying_key();
        let canonical = Self::canonical_bytes(&author_pubkey, created_at, &body);
        let signature = crypto::sign(signing_key, &canonical);
        Self {
            author_pubkey,
            created_at,
            body,
            signature,
        }
    }

    /// SHA-256 content address of this note, hex-encoded.
    pub fn id_hex(&self) -> String {
        hex::encode(crypto::content_address(&Self::canonical_bytes(
            &self.author_pubkey,
            self.created_at,
            &self.body,
        )))
    }

    /// Verify this note's signature against its claimed author.
    pub fn verify(&self) -> Result<(), crate::error::CryptoError> {
        let canonical = Self::canonical_bytes(&self.author_pubkey, self.created_at, &self.body);
        crypto::verify(&self.author_pubkey, &canonical, &self.signature)
    }

    /// Serialize for transport inside an envelope (the envelope's encryption is what
    /// keeps this private from the relay — this is just a container format).
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, ContentError> {
        let wire = NoteWire {
            author_pubkey: hex::encode(self.author_pubkey.as_bytes()),
            created_at: self.created_at,
            body: self.body.clone(),
            signature: hex::encode(self.signature.to_bytes()),
        };
        serde_json::to_vec(&wire).map_err(|e| ContentError::Malformed(e.to_string()))
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ContentError> {
        let wire: NoteWire =
            serde_json::from_slice(bytes).map_err(|e| ContentError::Malformed(e.to_string()))?;
        Self::from_wire(wire)
    }

    pub fn to_stored(&self) -> StoredNote {
        StoredNote {
            id: self.id_hex(),
            author_pubkey: hex::encode(self.author_pubkey.as_bytes()),
            body: self.body.clone(),
            created_at: self.created_at,
            signature: hex::encode(self.signature.to_bytes()),
            synced_at: None,
        }
    }

    pub fn from_stored(stored: &StoredNote) -> Result<Self, ContentError> {
        Self::from_wire(NoteWire {
            author_pubkey: stored.author_pubkey.clone(),
            created_at: stored.created_at,
            body: stored.body.clone(),
            signature: stored.signature.clone(),
        })
    }

    fn from_wire(wire: NoteWire) -> Result<Self, ContentError> {
        let pubkey_bytes =
            hex::decode(&wire.author_pubkey).map_err(|e| ContentError::Malformed(e.to_string()))?;
        let pubkey_bytes: [u8; 32] = pubkey_bytes.try_into().map_err(|_| {
            ContentError::Malformed("author_pubkey has the wrong length".to_string())
        })?;
        let author_pubkey = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| ContentError::Malformed(e.to_string()))?;

        let sig_bytes =
            hex::decode(&wire.signature).map_err(|e| ContentError::Malformed(e.to_string()))?;
        let sig_bytes: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| ContentError::Malformed("signature has the wrong length".to_string()))?;
        let signature = Signature::from_bytes(&sig_bytes);

        Ok(Self {
            author_pubkey,
            created_at: wire.created_at,
            body: wire.body,
            signature,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn new_note_verifies() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let note = Note::new(&signing_key, "hello".to_string(), 1_700_000_000);

        assert!(note.verify().is_ok());
    }

    #[test]
    fn id_is_deterministic_and_content_sensitive() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let a = Note::new(&signing_key, "hello".to_string(), 1_700_000_000);
        let b = Note::new(&signing_key, "hello".to_string(), 1_700_000_000);
        let c = Note::new(&signing_key, "goodbye".to_string(), 1_700_000_000);

        assert_eq!(a.id_hex(), b.id_hex());
        assert_ne!(a.id_hex(), c.id_hex());
    }

    #[test]
    fn wire_bytes_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let note = Note::new(&signing_key, "hello, sympoden".to_string(), 1_700_000_000);

        let bytes = note.to_wire_bytes().unwrap();
        let parsed = Note::from_wire_bytes(&bytes).unwrap();

        assert_eq!(note, parsed);
        assert!(parsed.verify().is_ok());
    }

    #[test]
    fn stored_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let note = Note::new(&signing_key, "hello, sympoden".to_string(), 1_700_000_000);

        let stored = note.to_stored();
        assert_eq!(stored.id, note.id_hex());

        let parsed = Note::from_stored(&stored).unwrap();
        assert_eq!(note, parsed);
        assert!(parsed.verify().is_ok());
    }

    #[test]
    fn from_wire_bytes_rejects_garbage() {
        let result = Note::from_wire_bytes(b"not json");
        assert!(matches!(result, Err(ContentError::Malformed(_))));
    }

    #[test]
    fn verify_fails_if_body_tampered_after_signing() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut note = Note::new(&signing_key, "hello".to_string(), 1_700_000_000);
        note.body = "goodbye".to_string();

        assert!(note.verify().is_err());
    }
}
