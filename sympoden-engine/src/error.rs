use thiserror::Error;

use crate::store::PinnedPeer;

/// Errors from the `identity` module: keyfile creation, unlock, and persistence.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("a keyfile already exists at this path")]
    AlreadyExists,
    #[error("incorrect passphrase")]
    InvalidPassphrase,
    #[error("passphrase key derivation failed")]
    KeyDerivation,
    #[error("keyfile is malformed: {0}")]
    Malformed(String),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors from a `SignedCard`: parsing, structural validation, and signature
/// verification (`SignedCard::parse_and_verify`, SLICE-05.md D-D), plus the
/// pinned-key-conflict reject (`check_card_against_pin`, D-C). Every variant here is
/// reachable only *before* `Store::add_peer` is ever called - a card is fully verified
/// (and, if a pin already exists for its key, checked against it) before any write.
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

/// Errors from the `crypto` module: signing, verification, sealing, opening.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("envelope could not be decrypted (wrong key or tampered ciphertext)")]
    DecryptionFailed,
    #[error("malformed envelope or key material: {0}")]
    Malformed(String),
}

/// Errors from the `store` module: the local SQLCipher-encrypted database.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database could not be opened with the given key")]
    InvalidKey,
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("no pinned peer matches \"{query}\"")]
    UnknownPeerKey { query: String },
    #[error("\"{query}\" matches more than one pinned peer - specify by label#fingerprint")]
    AmbiguousPeerQuery {
        query: String,
        candidates: Vec<PinnedPeer>,
    },
}

/// Errors from the `content` module: parsing/validating a note's wire format.
#[derive(Debug, Error)]
pub enum ContentError {
    #[error("malformed note: {0}")]
    Malformed(String),
}

/// Errors from the `sync` module: composing a note into/out of a relay-bound
/// envelope, and talking to the relay over the network. Each variant wraps the
/// lower-level error that actually occurred.
#[derive(Debug, Error)]
pub enum SyncError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Content(#[from] ContentError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("relay error: {0}")]
    Relay(String),
}
