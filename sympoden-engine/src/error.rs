use thiserror::Error;

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
    #[error(
        "a peer is already configured as \"{existing_label}\" - this slice supports only one peer"
    )]
    PeerAlreadyConfigured { existing_label: String },
    #[error(
        "\"{label}\" is already pinned to a different key - refusing to silently re-pin"
    )]
    PeerKeyMismatch { label: String },
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
