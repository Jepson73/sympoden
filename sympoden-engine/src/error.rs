use thiserror::Error;

/// Errors from the `identity` module: keyfile creation, unlock, and persistence.
#[derive(Debug, Error)]
pub enum IdentityError {
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
