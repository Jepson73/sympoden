//! Passphrase key derivation shared by `identity` (seals the keyfile) and `store`
//! (keys the SQLCipher database). One Argon2id pass produces a master key; HKDF-SHA256
//! expand with distinct labels then splits it into independent, domain-separated keys
//! so the same master key is never used directly as two different kinds of key.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::IdentityError;

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

const KEYFILE_SEAL_INFO: &[u8] = b"sympoden-v1-keyfile-seal";
const DB_KEY_INFO: &[u8] = b"sympoden-v1-db-key";

/// Argon2id parameters, persisted in the keyfile so they can be tuned later without
/// breaking existing keyfiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Params {
    /// OWASP-recommended Argon2id defaults: 19 MiB memory, 2 iterations, 1 thread.
    fn default() -> Self {
        Self {
            m_cost_kib: Params::DEFAULT_M_COST,
            t_cost: Params::DEFAULT_T_COST,
            p_cost: Params::DEFAULT_P_COST,
        }
    }
}

pub struct DerivedKeys {
    /// Seals/unseals the identity keyfile's secret key material.
    pub keyfile_seal_key: Zeroizing<[u8; KEY_LEN]>,
    /// Keys the local SQLCipher database.
    pub db_key: Zeroizing<[u8; KEY_LEN]>,
}

/// Derive both downstream keys from a passphrase and salt. Wrong passphrase is
/// indistinguishable from a correct one at this stage — only the data each key
/// unlocks reveals whether it was right.
pub fn derive_keys(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    params: Argon2Params,
) -> Result<DerivedKeys, IdentityError> {
    let argon2_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| IdentityError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut master = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, master.as_mut())
        .map_err(|_| IdentityError::KeyDerivation)?;

    let hkdf =
        Hkdf::<Sha256>::from_prk(master.as_ref()).map_err(|_| IdentityError::KeyDerivation)?;

    let mut keyfile_seal_key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(KEYFILE_SEAL_INFO, keyfile_seal_key.as_mut())
        .map_err(|_| IdentityError::KeyDerivation)?;

    let mut db_key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(DB_KEY_INFO, db_key.as_mut())
        .map_err(|_| IdentityError::KeyDerivation)?;

    Ok(DerivedKeys {
        keyfile_seal_key,
        db_key,
    })
}
