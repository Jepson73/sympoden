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
    /// RFC 9106 §4's second recommended option (for when 2 GiB isn't assumed
    /// available): 64 MiB memory, 3 iterations, 4 lanes. This is a desktop-app
    /// profile, not a resource-constrained one — sympoden runs on the user's own
    /// machine, not a shared server budgeting memory across many concurrent logins —
    /// so we pick RFC 9106's stronger-than-OWASP-minimum option over the lighter
    /// 19 MiB profile previously used here.
    ///
    /// This only changes params for *newly created* keyfiles (`Identity::create`);
    /// existing keyfiles carry their own `kdf.{m_cost_kib,t_cost,p_cost}` and are
    /// unaffected. 65536/3/4 sits comfortably inside the
    /// `[M_COST_KIB_FLOOR, M_COST_KIB_CEILING]` / `[T_COST_FLOOR, T_COST_CEILING]` /
    /// `[P_COST_FLOOR, P_COST_CEILING]` bounds enforced in `identity.rs::unlock`.
    fn default() -> Self {
        Self {
            m_cost_kib: 65536,
            t_cost: 3,
            p_cost: 4,
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
