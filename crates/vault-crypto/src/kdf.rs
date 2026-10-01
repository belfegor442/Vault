use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::keys::{Key32, SecretBytes};

/// Argon2id — the only password KDF accepted by Vault.
pub const KDF_ARGON2ID: u16 = 1;

/// OWASP minimum for Argon2id (m=19456 KiB, t=2, p=1).
pub const MIN_MEMORY_KIB: u32 = 19_456;
pub const MIN_ITERATIONS: u32 = 2;
pub const MIN_PARALLELISM: u32 = 1;
/// Refuse absurd values that would only be used to wedge the process.
pub const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024; // 4 GiB
pub const MAX_ITERATIONS: u32 = 32;
pub const MAX_PARALLELISM: u32 = 64;

pub const DEFAULT_MEMORY_KIB: u32 = 65_536; // 64 MiB
pub const DEFAULT_ITERATIONS: u32 = 3;
pub const DEFAULT_PARALLELISM: u32 = 1;

/// Versioned, serializable KDF parameters. Stored in the plaintext header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    pub algorithm: u16,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: [u8; 32],
}

impl KdfParams {
    pub fn production() -> Self {
        Self {
            algorithm: KDF_ARGON2ID,
            memory_kib: DEFAULT_MEMORY_KIB,
            iterations: DEFAULT_ITERATIONS,
            parallelism: DEFAULT_PARALLELISM,
            salt: crate::keys::random_bytes(),
        }
    }

    /// Enforce documented floors. Parameters below these floors are
    /// rejected — Vault never silently accepts weak KDF settings.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.algorithm != KDF_ARGON2ID {
            return Err(CryptoError::InvalidKdfParams("unknown kdf algorithm"));
        }
        if self.memory_kib < MIN_MEMORY_KIB {
            return Err(CryptoError::InvalidKdfParams("memory below security floor"));
        }
        if self.memory_kib > MAX_MEMORY_KIB {
            return Err(CryptoError::InvalidKdfParams("memory unreasonably large"));
        }
        if self.iterations < MIN_ITERATIONS {
            return Err(CryptoError::InvalidKdfParams("time cost below security floor"));
        }
        if self.iterations > MAX_ITERATIONS {
            return Err(CryptoError::InvalidKdfParams("time cost unreasonably large"));
        }
        if self.parallelism < MIN_PARALLELISM || self.parallelism > MAX_PARALLELISM {
            return Err(CryptoError::InvalidKdfParams("parallelism out of range"));
        }
        Ok(())
    }
}

/// Derive the password-based key-encryption key (KEK) with Argon2id.
///
/// The KEK never encrypts user data directly; it only unwraps the root key.
pub fn derive_kek(password: &SecretBytes, params: &KdfParams) -> Result<Key32, CryptoError> {
    params.validate()?;
    let argon_params = argon2::Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| CryptoError::InvalidKdfParams("argon2 rejected parameters"))?;
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &params.salt, &mut out)
        .map_err(|_| CryptoError::KdfFailed)?;
    let key = Key32::new(out);
    out.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> KdfParams {
        KdfParams {
            algorithm: KDF_ARGON2ID,
            memory_kib: MIN_MEMORY_KIB,
            iterations: MIN_ITERATIONS,
            parallelism: 1,
            salt: [3u8; 32],
        }
    }

    #[test]
    fn weak_params_are_rejected() {
        let mut p = test_params();
        p.memory_kib = MIN_MEMORY_KIB - 1;
        assert!(p.validate().is_err());
        let mut p = test_params();
        p.iterations = 1;
        assert!(p.validate().is_err());
        let mut p = test_params();
        p.algorithm = 999;
        assert!(p.validate().is_err());
    }

    #[test]
    fn production_params_are_valid() {
        assert!(KdfParams::production().validate().is_ok());
    }

    #[test]
    fn derive_is_deterministic() {
        let pw = SecretBytes::from_str("correct horse battery staple");
        let p = test_params();
        let a = derive_kek(&pw, &p).unwrap();
        let b = derive_kek(&pw, &p).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_password_gives_different_key() {
        let p = test_params();
        let a = derive_kek(&SecretBytes::from_str("password-one"), &p).unwrap();
        let b = derive_kek(&SecretBytes::from_str("password-two"), &p).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_salt_gives_different_key() {
        let pw = SecretBytes::from_str("same password");
        let mut p = test_params();
        let a = derive_kek(&pw, &p).unwrap();
        p.salt[0] ^= 0xff;
        let b = derive_kek(&pw, &p).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
