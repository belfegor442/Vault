//! Recovery subsystem.
//!
//! Recovery material is **separate from the everyday unlock path**:
//!
//! * Unlock path: `password → Argon2id → KEK → root key` (interactive,
//!   expensive by design).
//! * Recovery path: `recovery key (256-bit CSPRNG) → HKDF → recovery KEK →
//!   root key` (no Argon2 — the input is already full-entropy).
//!
//! The recovery envelope lives in the vault header and wraps the **same**
//! root key, so recovery restores access to existing data with the existing
//! key hierarchy.
//!
//! Documented guarantees (see docs/recovery.md):
//!
//! | Question                                | Answer                                             |
//! |-----------------------------------------|----------------------------------------------------|
//! | What recovery CAN restore               | Full access to all vault data (root key)          |
//! | What recovery CAN NOT restore           | Lost/forgotten data; erased domains stay erased    |
//! | If recovery material is lost            | Password unlock still works; recovery unavailable  |
//! | Does recovery bypass authentication?    | Yes — possession of the recovery key IS proof      |
//! | Does recovery invalidate sessions?      | Yes — engine forces a lock + password re-wrap      |
//! | Can recovery silently weaken security?  | No — it never disables Argon2 for normal unlock    |

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use zeroize::{Zeroize, Zeroizing};

use vault_container::{VaultHeader, ContainerError};
use vault_crypto::{random_bytes, CryptoError, Key32, SecretBytes};

const RECOVERY_KEY_LEN: usize = 32;

/// A 256-bit recovery key. Zeroized on drop; never logged.
#[derive(Clone)]
pub struct RecoveryKey {
    bytes: [u8; RECOVERY_KEY_LEN],
}

impl Zeroize for RecoveryKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for RecoveryKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey([REDACTED])")
    }
}

impl RecoveryKey {
    pub fn generate() -> Self {
        Self { bytes: random_bytes() }
    }

    pub fn from_bytes(bytes: [u8; RECOVERY_KEY_LEN]) -> Self {
        Self { bytes }
    }

    pub fn as_key32(&self) -> Key32 {
        Key32::new(self.bytes)
    }

    /// Human-transcribable display form: base64 split into 8-char groups.
    ///
    /// Example: `MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=`
    /// rendered as `MDEyMzQ1-Njc4OWFi-Y2RlZjAx-MjM0NTY3-ODlhYmNk-ZWY=`.
    /// Decoding ignores `-` separators and rejects anything else.
    pub fn to_display(&self) -> String {
        let b64 = STANDARD.encode(self.bytes);
        let grouped: Vec<String> = b64
            .as_bytes()
            .chunks(8)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect();
        grouped.join("-")
    }

    /// Strictly parse a display-form recovery key.
    pub fn from_display(s: &str) -> Result<Self, CryptoError> {
        // A valid display form is ~50 chars (44 base64 + group dashes);
        // reject pathological inputs (e.g. megabyte pastes) before the
        // filter/collect below allocates anything.
        if s.len() > 1024 {
            return Err(CryptoError::Malformed("recovery key has invalid length"));
        }
        let cleaned: String = s
            .chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .collect();
        if cleaned.is_empty() || cleaned.len() > 64 {
            return Err(CryptoError::Malformed("recovery key has invalid length"));
        }
        if !cleaned
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            return Err(CryptoError::Malformed("recovery key contains invalid characters"));
        }
        let raw = Zeroizing::new(
            STANDARD
                .decode(&cleaned)
                .map_err(|_| CryptoError::Malformed("recovery key is not valid base64"))?,
        );
        if raw.len() != RECOVERY_KEY_LEN {
            return Err(CryptoError::Malformed("recovery key must decode to 32 bytes"));
        }
        let mut bytes = [0u8; RECOVERY_KEY_LEN];
        bytes.copy_from_slice(&raw);
        Ok(Self { bytes })
    }
}

/// Outcome of a recovery attempt — single error class so the UI cannot
/// distinguish "wrong recovery key" from "tampered recovery envelope".
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("recovery failed (invalid recovery key or tampered vault header)")]
    Invalid,
    #[error("this vault has no recovery material")]
    NotConfigured,
    #[error("container error: {0}")]
    Container(#[from] ContainerError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

/// Verify a recovery key against a header and return the unwrapped root key.
pub fn unlock_with_recovery(
    header: &VaultHeader,
    recovery_key: &RecoveryKey,
) -> Result<Key32, RecoveryError> {
    if !header.has_recovery() {
        return Err(RecoveryError::NotConfigured);
    }
    header
        .unwrap_root_with_recovery(&recovery_key.as_key32())
        .map_err(|_| RecoveryError::Invalid)
}

/// Prepare a password re-wrap after successful recovery.
///
/// Recovery must not leave the vault unlockable only by the recovery key:
/// the caller is required to choose a new master password immediately, and
/// the header is re-wrapped with it (the recovery envelope is re-sealed so it
/// keeps working for future emergencies).
pub fn finish_recovery(
    header: &mut VaultHeader,
    root_key: &Key32,
    new_password: &SecretBytes,
    new_kdf: vault_crypto::KdfParams,
) -> Result<(), RecoveryError> {
    header.rewrap_root(new_kdf, new_password, root_key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_container::create_header_with_password;
    use vault_crypto::kdf::{MIN_ITERATIONS, MIN_MEMORY_KIB};

    fn test_kdf() -> vault_crypto::KdfParams {
        vault_crypto::KdfParams {
            algorithm: 1,
            memory_kib: MIN_MEMORY_KIB,
            iterations: MIN_ITERATIONS,
            parallelism: 1,
            salt: [4u8; 32],
        }
    }

    #[test]
    fn display_roundtrip() {
        let rk = RecoveryKey::generate();
        let disp = rk.to_display();
        assert!(disp.contains('-'));
        let parsed = RecoveryKey::from_display(&disp).unwrap();
        assert_eq!(rk.bytes, parsed.bytes);
        // Whitespace-tolerant.
        let spaced = disp.replace('-', " - ");
        assert!(RecoveryKey::from_display(&spaced).is_ok());
    }

    #[test]
    fn display_rejects_garbage() {
        assert!(RecoveryKey::from_display("").is_err());
        assert!(RecoveryKey::from_display("not valid!!").is_err());
        assert!(RecoveryKey::from_display(&"A".repeat(100)).is_err());
        // Valid base64 but wrong length.
        let short = STANDARD.encode([0u8; 16]);
        assert!(RecoveryKey::from_display(&short).is_err());
    }

    #[test]
    fn recovery_unlocks_and_wrong_key_fails() {
        let pw = SecretBytes::from_str("master");
        let root = Key32::random();
        let rk = RecoveryKey::generate();
        let header =
            create_header_with_password(&pw, test_kdf(), &root, Some(&rk.as_key32()), 0, 1)
                .unwrap();
        let got = unlock_with_recovery(&header, &rk).unwrap();
        assert_eq!(root.as_bytes(), got.as_bytes());
        assert!(matches!(
            unlock_with_recovery(&header, &RecoveryKey::generate()),
            Err(RecoveryError::Invalid)
        ));
    }

    #[test]
    fn recovery_not_configured_is_distinct() {
        let pw = SecretBytes::from_str("master");
        let root = Key32::random();
        let header = create_header_with_password(&pw, test_kdf(), &root, None, 0, 1).unwrap();
        assert!(matches!(
            unlock_with_recovery(&header, &RecoveryKey::generate()),
            Err(RecoveryError::NotConfigured)
        ));
    }

    #[test]
    fn finish_recovery_rewraps_password_and_keeps_recovery() {
        let pw = SecretBytes::from_str("old");
        let root = Key32::random();
        let rk = RecoveryKey::generate();
        let mut header =
            create_header_with_password(&pw, test_kdf(), &root, Some(&rk.as_key32()), 0, 1)
                .unwrap();
        let new_pw = SecretBytes::from_str("new-master");
        finish_recovery(&mut header, &root, &new_pw, test_kdf()).unwrap();
        // Old password gone, new password works, recovery still works.
        assert!(header.unwrap_root(&pw).is_err());
        assert!(header.unwrap_root(&new_pw).is_ok());
        assert!(unlock_with_recovery(&header, &rk).is_ok());
    }
}
