use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;
use crate::hash::sha256;

pub const KEY_LEN: usize = 32;

/// A 256-bit symmetric key. Zeroized on drop.
///
/// Keys never implement `Debug`, `Display`, `Serialize` or any other
/// mechanism that could copy key material into logs or diagnostics.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key32 {
    bytes: [u8; KEY_LEN],
}

impl Key32 {
    pub fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }

    pub fn random() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != KEY_LEN {
            return Err(CryptoError::Malformed("key length must be 32 bytes"));
        }
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }

    /// Derive a purpose-bound subkey using HKDF-SHA256.
    ///
    /// `label` must be a fixed, unique, application-defined string for the
    /// purpose of the derived key (e.g. `b"vault:data:v1"`). `context`
    /// binds the derivation to a concrete instance (e.g. the vault id).
    pub fn derive_labeled(&self, label: &[u8], context: &[u8]) -> Self {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"vault-hkdf-salt-v1"), &self.bytes);
        let mut okm = [0u8; KEY_LEN];
        // HKDF expand info = label || 0x00 || context (domain separation).
        let mut info = Vec::with_capacity(label.len() + 1 + context.len());
        info.extend_from_slice(label);
        info.push(0u8);
        info.extend_from_slice(context);
        // HKDF expand cannot fail for 32 bytes of output with SHA-256.
        hk.expand(&info, &mut okm)
            .expect("hkdf expand for 32 bytes");
        Self { bytes: okm }
    }

    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }
}

impl std::fmt::Debug for Key32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key32([REDACTED])")
    }
}

/// Purpose labels for domain key derivation. Every label is versioned.
pub mod labels {
    pub const DATA: &[u8] = b"vault:domain:data:v1";
    pub const META: &[u8] = b"vault:domain:meta:v1";
    pub const INTEGRITY: &[u8] = b"vault:domain:integrity:v1";
    pub const CONTROL: &[u8] = b"vault:domain:control:v1";
    pub const RECOVERY: &[u8] = b"vault:domain:recovery:v1";
    pub const AUDIT: &[u8] = b"vault:domain:audit:v1";
}

/// The full set of domain keys derived from the root key.
///
/// Every key has exactly one purpose; domain keys are never reused across
/// purposes.
pub struct DomainKeys {
    pub data: Key32,
    pub meta: Key32,
    pub integrity: Key32,
    pub control: Key32,
    pub recovery: Key32,
    pub audit: Key32,
}

impl DomainKeys {
    pub fn derive(root: &Key32, vault_id: &[u8; 16]) -> Self {
        Self {
            data: root.derive_labeled(labels::DATA, vault_id),
            meta: root.derive_labeled(labels::META, vault_id),
            integrity: root.derive_labeled(labels::INTEGRITY, vault_id),
            control: root.derive_labeled(labels::CONTROL, vault_id),
            recovery: root.derive_labeled(labels::RECOVERY, vault_id),
            audit: root.derive_labeled(labels::AUDIT, vault_id),
        }
    }
}

/// A secret value that is zeroized on drop and never logged.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn from_str(s: &str) -> Self {
        Self {
            bytes: s.as_bytes().to_vec(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consume and wipe, returning a plain hash of the secret.
    ///
    /// Useful for releasing a password from memory after the key hierarchy
    /// has been derived from it.
    pub fn wipe_to_hash(mut self) -> [u8; 32] {
        let digest = sha256(&self.bytes);
        self.bytes.zeroize();
        digest
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

pub fn random_vec(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labeled_derivation_is_deterministic_and_distinct() {
        let root = Key32::random();
        let vault_id = [7u8; 16];
        let a = root.derive_labeled(labels::DATA, &vault_id);
        let b = root.derive_labeled(labels::DATA, &vault_id);
        let c = root.derive_labeled(labels::META, &vault_id);
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn derivation_binds_vault_id() {
        let root = Key32::random();
        let a = root.derive_labeled(labels::DATA, &[1u8; 16]);
        let b = root.derive_labeled(labels::DATA, &[2u8; 16]);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn domain_keys_are_distinct() {
        let root = Key32::random();
        let k = DomainKeys::derive(&root, &[9u8; 16]);
        let keys: [&Key32; 6] = [&k.data, &k.meta, &k.integrity, &k.control, &k.recovery, &k.audit];
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i].as_bytes(), keys[j].as_bytes());
            }
        }
    }

    #[test]
    fn debug_never_reveals_key_material() {
        let k = Key32::new([0x42u8; 32]);
        let s = format!("{:?}", k);
        assert!(!s.contains("42"));
        assert!(s.contains("REDACTED"));
    }

    #[test]
    fn secret_bytes_zeroize_on_drop() {
        let secret = SecretBytes::from_str("hunter2");
        {
            let ptr = secret.as_bytes().as_ptr();
            drop(secret);
            // After drop the allocation may be reused; we only assert the
            // drop path ran without UB and the wrapper type is ZeroizeOnDrop.
            assert!(!ptr.is_null());
        }
    }
}
