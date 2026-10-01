use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::error::CryptoError;
use crate::keys::{random_bytes, Key32};

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

/// Seal with XChaCha20-Poly1305.
///
/// Output layout: `nonce(24) || ciphertext || tag(16)`.
/// The nonce is generated from the OS CSPRNG for every call; XChaCha20 has a
/// 192-bit nonce space so random nonces are safe (collision bound 2^-96).
pub fn seal(key: &Key32, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("32-byte key");
    let nonce_bytes: [u8; NONCE_LEN] = random_bytes();
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("xchacha20poly1305 encryption cannot fail for non-empty key");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

/// Open (decrypt + verify) a sealed blob. Any authentication failure,
/// malformed input, or AAD mismatch maps to `AuthFailed`.
pub fn open(key: &Key32, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::Malformed("sealed blob too short"));
    }
    let (nonce, rest) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| CryptoError::Malformed("bad key length"))?;
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: rest,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)
}

/// Fixed-size envelope wrapping exactly 32 bytes of key material.
///
/// Layout on the wire: `nonce(24) || ciphertext(48)`.
pub struct Envelope {
    pub bytes: [u8; NONCE_LEN + 32 + TAG_LEN],
}

impl Envelope {
    pub fn zeroed() -> Self {
        Self {
            bytes: [0u8; NONCE_LEN + 32 + TAG_LEN],
        }
    }

    pub fn is_zeroed(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }

    pub fn wrap(key: &Key32, aad: &[u8], secret: &Key32) -> Self {
        let sealed = seal(key, aad, secret.as_bytes());
        let mut bytes = [0u8; NONCE_LEN + 32 + TAG_LEN];
        bytes.copy_from_slice(&sealed);
        Self { bytes }
    }

    pub fn unwrap(&self, key: &Key32, aad: &[u8]) -> Result<Key32, CryptoError> {
        let plain = open(key, aad, &self.bytes)?;
        if plain.len() != 32 {
            return Err(CryptoError::Malformed("envelope payload must be 32 bytes"));
        }
        Key32::from_slice(&plain)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = Key32::random();
        let sealed = seal(&key, b"aad", b"hello world");
        let out = open(&key, b"aad", &sealed).unwrap();
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&Key32::random(), b"aad", b"secret");
        assert!(open(&Key32::random(), b"aad", &sealed).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = Key32::random();
        let sealed = seal(&key, b"aad-1", b"secret");
        assert!(open(&key, b"aad-2", &sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = Key32::random();
        let mut sealed = seal(&key, b"aad", b"secret data");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open(&key, b"aad", &sealed).is_err());
    }

    #[test]
    fn truncation_fails() {
        let key = Key32::random();
        let sealed = seal(&key, b"", b"secret data");
        assert!(open(&key, b"", &sealed[..sealed.len() - 1]).is_err());
        assert!(open(&key, b"", &sealed[..10]).is_err());
    }

    #[test]
    fn nonces_are_unique() {
        let key = Key32::random();
        let a = seal(&key, b"", b"same plaintext");
        let b = seal(&key, b"", b"same plaintext");
        assert_ne!(&a[..NONCE_LEN], &b[..NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let key = Key32::random();
        let sealed = seal(&key, b"aad", b"");
        assert_eq!(open(&key, b"aad", &sealed).unwrap(), b"");
    }

    #[test]
    fn envelope_roundtrip_and_tamper() {
        let kek = Key32::random();
        let root = Key32::random();
        let env = Envelope::wrap(&kek, b"hdr", &root);
        let recovered = env.unwrap(&kek, b"hdr").unwrap();
        assert_eq!(root.as_bytes(), recovered.as_bytes());
        let mut bad = Envelope::wrap(&kek, b"hdr", &root);
        bad.bytes[0] ^= 1;
        assert!(bad.unwrap(&kek, b"hdr").is_err());
        assert!(env.unwrap(&kek, b"other-hdr").is_err());
    }

    #[test]
    fn malformed_inputs_rejected() {
        let key = Key32::random();
        assert!(open(&key, b"", &[0u8; 5]).is_err());
        assert!(open(&key, b"", &[]).is_err());
    }
}
