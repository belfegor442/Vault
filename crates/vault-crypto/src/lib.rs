//! Vault cryptographic core.
//!
//! This crate contains **only** compositions of established, audited
//! primitives — no custom cryptographic constructions beyond the standard
//! STREAM composition of XChaCha20-Poly1305 documented in [`stream`].
//!
//! Primitives used:
//! * Argon2id (RFC 9106) — password → KEK
//! * HKDF-SHA256 (RFC 5869) — root key → domain keys
//! * XChaCha20-Poly1305 (RFC 8439 / libsodium) — AEAD for all encryption
//! * SHA-256 (FIPS 180-4) — content hashes and audit chain
//!
//! All randomness comes from the OS CSPRNG (`rand::rngs::OsRng`).

pub mod aead;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod keys;
pub mod stream;

pub use aead::{open, seal, Envelope, NONCE_LEN, TAG_LEN};
pub use error::CryptoError;
pub use hash::{sha256, Sha256Writer};
pub use kdf::{derive_kek, KdfParams, KDF_ARGON2ID};
pub use keys::{random_bytes, random_vec, DomainKeys, Key32, SecretBytes};
pub use stream::{open_stream, seal_stream, StreamStats, CHUNK_SIZE, NONCE_PREFIX_LEN};

/// Lowercase hex encoding (used for identifiers in state files; never for keys).
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn to_hex16(id: &[u8; 16]) -> String {
    to_hex(id)
}
