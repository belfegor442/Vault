use thiserror::Error;
use vault_crypto::CryptoError;

#[derive(Debug, Error)]
pub enum ContainerError {
    #[error("i/o error")]
    Io(#[from] std::io::Error),
    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("not a vault container: {0}")]
    BadMagic(&'static str),
    #[error("unsupported format version {found} (expected {expected})")]
    UnsupportedVersion { found: u16, expected: u16 },
    #[error("unsupported crypto suite {found} (expected {expected})")]
    UnsupportedSuite { found: u16, expected: u16 },
    #[error("malformed container structure: {0}")]
    Malformed(&'static str),
    #[error("vault id mismatch (container substitution detected)")]
    VaultIdMismatch,
    #[error("manifest generation mismatch")]
    GenerationMismatch,
    #[error("manifest hash chain broken")]
    ChainBroken,
}
