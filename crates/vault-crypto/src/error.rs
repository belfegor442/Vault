use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("key derivation failed")]
    KdfFailed,
    #[error("invalid KDF parameters: {0}")]
    InvalidKdfParams(&'static str),
    #[error("authentication failed (wrong key or tampered data)")]
    AuthFailed,
    #[error("malformed cryptographic material: {0}")]
    Malformed(&'static str),
    #[error("stream integrity violation: {0}")]
    StreamIntegrity(&'static str),
    #[error("random number generation failed")]
    Rng,
    #[error("i/o error during cryptographic operation")]
    Io(#[from] std::io::Error),
}
