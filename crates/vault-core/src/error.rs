use thiserror::Error;
use vault_container::ContainerError;
use vault_crypto::CryptoError;
use vault_recovery::RecoveryError;
use vault_security::SecurityError;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("vault is locked")]
    Locked,
    #[error("authentication failed (wrong password or tampered header)")]
    AuthFailed,
    #[error("too many failed attempts; locked for {retry_in_secs}s")]
    LockedOut { retry_in_secs: u64 },
    #[error("recovery failed")]
    Recovery(#[from] RecoveryError),
    #[error("container error: {0}")]
    Container(#[from] ContainerError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("security error: {0}")]
    Security(#[from] SecurityError),
    #[error("integrity verification failed: {0}")]
    Integrity(&'static str),
    #[error("rollback detected: container generation is older than the last witnessed state")]
    RollbackDetected,
    #[error("object not found")]
    NotFound,
    #[error("operation refused by lockdown policy ({0})")]
    Refused(&'static str),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid input: {0}")]
    Invalid(&'static str),
    #[error("vault already exists at the target location")]
    AlreadyExists,
    #[error("crypto-erasure requires password confirmation")]
    EraseConfirmationRequired,
}
