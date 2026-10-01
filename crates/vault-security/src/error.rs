use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("platform security error: {0}")]
    Platform(&'static str),
    #[error("platform security error: {0}")]
    PlatformBoxed(String),
    #[error("malformed security state: {0}")]
    Malformed(&'static str),
    #[error("i/o error")]
    Io(#[from] std::io::Error),
}
