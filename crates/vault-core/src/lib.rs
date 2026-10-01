//! Vault core engine: sessions, key management, object model, commits.
//!
//! This crate wires the lower layers (crypto, container, storage, security,
//! recovery) into the restricted API consumed by front-ends (CLI / native UI).
//! It contains **no cryptographic constructions of its own** — only key
//! handling, protocol ordering and policy enforcement.

pub mod audit;
pub mod engine;
pub mod error;
pub mod types;

pub use audit::{AuditEvent, AuditLog};
pub use engine::{CreateOptions, VaultEngine};
pub use error::CoreError;
pub use types::*;
