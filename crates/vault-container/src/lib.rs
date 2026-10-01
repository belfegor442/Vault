//! Vault container format: versioned, authenticated, tamper-evident.
//!
//! See `docs/container-format.md` for the full specification and
//! `docs/rollback.md` for generation/rollback semantics.

pub mod error;
pub mod header;
pub mod ids;
pub mod layout;
pub mod manifest;
pub mod object;

pub use error::ContainerError;
pub use header::{create_header_with_password, VaultHeader, FORMAT_VERSION, HEADER_SIZE};
pub use ids::{id_hex, new_id, parse_id_hex, Id};
pub use layout::Layout;
pub use manifest::{
    decode_current, encode_current, manifest_hash, FolderEntry, Manifest, ObjectEntry, ObjectMeta,
    ObjectType,
};
pub use object::{open_object, write_object, ObjectHeader, OBJECT_HEADER_SIZE};
