//! Crash-safe storage primitives for the Vault container.

pub mod atomic;

pub use atomic::{atomic_write, atomic_write_from, cleanup_temp_files, fault_point, read_file_capped};
