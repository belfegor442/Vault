//! On-disk container layout.
//!
//! ```text
//! <vault-dir>/
//! ├── VAULTHDR              fixed 4096-byte plaintext header
//! ├── CURRENT               48-byte generation pointer (plaintext)
//! ├── manifest/
//! │   └── manifest-<gen>.bin   encrypted manifest snapshot per generation
//! ├── objects/
//! │   └── <xx>/<hex-id>        encrypted object blobs
//! ├── state/
//! │   ├── ctl.bin              machine-bound control state (throttle, rollback witness)
//! │   └── lockdown.json         persisted lockdown state (security events)
//! └── audit/
//!     └── audit.bin            encrypted, hash-chained security event log
//! ```
//!
//! Commit ordering (crash safety):
//! 1. write object blob (incomplete blobs are unreferenced orphans)
//! 2. write `manifest/manifest-<gen+1>.bin` via temp+fsync+rename
//! 3. write `CURRENT` via temp+fsync+rename
//!
//! A crash between any steps yields either the previous fully valid state or
//! the new fully valid state; orphan manifests/blobs are cleaned on open.

use std::path::{Path, PathBuf};

pub const HEADER_FILE: &str = "VAULTHDR";
pub const CURRENT_FILE: &str = "CURRENT";
pub const MANIFEST_DIR: &str = "manifest";
pub const OBJECTS_DIR: &str = "objects";
pub const STATE_DIR: &str = "state";
pub const AUDIT_DIR: &str = "audit";
pub const AUDIT_FILE: &str = "audit.bin";
pub const CONTROL_FILE: &str = "ctl.bin";

pub struct Layout {
    root: PathBuf,
}

impl Layout {
    pub fn new(root: &Path) -> Self {
        Self { root: root.to_path_buf() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn header(&self) -> PathBuf {
        self.root.join(HEADER_FILE)
    }

    pub fn current(&self) -> PathBuf {
        self.root.join(CURRENT_FILE)
    }

    pub fn manifest_dir(&self) -> PathBuf {
        self.root.join(MANIFEST_DIR)
    }

    pub fn manifest_file(&self, generation: u64) -> PathBuf {
        self.manifest_dir().join(format!("manifest-{:016}.bin", generation))
    }

    pub fn objects_dir(&self) -> PathBuf {
        self.root.join(OBJECTS_DIR)
    }

    /// Sharded object path: `objects/<first byte hex>/<hex id>`.
    pub fn object_file(&self, id: &[u8; 16]) -> PathBuf {
        let hex: String = id.iter().map(|b| format!("{:02x}", b)).collect();
        self.objects_dir()
            .join(&hex[..2])
            .join(&hex)
    }

    pub fn state_dir(&self) -> PathBuf {
        self.root.join(STATE_DIR)
    }

    pub fn control_file(&self) -> PathBuf {
        self.state_dir().join(CONTROL_FILE)
    }

    /// Persisted lockdown state (see `docs/threat-model.md` §Lockdown).
    pub fn lockdown_file(&self) -> PathBuf {
        self.state_dir().join("lockdown.json")
    }

    pub fn audit_dir(&self) -> PathBuf {
        self.root.join(AUDIT_DIR)
    }

    pub fn audit_file(&self) -> PathBuf {
        self.audit_dir().join(AUDIT_FILE)
    }

    /// Create the directory skeleton (idempotent).
    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(self.manifest_dir())?;
        std::fs::create_dir_all(self.objects_dir())?;
        std::fs::create_dir_all(self.state_dir())?;
        std::fs::create_dir_all(self.audit_dir())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_stable() {
        let l = Layout::new(Path::new("C:\\vault"));
        assert!(l.header().ends_with("VAULTHDR"));
        assert!(l.manifest_file(42).to_string_lossy().contains("manifest-0000000000000042.bin"));
        let obj = l.object_file(&[0xab; 16]);
        let s = obj.to_string_lossy().replace('\\', "/");
        assert!(s.ends_with("objects/ab/abababababababababababababababab"));
    }
}
