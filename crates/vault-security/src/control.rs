//! Persisted control state (`state/ctl.bin`).
//!
//! Contents are **integrity metadata only** — never secrets, never keys:
//!
//! * `vault_id` — binding target
//! * `failed_attempts` / `lockout_until_ms` — interactive throttle
//! * `max_seen_generation` / `seen_manifest_hash` — rollback witness
//! * `binary_hash` — tamper evidence for the executable
//! * `capability` — which protection level protects this file
//!
//! Protection levels:
//! 1. **DPAPI** (Windows): blob bound to user + machine + `vault_id` entropy.
//! 2. **Degraded**: plaintext JSON. Documented in the threat model: an
//!    attacker with file access can reset the throttle or the rollback
//!    witness; the primary offline defense remains Argon2id cost.
//!
//! Vault never silently claims the stronger level: `capability` records which
//! one was actually used at write time and is shown in the Security Center.

use serde::{Deserialize, Serialize};

use vault_storage::{atomic_write, read_file_capped};

use crate::error::SecurityError;
use crate::platform::{dpapi_protect, dpapi_unprotect};

pub const CAPABILITY_DPAPI: &str = "dpapi";
pub const CAPABILITY_DEGRADED: &str = "degraded";

const CONTROL_FORMAT: u32 = 1;
const MAX_CONTROL_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlState {
    pub format: u32,
    pub vault_id: String,
    pub failed_attempts: u32,
    pub lockout_until_ms: u64,
    pub max_seen_generation: u64,
    pub seen_manifest_hash: String,
    pub binary_hash: String,
    pub capability: String,
    pub updated_ms: u64,
    /// Crash witness: `true` while an object update has been written but the
    /// manifest commit has not completed. Cleared only after a successful
    /// commit (or a successful heal at next unlock).
    #[serde(default)]
    pub pending_commit: bool,
    /// Audit-chain anchor: number of records this witness has seen. A log
    /// with *fewer* records than the anchor has been truncated (suffix
    /// removal) and must raise `audit.chain_broken`. Lag (anchor < actual)
    /// is allowed: it only heals forward on the next save.
    #[serde(default)]
    pub audit_records: u64,
}

impl ControlState {
    pub fn new(vault_id_hex: &str, now_ms: u64, binary_hash_hex: &str) -> Self {
        Self {
            format: CONTROL_FORMAT,
            vault_id: vault_id_hex.to_string(),
            failed_attempts: 0,
            lockout_until_ms: 0,
            max_seen_generation: 0,
            seen_manifest_hash: String::new(),
            binary_hash: binary_hash_hex.to_string(),
            capability: CAPABILITY_DEGRADED.to_string(),
            updated_ms: now_ms,
            pending_commit: false,
            audit_records: 0,
        }
    }

    fn serialize(&self) -> Result<Vec<u8>, SecurityError> {
        serde_json::to_vec(self).map_err(|_| SecurityError::Malformed("control state serialize"))
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, SecurityError> {
        let s: Self = serde_json::from_slice(bytes)
            .map_err(|_| SecurityError::Malformed("control state is not valid JSON"))?;
        if s.format != CONTROL_FORMAT {
            return Err(SecurityError::Malformed("unsupported control state format"));
        }
        Ok(s)
    }

    /// Persist the state, preferring DPAPI when the platform supports it.
    ///
    /// Returns the capability actually used.
    pub fn save(&mut self, path: &std::path::Path, vault_id: &[u8; 16]) -> Result<String, SecurityError> {
        let mut state = self.clone();
        state.capability = CAPABILITY_DEGRADED.to_string();
        let plain = state.serialize()?;

        let protected = dpapi_protect(&plain, vault_id).map(|blob| {
            let mut tagged = Vec::with_capacity(blob.len() + 1);
            tagged.push(b'D'); // D = DPAPI-wrapped
            tagged.extend_from_slice(&blob);
            tagged
        });

        let (bytes, capability) = match protected {
            Ok(tagged) => (tagged, CAPABILITY_DPAPI.to_string()),
            Err(_) => {
                let mut tagged = Vec::with_capacity(plain.len() + 1);
                tagged.push(b'P'); // P = plaintext (degraded)
                tagged.extend_from_slice(&plain);
                (tagged, CAPABILITY_DEGRADED.to_string())
            }
        };
        atomic_write(path, &bytes)?;
        self.capability = capability.clone();
        Ok(capability)
    }

    /// Load the state. Returns `Ok(None)` when no file exists yet.
    pub fn load(path: &std::path::Path, vault_id: &[u8; 16]) -> Result<Option<Self>, SecurityError> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_file_capped(path, MAX_CONTROL_BYTES)?;
        if bytes.is_empty() {
            return Err(SecurityError::Malformed("empty control state"));
        }
        let (mut state, capability) = match bytes[0] {
            b'D' => {
                let plain = dpapi_unprotect(&bytes[1..], vault_id)?;
                (Self::deserialize(&plain)?, CAPABILITY_DPAPI.to_string())
            }
            b'P' => (Self::deserialize(&bytes[1..])?, CAPABILITY_DEGRADED.to_string()),
            _ => return Err(SecurityError::Malformed("unknown control state tag")),
        };
        // The wrapper tag is authoritative for which protection was used.
        state.capability = capability;
        if state.vault_id != vault_crypto::to_hex16(vault_id) {
            return Err(SecurityError::Malformed("control state belongs to another vault"));
        }
        Ok(Some(state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn save_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ctl.bin");
        let vid = [1u8; 16];
        let mut st = ControlState::new(&vault_crypto::to_hex16(&vid), 1000, "aabb");
        st.failed_attempts = 3;
        st.max_seen_generation = 7;
        let cap = st.save(&path, &vid).unwrap();
        assert!(cap == CAPABILITY_DPAPI || cap == CAPABILITY_DEGRADED);

        let loaded = ControlState::load(&path, &vid).unwrap().unwrap();
        assert_eq!(loaded.failed_attempts, 3);
        assert_eq!(loaded.max_seen_generation, 7);
        assert_eq!(loaded.capability, cap);
        assert_eq!(loaded.vault_id, vault_crypto::to_hex16(&vid));
    }

    #[test]
    fn wrong_vault_id_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ctl.bin");
        let mut st = ControlState::new(&vault_crypto::to_hex16(&[1u8; 16]), 0, "x");
        st.save(&path, &[1u8; 16]).unwrap();
        // In degraded mode the vault_id field check still applies; in DPAPI
        // mode the entropy check fails first. Either way it must error.
        assert!(ControlState::load(&path, &[2u8; 16]).is_err());
    }

    #[test]
    fn corrupted_file_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ctl.bin");
        let vid = [1u8; 16];
        let st = ControlState::new(&vault_crypto::to_hex16(&vid), 0, "x");
        let mut st = st;
        st.save(&path, &vid).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        assert!(ControlState::load(&path, &vid).is_err());
    }

    #[test]
    fn missing_file_is_none() {
        let dir = tempdir().unwrap();
        assert!(ControlState::load(&dir.path().join("nope"), &[0u8; 16]).unwrap().is_none());
    }
}
