//! Encrypted, hash-chained security audit log (`audit/audit.bin`).
//!
//! Record layout:
//!
//! ```text
//! record := u32_le(len) || sealed
//! sealed := AEAD(audit_key, aad, json_event)
//! aad    := seq(u64_le) || prev_record_hash(32)
//! prev_record_hash := sha256(previous record bytes) | 0^32 for seq 0
//! ```
//!
//! Properties:
//! * Confidentiality: events are encrypted with the audit domain key.
//! * Tamper evidence: removing, reordering or modifying any record breaks
//!   the chain at verification time (AAD binds seq + previous hash).
//! * Append-only by construction: the file is only ever extended. Removal of
//!   a *suffix* of whole records is invisible to the chain itself and is
//!   detected by the record-count anchor in control state
//!   (`ControlState::audit_records`, checked at unlock); mid-record truncation
//!   fails chain verification directly.
//!
//! Events must never contain secrets — callers are responsible for passing
//! only event names, component names, results and non-sensitive details.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use vault_crypto::{open, seal, sha256, Key32};
use vault_storage::{atomic_write_from, read_file_capped};

use crate::error::CoreError;

/// Hard cap for the audit log (hostile input guard for the read-all paths).
const MAX_AUDIT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub seq: u64,
    pub timestamp_ms: u64,
    pub event: String,
    pub component: String,
    pub result: String,
    pub detail: String,
}

pub struct AuditLog {
    path: PathBuf,
    key: Key32,
    next_seq: u64,
    last_hash: [u8; 32],
    cached_events: Option<Vec<AuditEvent>>,
}

impl AuditLog {
    /// Open (or create) the log. Verifies the existing chain immediately so
    /// tampering is detected at unlock time, not later.
    pub fn open(path: &Path, key: Key32) -> Result<Self, CoreError> {
        let mut log = Self {
            path: path.to_path_buf(),
            key,
            next_seq: 0,
            last_hash: [0u8; 32],
            cached_events: None,
        };
        let (events, last_hash) = log.read_and_verify()?;
        log.next_seq = events.len() as u64;
        log.last_hash = last_hash;
        log.cached_events = Some(events);
        Ok(log)
    }

    /// Number of records currently in the chain (the control-state anchor
    /// value; see `ControlState::audit_records`).
    pub fn record_count(&self) -> u64 {
        self.next_seq
    }

    pub fn append(&mut self, timestamp_ms: u64, event: &str, component: &str, result: &str, detail: &str) -> Result<u64, CoreError> {
        if event.len() > 128 || component.len() > 64 || result.len() > 32 || detail.len() > 512 {
            return Err(CoreError::Invalid("audit field too long"));
        }
        let seq = self.next_seq;
        let ev = AuditEvent {
            seq,
            timestamp_ms,
            event: event.to_string(),
            component: component.to_string(),
            result: result.to_string(),
            detail: detail.to_string(),
        };
        let json = serde_json::to_vec(&ev).map_err(|_| CoreError::Invalid("audit serialize"))?;
        let mut aad = Vec::with_capacity(40);
        aad.extend_from_slice(&seq.to_le_bytes());
        aad.extend_from_slice(&self.last_hash);
        let sealed = seal(&self.key, &aad, &json);

        let mut record = Vec::with_capacity(4 + sealed.len());
        record.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        record.extend_from_slice(&sealed);

        // Append is implemented as read-all + atomic replace: the log is
        // small (security events) and atomic replacement keeps crash safety.
        let mut full = match read_file_capped(&self.path, MAX_AUDIT_BYTES) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        full.extend_from_slice(&record);
        atomic_write_from(&self.path, |f| f.write_all(&full))?;

        self.last_hash = sha256(&record);
        self.next_seq = seq + 1;
        if let Some(cache) = self.cached_events.as_mut() {
            cache.push(ev);
        }
        Ok(seq)
    }

    /// Re-seal an existing log under a new key (domain rekey).
    ///
    /// The chain structure (seq / prev-hash AADs) is preserved byte-for-byte
    /// in layout; only the sealed payloads change. The chain is first
    /// verified under `old_key`, so tampering is caught before migration.
    pub fn rekey(path: &Path, old_key: &Key32, new_key: &Key32) -> Result<(), CoreError> {
        let old = Self {
            path: path.to_path_buf(),
            key: old_key.clone(),
            next_seq: 0,
            last_hash: [0u8; 32],
            cached_events: None,
        };
        let (events, _) = old.read_and_verify()?;
        let mut full = Vec::new();
        let mut prev_hash = [0u8; 32];
        for ev in &events {
            let seq = ev.seq;
            let json = serde_json::to_vec(ev).map_err(|_| CoreError::Invalid("audit serialize"))?;
            let mut aad = Vec::with_capacity(40);
            aad.extend_from_slice(&seq.to_le_bytes());
            aad.extend_from_slice(&prev_hash);
            let sealed = seal(new_key, &aad, &json);
            let mut record = Vec::with_capacity(4 + sealed.len());
            record.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
            record.extend_from_slice(&sealed);
            prev_hash = sha256(&record);
            full.extend_from_slice(&record);
        }
        atomic_write_from(path, |f| f.write_all(&full))?;
        Ok(())
    }

    pub fn events(&mut self) -> Result<Vec<AuditEvent>, CoreError> {
        if self.cached_events.is_none() {
            let (events, last_hash) = self.read_and_verify()?;
            self.last_hash = last_hash;
            self.cached_events = Some(events);
        }
        Ok(self.cached_events.clone().unwrap_or_default())
    }

    pub fn recent(&mut self, limit: usize) -> Result<Vec<AuditEvent>, CoreError> {
        let events = self.events()?;
        let start = events.len().saturating_sub(limit);
        Ok(events[start..].to_vec())
    }

    /// Verify the whole chain. Returns the events plus the hash of the final
    /// record (the chain tip a subsequent append must chain from).
    fn read_and_verify(&self) -> Result<(Vec<AuditEvent>, [u8; 32]), CoreError> {
        let bytes = match read_file_capped(&self.path, MAX_AUDIT_BYTES) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), [0u8; 32])),
            Err(e) => return Err(e.into()),
        };
        let mut events = Vec::new();
        let mut pos = 0usize;
        let mut prev_hash = [0u8; 32];
        let mut expect_seq: u64 = 0;
        while pos < bytes.len() {
            if pos + 4 > bytes.len() {
                return Err(CoreError::Integrity("audit record length truncated"));
            }
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            if len == 0 || len > 64 * 1024 {
                return Err(CoreError::Integrity("audit record length invalid"));
            }
            let end = pos
                .checked_add(4 + len)
                .ok_or(CoreError::Integrity("audit length overflow"))?;
            if end > bytes.len() {
                return Err(CoreError::Integrity("audit record truncated"));
            }
            let record = &bytes[pos..end];
            let sealed = &record[4..];

            let mut aad = Vec::with_capacity(40);
            aad.extend_from_slice(&expect_seq.to_le_bytes());
            aad.extend_from_slice(&prev_hash);
            let json = open(&self.key, &aad, sealed)
                .map_err(|_| CoreError::Integrity("audit chain authentication failed"))?;
            let ev: AuditEvent = serde_json::from_slice(&json)
                .map_err(|_| CoreError::Integrity("audit event malformed"))?;
            if ev.seq != expect_seq {
                return Err(CoreError::Integrity("audit sequence mismatch"));
            }
            prev_hash = sha256(record);
            events.push(ev);
            expect_seq += 1;
            pos = end;
        }
        Ok((events, prev_hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn log_at(dir: &Path, key: Key32) -> AuditLog {
        AuditLog::open(&dir.join("audit.bin"), key).unwrap()
    }

    #[test]
    fn append_and_read_roundtrip() {
        let dir = tempdir().unwrap();
        let mut log = log_at(dir.path(), Key32::random());
        log.append(1, "vault.unlock", "core", "ok", "").unwrap();
        log.append(2, "object.import", "core", "ok", "size=10").unwrap();
        let events = log.events().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, "vault.unlock");
        assert_eq!(events[1].detail, "size=10");
    }

    #[test]
    fn chain_survives_reopen() {
        let dir = tempdir().unwrap();
        let key = Key32::random();
        {
            let mut log = log_at(dir.path(), key.clone());
            log.append(1, "a", "c", "ok", "").unwrap();
            log.append(2, "b", "c", "ok", "").unwrap();
        }
        let mut log = log_at(dir.path(), key.clone());
        assert_eq!(log.events().unwrap().len(), 2);
        log.append(3, "c", "c", "ok", "").unwrap();
        drop(log);
        let mut log = log_at(dir.path(), key);
        let events = log.events().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[2].seq, 2);
    }

    #[test]
    fn tampered_event_detected() {
        let dir = tempdir().unwrap();
        let key = Key32::random();
        {
            let mut log = log_at(dir.path(), key.clone());
            log.append(1, "a", "c", "ok", "").unwrap();
            log.append(2, "b", "c", "ok", "").unwrap();
        }
        let path = dir.path().join("audit.bin");
        let mut bytes = std::fs::read(&path).unwrap();
        // Flip a byte inside the first sealed payload.
        let flip_at = 4 + 10;
        bytes[flip_at] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        // Reopen with the *same* key: mutation must break verification.
        assert!(AuditLog::open(&path, key).is_err());
    }

    #[test]
    fn truncated_log_detected() {
        let dir = tempdir().unwrap();
        let key = Key32::random();
        {
            let mut log = log_at(dir.path(), key.clone());
            log.append(1, "a", "c", "ok", "").unwrap();
            log.append(2, "b", "c", "ok", "").unwrap();
        }
        let path = dir.path().join("audit.bin");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.truncate(bytes.len() - 8);
        std::fs::write(&path, &bytes).unwrap();
        assert!(AuditLog::open(&path, key.clone()).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let dir = tempdir().unwrap();
        {
            let mut log = log_at(dir.path(), Key32::random());
            log.append(1, "a", "c", "ok", "").unwrap();
        }
        assert!(AuditLog::open(&dir.path().join("audit.bin"), Key32::random()).is_err());
    }

    #[test]
    fn oversized_fields_rejected() {
        let dir = tempdir().unwrap();
        let mut log = log_at(dir.path(), Key32::random());
        assert!(log.append(1, &"x".repeat(200), "c", "ok", "").is_err());
        assert!(log.append(1, "ok", "c", "ok", &"y".repeat(1000)).is_err());
    }
}
