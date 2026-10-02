//! Vault engine: sessions, authentication, object model, commits, integrity.
//!
//! Layering (see docs/architecture.md):
//!
//! ```text
//! front-end (CLI / native UI)
//!        │  restricted API (this module)
//!        ▼
//!  VaultEngine ── Session (keys, zeroized on lock)
//!        │
//!   ┌────┼──────────┬─────────────┐
//!   ▼    ▼          ▼             ▼
//! header  manifest  object blobs  audit log   (vault-container)
//!   │        │          │            │
//!   └────────┴──────────┴────────────┘
//!            vault-storage (atomic writes)
//!            vault-security (lockdown, DPAPI)
//! ```
//!
//! Commit protocol (crash safety): objects are written **before** the
//! manifest commit; `manifest-N.bin` is written **before** `CURRENT`.
//! An interruption at any point leaves the previous valid state, the new
//! valid state, or an orphan that is garbage-collected at next open.
//! Interrupted *updates* are healed from the newer blob via the
//! `pending_commit` witness in control state.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use vault_container::{
    create_header_with_password, decode_current, encode_current, manifest_hash, new_id,
    write_object, FolderEntry, Id, Layout, Manifest, ObjectEntry, ObjectHeader, ObjectMeta,
    ObjectType, VaultHeader, OBJECT_HEADER_SIZE,
};
use vault_crypto::{DomainKeys, KdfParams, Key32, SecretBytes, Sha256Writer};
use vault_recovery::RecoveryKey;
use vault_security::{
    probe_capabilities, Action, ControlState, Lockdown, LockdownRecord, PlatformCapability,
    Trigger, VaultState,
};
use vault_storage::{atomic_write, atomic_write_from, cleanup_temp_files, fault_point};

use crate::audit::{AuditEvent, AuditLog};
use crate::error::CoreError;
use crate::types::*;

const APP_VERSION: u64 = 0x0000_0001_0000_0000; // 1.0.0
const MAX_INLINE_READ: u64 = 64 * 1024 * 1024; // 64 MiB cap for note/text reads
const MAX_ATTEMPTS_BEFORE_LOCKOUT: u32 = 5;
const BASE_LOCKOUT_MS: u64 = 300_000;
const MAX_LOCKOUT_MS: u64 = 3_600_000;

/// Lockout delay for a failed-attempt count: 5 m · 2^(n−5), capped at 1 h.
/// Returns `None` while the count is still below the lockout threshold.
fn lockout_delay_ms(failed_attempts: u32) -> Option<u64> {
    let steps = failed_attempts.checked_sub(MAX_ATTEMPTS_BEFORE_LOCKOUT)?;
    // Exponent capped at 6 so the 1 h cap (not the exponent) governs; the
    // uncapped shift would overflow well before a realistic attempt count.
    let backoff = BASE_LOCKOUT_MS.saturating_mul(1u64 << steps.min(6));
    Some(backoff.min(MAX_LOCKOUT_MS))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn mime_for_name(name: &str) -> String {
    let ext = Path::new(name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "mp4" | "m4v" => "video/mp4",
        "avi" => "video/x-msvideo",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "txt" | "log" => "text/plain",
        "md" => "text/markdown",
        "json" => "application/json",
        "csv" => "text/csv",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
    .to_string()
}

fn is_text_mime(m: &str) -> bool {
    m.starts_with("text/") || m == "application/json" || m == "application/xml"
}

/// Write sink that hashes without retaining data: verification needs the
/// plaintext's SHA-256 and length, never the plaintext itself. Keeps deep
/// verify / heal memory bounded at O(1) regardless of object size.
struct HashingSink {
    hasher: Sha256Writer,
    len: u64,
}

impl HashingSink {
    fn new() -> Self {
        Self { hasher: Sha256Writer::new(), len: 0 }
    }
}

impl Write for HashingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        self.len += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
pub struct CreateOptions {
    pub kdf: Option<KdfParams>,
    pub with_recovery: bool,
}

struct Session {
    root: Key32,
    domains: DomainKeys,
    vault_id: [u8; 16],
}

impl Drop for Session {
    fn drop(&mut self) {
        // Key32/DomainKeys zeroize on drop (zeroize crate).
    }
}

pub struct VaultEngine {
    layout: Layout,
    header: VaultHeader,
    control: ControlState,
    capability: PlatformCapability,
    lockdown: Lockdown,
    binary_hash: [u8; 32],
    session: Option<Session>,
    manifest: Option<Manifest>,
    audit: Option<AuditLog>,
    /// Events recorded while locked; flushed into the audit log at unlock.
    pending_events: Vec<(u64, String, String, String, String)>,
}

impl VaultEngine {
    // ---------------------------------------------------------------- create

    /// Create a brand-new vault at `path`. Returns the unlocked engine and,
    /// when requested, the recovery key in display form (shown exactly once).
    pub fn create(
        path: &Path,
        password: &SecretBytes,
        opts: CreateOptions,
    ) -> Result<(Self, Option<String>), CoreError> {
        let layout = Layout::new(path);
        if layout.header().exists() {
            return Err(CoreError::AlreadyExists);
        }
        if password.len() < 8 {
            return Err(CoreError::Invalid("password must be at least 8 characters"));
        }
        layout.ensure_dirs()?;
        cleanup_temp_files(&layout.manifest_dir())?;

        let kdf = opts.kdf.unwrap_or_else(KdfParams::production);
        kdf.validate()?;

        let root = Key32::random();
        let (header, recovery_display) = if opts.with_recovery {
            let rk = RecoveryKey::generate();
            let hdr = create_header_with_password(
                password,
                kdf,
                &root,
                Some(&rk.as_key32()),
                now_ms(),
                APP_VERSION,
            )?;
            (hdr, Some(rk.to_display()))
        } else {
            let hdr = create_header_with_password(password, kdf, &root, None, now_ms(), APP_VERSION)?;
            (hdr, None)
        };

        atomic_write(&layout.header(), &header.to_bytes())?;
        fault_point("after_header_write");

        let vault_id = header.vault_id;
        let domains = DomainKeys::derive(&root, &vault_id);

        // Initial manifest (generation 1).
        let manifest = Manifest::new_initial(now_ms());
        let sealed = manifest.seal(&domains.meta, &vault_id)?;
        atomic_write(&layout.manifest_file(1), &sealed)?;
        let hash = manifest_hash(&sealed);
        atomic_write(&layout.current(), &encode_current(1, &hash))?;
        fault_point("after_initial_commit");

        let binary_hash = vault_security::platform::current_binary_hash().unwrap_or([0u8; 32]);
        let mut control = ControlState::new(&vault_crypto::to_hex16(&vault_id), now_ms(), &vault_crypto::to_hex(&binary_hash));
        control.max_seen_generation = 1;
        control.seen_manifest_hash = vault_crypto::to_hex(&hash);
        let capability = control.save(&layout.control_file(), &vault_id)?;

        let mut engine = Self {
            layout,
            header,
            control,
            capability: if capability == vault_security::CAPABILITY_DPAPI {
                PlatformCapability::Dpapi
            } else {
                PlatformCapability::DpapiUnavailable
            },
            lockdown: Lockdown::new(),
            binary_hash,
            session: Some(Session {
                root,
                domains,
                vault_id,
            }),
            manifest: Some(manifest),
            audit: None,
            pending_events: Vec::new(),
        };
        engine.open_audit()?;
        engine.audit_event("vault.create", "core", "ok", "vault initialized")?;
        Ok((engine, recovery_display))
    }

    // ----------------------------------------------------------------- open

    /// Open an existing vault (locked view: header + control state only).
    pub fn open(path: &Path) -> Result<Self, CoreError> {
        let layout = Layout::new(path);
        if !layout.header().exists() {
            return Err(CoreError::Invalid("no vault at this location"));
        }
        let header_bytes = vault_storage::read_file_capped(&layout.header(), 8192)?;
        let header = VaultHeader::parse(&header_bytes)?;
        let vault_id = header.vault_id;

        let binary_hash = vault_security::platform::current_binary_hash().unwrap_or([0u8; 32]);
        // Restore persisted lockdown state so a fresh process cannot reset it
        // by simply restarting (state lives in `state/lockdown.json`).
        let lockdown = std::fs::read(layout.lockdown_file())
            .ok()
            .and_then(|b| serde_json::from_slice::<LockdownRecord>(&b).ok())
            .map(Lockdown::from_record)
            .unwrap_or_default();

        let mut pending_events: Vec<(u64, String, String, String, String)> = Vec::new();
        let control = match ControlState::load(&layout.control_file(), &vault_id) {
            Ok(Some(c)) => c,
            res => {
                // A missing control file is just as much a lost witness as an
                // unreadable one: both reset throttle/rollback evidence and
                // must be raised (previously `Ok(None)` silently continued).
                let detail = match res {
                    Ok(_) => "control state missing; throttle/rollback witness reset",
                    Err(_) => "control state unreadable; throttle/rollback witness reset",
                };
                pending_events.push((
                    now_ms(),
                    "control.unavailable".into(),
                    "control".into(),
                    "fail".into(),
                    detail.into(),
                ));
                ControlState::new(&vault_crypto::to_hex16(&vault_id), now_ms(), &vault_crypto::to_hex(&binary_hash))
            }
        };

        // Tamper evidence for the executable (documented as weak: an attacker
        // with write access can update both sides).
        if !control.binary_hash.is_empty()
            && control.binary_hash != vault_crypto::to_hex(&binary_hash)
        {
            pending_events.push((
                now_ms(),
                "binary.modified".into(),
                "platform".into(),
                "warn".into(),
                "executable hash changed since last trusted launch".into(),
            ));
        }

        let capability = if control.capability == vault_security::CAPABILITY_DPAPI {
            PlatformCapability::Dpapi
        } else {
            PlatformCapability::DpapiUnavailable
        };
        let control_degraded = pending_events
            .iter()
            .any(|(_, ev, ..)| ev == "control.unavailable");
        let binary_changed = pending_events
            .iter()
            .any(|(_, ev, ..)| ev == "binary.modified");

        let mut engine = Self {
            layout,
            header,
            control,
            capability,
            lockdown,
            binary_hash,
            session: None,
            manifest: None,
            audit: None,
            pending_events,
        };
        if control_degraded {
            engine.eval_trigger(
                Trigger::new(
                    "control.unavailable",
                    60,
                    vault_security::Severity::Warning,
                    "control",
                    "control state missing or unreadable; throttle/rollback witness reset",
                ),
                now_ms(),
            );
        }
        if binary_changed {
            engine.eval_trigger(
                Trigger::new(
                    "binary.modified",
                    70,
                    vault_security::Severity::Warning,
                    "platform",
                    "executable hash changed since last trusted launch",
                ),
                now_ms(),
            );
        }
        Ok(engine)
    }

    // --------------------------------------------------------------- status

    pub fn status(&self) -> VaultStatus {
        let generation = self
            .manifest
            .as_ref()
            .map(|m| m.generation)
            .or_else(|| self.peek_generation().ok())
            .unwrap_or(0);
        VaultStatus {
            initialized: true,
            unlocked: self.session.is_some(),
            vault_id: vault_crypto::to_hex16(&self.header.vault_id),
            format_version: self.header.format_version,
            app_version: APP_VERSION,
            created_ms: self.header.created_at_ms,
            generation,
            has_recovery: self.header.has_recovery(),
            kdf_memory_kib: self.header.kdf.memory_kib,
            kdf_iterations: self.header.kdf.iterations,
            kdf_parallelism: self.header.kdf.parallelism,
            lockdown_state: self.lockdown.state().as_str().to_string(),
            failed_attempts: self.control.failed_attempts,
            lockout_until_ms: self.control.lockout_until_ms,
            platform_capability: format!("{:?}", self.capability),
            binary_hash: vault_crypto::to_hex(&self.binary_hash),
            binary_verified: self.control.binary_hash == vault_crypto::to_hex(&self.binary_hash),
        }
    }

    fn peek_generation(&self) -> Result<u64, CoreError> {
        let bytes = vault_storage::read_file_capped(&self.layout.current(), 4096)?;
        let (gen, _) = decode_current(&bytes)?;
        Ok(gen)
    }

    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    pub fn lockdown_state(&self) -> VaultState {
        self.lockdown.state()
    }

    pub fn lockdown(&self) -> &Lockdown {
        &self.lockdown
    }

    // --------------------------------------------------------------- unlock

    pub fn unlock(&mut self, password: &SecretBytes) -> Result<(), CoreError> {
        if self.session.is_some() {
            return Ok(());
        }
        let now = now_ms();
        if self.lockdown.state() == VaultState::Critical {
            return Err(CoreError::Refused("vault is in CRITICAL state; resolve it first"));
        }
        if self.control.lockout_until_ms > now {
            let retry = (self.control.lockout_until_ms - now) / 1000 + 1;
            return Err(CoreError::LockedOut { retry_in_secs: retry });
        }

        let mut root = match self.header.unwrap_root(password) {
            Ok(r) => r,
            Err(_) => {
                let retry = self.register_failed_attempt(now);
                self.pending_events.push((
                    now,
                    "vault.unlock_failed".into(),
                    "auth".into(),
                    "denied".into(),
                    format!("attempt {}", self.control.failed_attempts),
                ));
                return Err(match retry {
                    Some(secs) => CoreError::LockedOut { retry_in_secs: secs },
                    None => CoreError::AuthFailed,
                });
            }
        };

        // A domain rekey interrupted by a crash resumes here: every step is
        // idempotent, so unlocking with the password always drives the
        // transition to completion (see drive_rekey).
        if self.header.rekey_pending() {
            root = self.drive_rekey(password, root)?;
        }

        let vault_id = self.header.vault_id;
        let domains = DomainKeys::derive(&root, &vault_id);

        // ---- locate + verify current manifest (no session yet) ----
        let (generation, cur_hash, manifest_bytes) = self.read_verified_manifest_bytes()?;
        let manifest = Manifest::open(&domains.meta, &manifest_bytes)?;
        if manifest.generation != generation {
            return Err(CoreError::Integrity("manifest generation mismatch"));
        }

        // ---- success: install session ----
        self.session = Some(Session { root, domains, vault_id });
        self.manifest = Some(manifest);

        self.control.failed_attempts = 0;
        self.control.lockout_until_ms = 0;
        self.control.max_seen_generation = generation;
        self.control.seen_manifest_hash = vault_crypto::to_hex(&cur_hash);
        self.control.binary_hash = vault_crypto::to_hex(&self.binary_hash);
        if let Err(e) = self.control.save(&self.layout.control_file(), &vault_id) {
            self.eval_trigger(
                Trigger::new(
                    "control.unavailable",
                    70,
                    vault_security::Severity::Error,
                    "control",
                    format!("failed to persist control state: {e}"),
                ),
                now,
            );
        }

        // Quarantine-and-restart failures are already reflected in the
        // lockdown record; unlock must not fail because of them.
        let _ = self.open_audit();
        self.lockdown.on_successful_auth(now);
        self.save_lockdown();

        // Crash debris housekeeping (runs only while unlocked & verified).
        if let Err(e) = self.collect_garbage() {
            self.audit_event("container.gc", "storage", "warn", &e.to_string())?;
        }
        if self.control.pending_commit {
            if let Err(e) = self.heal_pending_updates() {
                self.audit_event("container.heal", "storage", "fail", &e.to_string())?;
            } else {
                self.audit_event("container.heal", "storage", "ok", "pending update committed")?;
            }
        }

        // Flush events recorded while locked (binary.modified,
        // control.unavailable, GC orphans) after housekeeping so the log is
        // open and every pending event lands in one pass.
        let _ = self.flush_pending_events();

        self.audit_event("vault.unlock", "auth", "ok", "")?;
        Ok(())
    }

    fn register_failed_attempt(&mut self, now: u64) -> Option<u64> {
        self.control.failed_attempts = self.control.failed_attempts.saturating_add(1);
        if let Some(backoff) = lockout_delay_ms(self.control.failed_attempts) {
            self.control.lockout_until_ms = now + backoff;
        }
        if self.control.failed_attempts.is_multiple_of(MAX_ATTEMPTS_BEFORE_LOCKOUT) {
            self.eval_trigger(
                Trigger::new(
                    "auth.repeated_failure",
                    70,
                    vault_security::Severity::Warning,
                    "auth",
                    format!("{} consecutive failed unlock attempts", self.control.failed_attempts),
                ),
                now,
            );
        }
        if let Err(e) = self.control.save(&self.layout.control_file(), &self.header.vault_id) {
            self.eval_trigger(
                Trigger::new(
                    "control.unavailable",
                    70,
                    vault_security::Severity::Error,
                    "control",
                    format!("failed to persist attempt counter: {e}"),
                ),
                now,
            );
        }
        self.control
            .lockout_until_ms
            .checked_sub(now)
            .map(|ms| ms / 1000 + 1)
    }

    pub fn lock(&mut self, reason: LockReason) {
        if self.session.is_some() {
            if let (Some(audit), Some(_)) = (self.audit.as_mut(), self.session.as_ref()) {
                let _ = audit.append(now_ms(), "vault.lock", "core", "ok", reason.as_str());
            }
        }
        self.session = None;
        if let Some(mut m) = self.manifest.take() {
            m.wipe();
        }
        self.audit = None;
    }

    // -------------------------------------------------------------- helpers

    fn session(&self) -> Result<&Session, CoreError> {
        self.session.as_ref().ok_or(CoreError::Locked)
    }

    fn require_writable(&self) -> Result<&Session, CoreError> {
        let s = self.session()?;
        // Writes are allowed only in NORMAL/SUSPICIOUS. LOCKED previously
        // slipped through (only Restricted/Critical were checked), letting
        // mutations run while the vault was supposed to require re-auth.
        if !matches!(
            self.lockdown.state(),
            VaultState::Normal | VaultState::Suspicious
        ) {
            return Err(CoreError::Refused("lockdown policy blocks writes"));
        }
        Ok(s)
    }

    /// Evaluate a lockdown trigger, apply the resulting action, and persist
    /// the lockdown record (so a restart cannot reset the state machine).
    /// `Action::DestroySession` drops the in-memory session immediately.
    fn eval_trigger(&mut self, trigger: Trigger, now: u64) -> Action {
        let action = self.lockdown.evaluate(trigger, now);
        if matches!(action, Action::DestroySession) && self.session.is_some() {
            self.lock(LockReason::Tamper);
        }
        self.save_lockdown();
        action
    }

    fn save_lockdown(&self) {
        if let Ok(json) = serde_json::to_vec(self.lockdown.record()) {
            let _ = vault_storage::atomic_write(&self.layout.lockdown_file(), &json);
        }
    }

    fn manifest(&self) -> Result<&Manifest, CoreError> {
        self.manifest.as_ref().ok_or(CoreError::Locked)
    }

    /// Locate, hash-check and chain-verify the current manifest file.
    ///
    /// Key-independent: callers then AEAD-open the bytes under whichever
    /// domain keys apply (normal unlock, or old/new probing during a domain
    /// rekey). All lockdown evaluation happens here so no caller can skip
    /// tamper evidence — including the anti-rollback witness check, which
    /// runs before any rekey migration may write.
    fn read_verified_manifest_bytes(&mut self) -> Result<(u64, [u8; 32], Vec<u8>), CoreError> {
        let now = now_ms();
        let vault_id = self.header.vault_id;
        let cur_bytes = vault_storage::read_file_capped(&self.layout.current(), 4096)?;
        let (generation, cur_hash) = decode_current(&cur_bytes)?;

        // Same-generation witness: `CURRENT` must keep pointing at the exact
        // manifest whose hash was witnessed for this generation. A different
        // hash at the same generation means the manifest was rewritten after
        // being witnessed — raise the rollback evidence. The read continues
        // (the manifest is still verified against `CURRENT`, the chain and the
        // vault id below): failing hard here would permanently brick a vault
        // touched by a second concurrent writer, and forging a *self-
        // consistent* manifest at the witnessed generation requires the meta
        // key anyway. The witness re-anchors to the observed pair so the
        // alert does not repeat on every unlock.
        if generation == self.control.max_seen_generation
            && !self.control.seen_manifest_hash.is_empty()
            && vault_crypto::to_hex(&cur_hash) != self.control.seen_manifest_hash
        {
            self.eval_trigger(
                Trigger::new(
                    "rollback.detected",
                    95,
                    vault_security::Severity::Critical,
                    "control",
                    format!(
                        "manifest for generation {} does not match witnessed hash; re-anchoring",
                        generation
                    ),
                ),
                now,
            );
            self.control.seen_manifest_hash = vault_crypto::to_hex(&cur_hash);
            let vid = self.header.vault_id;
            let _ = self.control.save(&self.layout.control_file(), &vid);
        }

        let manifest_path = self.layout.manifest_file(generation);
        let manifest_bytes = vault_storage::read_file_capped(&manifest_path, 512 * 1024 * 1024)?;
        if manifest_hash(&manifest_bytes) != cur_hash {
            self.eval_trigger(
                Trigger::new(
                    "manifest.auth_failed",
                    100,
                    vault_security::Severity::Critical,
                    "container",
                    "CURRENT does not match manifest content",
                ),
                now,
            );
            return Err(CoreError::Integrity("manifest hash mismatch"));
        }
        if Manifest::peek_vault_id(&manifest_bytes)? != vault_id {
            self.eval_trigger(
                Trigger::new(
                    "vault_id.mismatch",
                    100,
                    vault_security::Severity::Critical,
                    "container",
                    "manifest belongs to another vault",
                ),
                now,
            );
            return Err(CoreError::Integrity("vault id mismatch"));
        }
        if generation > 1 {
            let prev_path = self.layout.manifest_file(generation - 1);
            let prev_bytes =
                vault_storage::read_file_capped(&prev_path, 512 * 1024 * 1024).map_err(|_| {
                    CoreError::Integrity("previous manifest missing")
                })?;
            let claimed_prev = Manifest::peek_prev_manifest_hash(&manifest_bytes)?;
            if claimed_prev != manifest_hash(&prev_bytes) {
                self.eval_trigger(
                    Trigger::new(
                        "manifest.auth_failed",
                        95,
                        vault_security::Severity::Critical,
                        "container",
                        "manifest hash chain broken",
                    ),
                    now,
                );
                return Err(CoreError::Integrity("manifest hash chain broken"));
            }
        }

        // ---- rollback witness ----
        if generation < self.control.max_seen_generation {
            self.eval_trigger(
                Trigger::new(
                    "rollback.detected",
                    95,
                    vault_security::Severity::Critical,
                    "control",
                    format!(
                        "container generation {} < witnessed {}",
                        generation, self.control.max_seen_generation
                    ),
                ),
                now,
            );
            return Err(CoreError::RollbackDetected);
        }
        Ok((generation, cur_hash, manifest_bytes))
    }

    fn open_audit(&mut self) -> Result<(), CoreError> {
        let key = match &self.session {
            Some(s) => s.domains.audit.clone(),
            None => return Err(CoreError::Locked),
        };
        let path = self.layout.audit_file();
        match AuditLog::open(&path, key.clone()) {
            Ok(log) => {
                // Record-count anchor: suffix removal of whole records is
                // invisible to the chain itself (see docs/security-audit.md),
                // so compare against the witness in control state. Lag
                // (anchor < actual, crash between append and witness save)
                // heals forward silently; only a *shrink* raises the alarm.
                let count = log.record_count();
                if self.control.audit_records > count {
                    self.eval_trigger(
                        Trigger::new(
                            "audit.chain_broken",
                            85,
                            vault_security::Severity::Error,
                            "audit",
                            format!(
                                "audit log truncated: witness has {} records, found {}",
                                self.control.audit_records, count
                            ),
                        ),
                        now_ms(),
                    );
                    self.control.audit_records = count;
                    let vid = self.header.vault_id;
                    let _ = self.control.save(&self.layout.control_file(), &vid);
                } else if count > self.control.audit_records {
                    self.control.audit_records = count;
                    let vid = self.header.vault_id;
                    let _ = self.control.save(&self.layout.control_file(), &vid);
                }
                self.audit = Some(log);
                Ok(())
            }
            Err(e) => {
                // Preserve the broken log as evidence, start a fresh chain.
                let quarantine = self
                    .layout
                    .audit_dir()
                    .join(format!("audit.bin.corrupt-{}", now_ms()));
                let _ = std::fs::rename(&path, &quarantine);
                self.eval_trigger(
                    Trigger::new(
                        "audit.chain_broken",
                        85,
                        vault_security::Severity::Error,
                        "audit",
                        "audit chain failed verification; log quarantined",
                    ),
                    now_ms(),
                );
                // Fresh log starts at 0 records; drop the stale anchor so the
                // quarantine itself is not re-reported at the next open.
                self.control.audit_records = 0;
                let fresh = AuditLog::open(&path, key)?;
                self.audit = Some(fresh);
                Err(e)
            }
        }
    }

    fn audit_event(&mut self, event: &str, component: &str, result: &str, detail: &str) -> Result<(), CoreError> {
        match self.audit.as_mut() {
            Some(a) => {
                a.append(now_ms(), event, component, result, detail)?;
                self.control.audit_records = a.record_count();
                Ok(())
            }
            None => {
                self.pending_events.push((
                    now_ms(),
                    event.to_string(),
                    component.to_string(),
                    result.to_string(),
                    detail.to_string(),
                ));
                Ok(())
            }
        }
    }

    fn flush_pending_events(&mut self) -> Result<(), CoreError> {
        let pending: Vec<_> = std::mem::take(&mut self.pending_events);
        if let Some(a) = self.audit.as_mut() {
            for (ts, ev, comp, res, det) in pending {
                let _ = a.append(ts, &ev, &comp, &res, &det);
            }
            self.control.audit_records = a.record_count();
        } else {
            self.pending_events = pending;
        }
        Ok(())
    }

    /// Atomic manifest commit: seal gen+1, write manifest file, then CURRENT,
    /// then update the rollback witness. A write failure rolls the in-memory
    /// generation back so the session never claims a commit that disk does not
    /// have.
    fn commit(&mut self, detail: &str) -> Result<(), CoreError> {
        let (vault_id, meta_key) = {
            let s = self.session()?;
            (s.vault_id, s.domains.meta.clone())
        };
        let manifest = self.manifest.as_mut().ok_or(CoreError::Locked)?;
        let witness = (
            manifest.generation,
            manifest.prev_manifest_hash,
            manifest.committed_at_ms,
        );
        manifest.generation += 1;
        manifest.committed_at_ms = now_ms();
        let gen = manifest.generation;

        let prev_path = self.layout.manifest_file(gen - 1);
        let prev_bytes = vault_storage::read_file_capped(&prev_path, 512 * 1024 * 1024)?;
        manifest.prev_manifest_hash = manifest_hash(&prev_bytes);

        let sealed = manifest.seal(&meta_key, &vault_id)?;
        let hash = manifest_hash(&sealed);

        let disk = || -> Result<(), std::io::Error> {
            atomic_write(&self.layout.manifest_file(gen), &sealed)?;
            fault_point("after_manifest_write");
            atomic_write(&self.layout.current(), &encode_current(gen, &hash))?;
            fault_point("after_current_write");
            Ok(())
        };
        if let Err(e) = disk() {
            manifest.generation = witness.0;
            manifest.prev_manifest_hash = witness.1;
            manifest.committed_at_ms = witness.2;
            return Err(e.into());
        }

        self.control.max_seen_generation = gen;
        self.control.seen_manifest_hash = vault_crypto::to_hex(&hash);
        if let Err(e) = self.control.save(&self.layout.control_file(), &vault_id) {
            // The manifest is committed but the witness is not: without a
            // loud failure this becomes a false rollback lockout at the next
            // open. Surface it instead of swallowing (old `let _ =`).
            self.pending_events.push((
                now_ms(),
                "control.unavailable".into(),
                "control".into(),
                "fail".into(),
                format!("rollback witness save failed after commit: {e}"),
            ));
            return Err(e.into());
        }

        self.audit_event("container.commit", "storage", "ok", detail)?;
        Ok(())
    }

    fn object_path(&self, id: &Id) -> PathBuf {
        self.layout.object_file(id)
    }

    // ------------------------------------------------------- folder ops

    pub fn create_folder(&mut self, name: &str, parent: Option<Id>) -> Result<Id, CoreError> {
        self.require_writable()?;
        let name = name.trim();
        if name.is_empty() || name.len() > 256 {
            return Err(CoreError::Invalid("folder name must be 1..=256 chars"));
        }
        if let Some(p) = parent {
            if self.manifest()?.find_folder(&p).is_none() {
                return Err(CoreError::NotFound);
            }
        }
        let id = new_id();
        let now = now_ms();
        self.manifest.as_mut().ok_or(CoreError::Locked)?.folders.push(FolderEntry {
            id,
            parent,
            created_ms: now,
            updated_ms: now,
            name: name.to_string(),
        });
        self.commit("folder.create")?;
        Ok(id)
    }

    pub fn delete_folder(&mut self, id: &Id) -> Result<(), CoreError> {
        self.require_writable()?;
        let m = self.manifest.as_mut().ok_or(CoreError::Locked)?;
        if m.find_folder(id).is_none() {
            return Err(CoreError::NotFound);
        }
        // Children get promoted to root (parent cleared); items keep folder=None.
        for f in m.folders.iter_mut() {
            if f.parent == Some(*id) {
                f.parent = None;
            }
        }
        for o in m.objects.iter_mut() {
            if o.folder == Some(*id) {
                o.folder = None;
            }
        }
        m.folders.retain(|f| f.id != *id);
        self.commit("folder.delete")?;
        Ok(())
    }

    pub fn list_folders(&self) -> Result<Vec<FolderSummary>, CoreError> {
        let m = self.manifest()?;
        Ok(m.folders
            .iter()
            .map(|f| FolderSummary {
                id: f.id,
                parent: f.parent,
                name: f.name.clone(),
                created_ms: f.created_ms,
                item_count: m.objects.iter().filter(|o| o.folder == Some(f.id)).count() as u64,
            })
            .collect())
    }

    // --------------------------------------------------------- listing/search

    pub fn list(&self, folder: Option<Id>) -> Result<Vec<ItemSummary>, CoreError> {
        let m = self.manifest()?;
        Ok(m.objects
            .iter()
            .filter(|o| o.folder == folder)
            .map(|o| {
                ItemSummary::from_entry(o.id, o.object_type, o.size, o.folder, o.created_ms, o.updated_ms, o.flags, &o.meta)
            })
            .collect())
    }

    pub fn list_kind(&self, kind: ItemKind, folder: Option<Id>) -> Result<Vec<ItemSummary>, CoreError> {
        let m = self.manifest()?;
        Ok(m.objects
            .iter()
            .filter(|o| o.folder == folder)
            .filter(|o| ItemKind::from_object_type(o.object_type) == kind)
            .map(|o| {
                ItemSummary::from_entry(o.id, o.object_type, o.size, o.folder, o.created_ms, o.updated_ms, o.flags, &o.meta)
            })
            .collect())
    }

    /// Flat listing of every item in the vault, regardless of folder.
    pub fn list_all(&self) -> Result<Vec<ItemSummary>, CoreError> {
        let m = self.manifest()?;
        Ok(m.objects
            .iter()
            .map(|o| {
                ItemSummary::from_entry(o.id, o.object_type, o.size, o.folder, o.created_ms, o.updated_ms, o.flags, &o.meta)
            })
            .collect())
    }

    /// Search model: **decrypt-and-search in memory** (documented in
    /// docs/search.md). No persistent index exists; query strings and
    /// intermediate comparisons live only for the duration of this call.
    pub fn search(&self, query: &str) -> Result<Vec<ItemSummary>, CoreError> {
        let m = self.manifest()?;
        let q = query.to_lowercase();
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for o in &m.objects {
            let mut hay = String::new();
            hay.push_str(&o.meta.name.to_lowercase());
            hay.push(' ');
            if let Some(u) = &o.meta.username {
                hay.push_str(&u.to_lowercase());
                hay.push(' ');
            }
            if let Some(u) = &o.meta.url {
                hay.push_str(&u.to_lowercase());
                hay.push(' ');
            }
            if let Some(c) = &o.meta.category {
                hay.push_str(&c.to_lowercase());
                hay.push(' ');
            }
            if let Some(p) = &o.meta.preview {
                hay.push_str(&p.to_lowercase());
            }
            for t in &o.meta.tags {
                hay.push(' ');
                hay.push_str(&t.to_lowercase());
            }
            if hay.contains(&q) {
                out.push(ItemSummary::from_entry(o.id, o.object_type, o.size, o.folder, o.created_ms, o.updated_ms, o.flags, &o.meta));
            }
        }
        Ok(out)
    }

    pub fn stats(&self) -> Result<Stats, CoreError> {
        let m = self.manifest()?;
        let mut s = Stats {
            folders: m.folders.len() as u64,
            ..Default::default()
        };
        for o in &m.objects {
            match o.object_type {
                ObjectType::File => s.files += 1,
                ObjectType::Note => s.notes += 1,
                ObjectType::Password => s.passwords += 1,
            }
            s.total_bytes += o.size;
            if o.flags & vault_container::manifest::object_flags::FAVORITE != 0 {
                s.favorites += 1;
            }
        }
        Ok(s)
    }

    // ------------------------------------------------------- blob primitives

    fn write_blob_with_hash(
        &self,
        id: &Id,
        version: u32,
        reader: &mut dyn Read,
    ) -> Result<(u64, u64, [u8; 32]), CoreError> {
        let s = self.session()?;
        let path = self.object_path(id);
        let data_key = s.domains.data.clone();
        let vault_id = s.vault_id;

        struct Hashing<R: Read> {
            inner: R,
            hasher: Sha256Writer,
        }
        impl<R: Read> Read for Hashing<R> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.inner.read(buf)?;
                self.hasher.update(&buf[..n]);
                Ok(n)
            }
        }

        let mut hdr_out: Option<ObjectHeader> = None;
        let mut hash_out: Option<[u8; 32]> = None;
        atomic_write_from(&path, |f| {
            let mut hashing = Hashing { inner: &mut *reader, hasher: Sha256Writer::new() };
            let hdr = write_object(f, &data_key, &vault_id, id, version, &mut hashing)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            hash_out = Some(hashing.hasher.finalize());
            hdr_out = Some(hdr);
            Ok(())
        })?;
        let hdr = hdr_out.ok_or(CoreError::Integrity("object write produced no header"))?;
        let hash = hash_out.ok_or(CoreError::Integrity("object hash missing"))?;
        Ok((hdr.plaintext_len, hdr.chunk_count, hash))
    }

    fn read_blob_into(&self, id: &Id, expected_version: u32, out: &mut Vec<u8>) -> Result<(), CoreError> {
        let s = self.session()?;
        let path = self.object_path(id);
        let mut file = std::fs::File::open(&path)?;
        let mut header_bytes = [0u8; OBJECT_HEADER_SIZE];
        file.read_exact(&mut header_bytes)?;
        let header = ObjectHeader::parse(&header_bytes)?;
        // Bind the blob to the manifest entry it claims to be. The chunk AAD
        // derives from the *header's own* id/version, so a whole-file
        // substitution (object A copied over object B's path) would decrypt
        // cleanly without this check.
        if header.object_id != *id {
            return Err(CoreError::Integrity("object id mismatch"));
        }
        if header.version != expected_version {
            return Err(CoreError::Integrity("object version mismatch"));
        }
        if header.plaintext_len > MAX_INLINE_READ {
            return Err(CoreError::Invalid("object too large for inline read"));
        }
        out.clear();
        out.reserve(header.plaintext_len as usize);
        vault_container::open_object(&mut file, &header, &s.domains.data, &s.vault_id, out)?;
        Ok(())
    }

    // -------------------------------------------------------------- notes

    pub fn add_note(&mut self, title: &str, content: &str, folder: Option<Id>) -> Result<Id, CoreError> {
        self.require_writable()?;
        if title.trim().is_empty() || title.len() > 512 {
            return Err(CoreError::Invalid("note title must be 1..=512 chars"));
        }
        if folder.is_some() && self.manifest()?.find_folder(&folder.unwrap()).is_none() {
            return Err(CoreError::NotFound);
        }
        let id = new_id();
        let payload = serde_json::json!({ "content": content }).to_string();
        let (size, chunks, hash) =
            self.write_blob_with_hash(&id, 1, &mut payload.as_bytes())?;
        let now = now_ms();
        let preview: String = content.chars().take(150).collect();
        self.manifest.as_mut().ok_or(CoreError::Locked)?.objects.push(ObjectEntry {
            id,
            object_type: ObjectType::Note,
            version: 1,
            size,
            chunk_count: chunks,
            content_hash: hash,
            folder,
            created_ms: now,
            updated_ms: now,
            flags: 0,
            meta: ObjectMeta {
                name: title.trim().to_string(),
                preview: Some(preview),
                ..Default::default()
            },
        });
        self.commit("note.create")?;
        Ok(id)
    }

    pub fn get_note(&mut self, id: &Id) -> Result<Note, CoreError> {
        self.session()?;
        let (version, content_hash) = {
            let m = self.manifest()?;
            let e = m.find_object(id).ok_or(CoreError::NotFound)?;
            if e.object_type != ObjectType::Note {
                return Err(CoreError::Invalid("not a note"));
            }
            (e.version, e.content_hash)
        };
        let mut buf = Vec::new();
        self.read_blob_into(id, version, &mut buf)?;
        if vault_crypto::sha256(&buf) != content_hash {
            self.note_inline_integrity("note content hash mismatch");
            return Err(CoreError::Integrity("content hash mismatch"));
        }
        let json: serde_json::Value =
            serde_json::from_slice(&buf).map_err(|_| CoreError::Integrity("note payload malformed"))?;
        let content = json["content"].as_str().unwrap_or("").to_string();
        let e = self.manifest()?.find_object(id).ok_or(CoreError::NotFound)?;
        Ok(Note {
            id: *id,
            title: e.meta.name.clone(),
            content,
            folder: e.folder,
            tags: e.meta.tags.clone(),
            created_ms: e.created_ms,
            updated_ms: e.updated_ms,
            favorite: e.flags & vault_container::manifest::object_flags::FAVORITE != 0,
        })
    }

    pub fn update_note(&mut self, id: &Id, title: &str, content: &str) -> Result<(), CoreError> {
        self.require_writable()?;
        if title.trim().is_empty() {
            return Err(CoreError::Invalid("note title must not be empty"));
        }
        let old_version = {
            let m = self.manifest()?;
            let e = m.find_object(id).ok_or(CoreError::NotFound)?;
            if e.object_type != ObjectType::Note {
                return Err(CoreError::Invalid("not a note"));
            }
            e.version
        };
        let new_version = old_version + 1;
        self.set_pending_commit(true)?;
        let payload = serde_json::json!({ "content": content }).to_string();
        let (size, chunks, hash) =
            self.write_blob_with_hash(id, new_version, &mut payload.as_bytes())?;
        fault_point("after_blob_write");
        let preview: String = content.chars().take(150).collect();
        {
            let m = self.manifest.as_mut().ok_or(CoreError::Locked)?;
            let e = m.objects.iter_mut().find(|o| o.id == *id).ok_or(CoreError::NotFound)?;
            e.version = new_version;
            e.size = size;
            e.chunk_count = chunks;
            e.content_hash = hash;
            e.updated_ms = now_ms();
            e.meta.name = title.trim().to_string();
            e.meta.preview = Some(preview);
        }
        self.commit("note.update")?;
        self.set_pending_commit(false)?;
        Ok(())
    }

    // ----------------------------------------------------------- passwords

    pub fn add_password(
        &mut self,
        name: &str,
        username: &str,
        password: &str,
        url: &str,
        notes: &str,
        category: &str,
        favorite: bool,
    ) -> Result<Id, CoreError> {
        self.require_writable()?;
        if name.trim().is_empty() {
            return Err(CoreError::Invalid("password entry requires a name"));
        }
        let id = new_id();
        let payload = serde_json::json!({ "password": password, "notes": notes }).to_string();
        let (size, chunks, hash) =
            self.write_blob_with_hash(&id, 1, &mut payload.as_bytes())?;
        let now = now_ms();
        self.manifest.as_mut().ok_or(CoreError::Locked)?.objects.push(ObjectEntry {
            id,
            object_type: ObjectType::Password,
            version: 1,
            size,
            chunk_count: chunks,
            content_hash: hash,
            folder: None,
            created_ms: now,
            updated_ms: now,
            flags: if favorite { vault_container::manifest::object_flags::FAVORITE } else { 0 },
            meta: ObjectMeta {
                name: name.trim().to_string(),
                username: Some(username.to_string()),
                url: Some(url.to_string()),
                category: Some(category.to_string()),
                ..Default::default()
            },
        });
        self.commit("password.create")?;
        Ok(id)
    }

    pub fn get_password(&mut self, id: &Id) -> Result<PasswordRecord, CoreError> {
        self.session()?;
        let (version, content_hash) = {
            let m = self.manifest()?;
            let e = m.find_object(id).ok_or(CoreError::NotFound)?;
            if e.object_type != ObjectType::Password {
                return Err(CoreError::Invalid("not a password entry"));
            }
            (e.version, e.content_hash)
        };
        let mut buf = Vec::new();
        self.read_blob_into(id, version, &mut buf)?;
        if vault_crypto::sha256(&buf) != content_hash {
            self.note_inline_integrity("password content hash mismatch");
            return Err(CoreError::Integrity("content hash mismatch"));
        }
        let json: serde_json::Value =
            serde_json::from_slice(&buf).map_err(|_| CoreError::Integrity("password payload malformed"))?;
        let e = self.manifest()?.find_object(id).ok_or(CoreError::NotFound)?;
        Ok(PasswordRecord {
            id: *id,
            name: e.meta.name.clone(),
            username: e.meta.username.clone().unwrap_or_default(),
            password: json["password"].as_str().unwrap_or("").to_string(),
            url: e.meta.url.clone().unwrap_or_default(),
            notes: json["notes"].as_str().unwrap_or("").to_string(),
            category: e.meta.category.clone().unwrap_or_else(|| "other".into()),
            favorite: e.flags & vault_container::manifest::object_flags::FAVORITE != 0,
            created_ms: e.created_ms,
            updated_ms: e.updated_ms,
        })
    }

    pub fn update_password(
        &mut self,
        id: &Id,
        name: &str,
        username: &str,
        password: &str,
        url: &str,
        notes: &str,
        category: &str,
        favorite: bool,
    ) -> Result<(), CoreError> {
        self.require_writable()?;
        let old_version = {
            let m = self.manifest()?;
            let e = m.find_object(id).ok_or(CoreError::NotFound)?;
            if e.object_type != ObjectType::Password {
                return Err(CoreError::Invalid("not a password entry"));
            }
            e.version
        };
        if name.trim().is_empty() {
            return Err(CoreError::Invalid("password entry requires a name"));
        }
        let new_version = old_version + 1;
        self.set_pending_commit(true)?;
        let payload = serde_json::json!({ "password": password, "notes": notes }).to_string();
        let (size, chunks, hash) =
            self.write_blob_with_hash(id, new_version, &mut payload.as_bytes())?;
        fault_point("after_blob_write");
        {
            let m = self.manifest.as_mut().ok_or(CoreError::Locked)?;
            let e = m.objects.iter_mut().find(|o| o.id == *id).ok_or(CoreError::NotFound)?;
            e.version = new_version;
            e.size = size;
            e.chunk_count = chunks;
            e.content_hash = hash;
            e.updated_ms = now_ms();
            e.meta.name = name.trim().to_string();
            e.meta.username = Some(username.to_string());
            e.meta.url = Some(url.to_string());
            e.meta.category = Some(category.to_string());
            // Only touch the FAVORITE bit — the old whole-word assignment
            // clobbered any other flag bits this entry might carry.
            let fav = vault_container::manifest::object_flags::FAVORITE;
            e.flags = if favorite { e.flags | fav } else { e.flags & !fav };
        }
        self.commit("password.update")?;
        self.set_pending_commit(false)?;
        Ok(())
    }

    pub fn toggle_favorite(&mut self, id: &Id) -> Result<(), CoreError> {
        self.require_writable()?;
        let m = self.manifest.as_mut().ok_or(CoreError::Locked)?;
        let e = m.objects.iter_mut().find(|o| o.id == *id).ok_or(CoreError::NotFound)?;
        e.flags ^= vault_container::manifest::object_flags::FAVORITE;
        e.updated_ms = now_ms();
        self.commit("object.favorite")?;
        Ok(())
    }

    // --------------------------------------------------------------- files

    /// Stream-encrypt a file from disk directly into the vault. The source is
    /// read once; no plaintext staging file is ever created.
    pub fn import_file(
        &mut self,
        src: &Path,
        folder: Option<Id>,
        display_name: Option<&str>,
    ) -> Result<Id, CoreError> {
        self.require_writable()?;
        if folder.is_some() && self.manifest()?.find_folder(&folder.unwrap()).is_none() {
            return Err(CoreError::NotFound);
        }
        let name = match display_name {
            Some(n) => n.to_string(),
            None => src
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .ok_or(CoreError::Invalid("source has no file name"))?,
        };
        if name.len() > 1024 {
            return Err(CoreError::Invalid("file name too long"));
        }
        let mime = mime_for_name(&name);
        let id = new_id();
        {
            let mut file = std::fs::File::open(src)?;
            let (size, chunks, hash) = self.write_blob_with_hash(&id, 1, &mut file)?;
            fault_point("after_blob_write");
            let now = now_ms();
            self.manifest.as_mut().ok_or(CoreError::Locked)?.objects.push(ObjectEntry {
                id,
                object_type: ObjectType::File,
                version: 1,
                size,
                chunk_count: chunks,
                content_hash: hash,
                folder,
                created_ms: now,
                updated_ms: now,
                flags: 0,
                meta: ObjectMeta {
                    name,
                    mime: Some(mime),
                    ..Default::default()
                },
            });
        }
        self.commit("file.import")?;
        Ok(id)
    }

    /// Decrypt an object to `dst` (staged in the destination directory and
    /// atomically renamed). Verifies the content hash **before** the rename,
    /// so an existing `dst` is never replaced by unverified data and a
    /// mismatch never deletes the user's previous file.
    pub fn export_file(&mut self, id: &Id, dst: &Path) -> Result<(), CoreError> {
        let (object_type, expected_hash, expected_size, version) = {
            let m = self.manifest()?;
            let e = m.find_object(id).ok_or(CoreError::NotFound)?;
            (e.object_type, e.content_hash, e.size, e.version)
        };
        if object_type != ObjectType::File {
            return Err(CoreError::Invalid("not a file"));
        }
        if self.path_inside_vault(dst) {
            return Err(CoreError::Refused(
                "refusing to export into the vault directory (the container is not a safe export target)",
            ));
        }
        let (path, data_key, vault_id) = {
            let s = self.session()?;
            (self.object_path(id), s.domains.data.clone(), s.vault_id)
        };

        // Stage next to `dst` under our own temp naming, then verify, then
        // rename. `atomic_write_from(dst)` directly would rename first and
        // verify afterwards — a mismatch then deleted the *user's* old dst.
        let staged = match dst.file_name() {
            Some(name) => {
                let rnd: [u8; 16] = vault_crypto::random_bytes();
                let suffix: String = rnd.iter().map(|b| format!("{:02x}", b)).collect();
                dst.with_file_name(format!("{}.{}.tmp", name.to_string_lossy(), suffix))
            }
            None => return Err(CoreError::Invalid("export target has no file name")),
        };

        let write_result = atomic_write_from(&staged, |f| {
            let mut file = std::fs::File::open(&path)?;
            let mut header_bytes = [0u8; OBJECT_HEADER_SIZE];
            file.read_exact(&mut header_bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let header = ObjectHeader::parse(&header_bytes)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            if header.object_id != *id || header.version != version {
                return Err(std::io::Error::other("object id/version mismatch"));
            }
            vault_container::open_object(&mut file, &header, &data_key, &vault_id, f)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            Ok(())
        });
        if let Err(e) = write_result {
            let _ = std::fs::remove_file(&staged);
            return Err(e.into());
        }

        // Verify the staged plaintext against the manifest's expectations.
        let verify = (|| -> std::io::Result<bool> {
            let mut file = std::fs::File::open(&staged)?;
            let mut hasher = Sha256Writer::new();
            let mut buf = vec![0u8; 1024 * 1024];
            let mut total = 0u64;
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                total += n as u64;
            }
            Ok(hasher.finalize() == expected_hash && total == expected_size)
        })();
        match verify {
            Ok(true) => {}
            Ok(false) => {
                let _ = std::fs::remove_file(&staged);
                self.note_inline_integrity("exported content hash/size mismatch");
                return Err(CoreError::Integrity("exported content hash mismatch"));
            }
            Err(e) => {
                let _ = std::fs::remove_file(&staged);
                return Err(e.into());
            }
        }

        // Verified: atomically put it in place (same directory → same volume).
        if let Err(e) = std::fs::rename(&staged, dst) {
            let _ = std::fs::remove_file(&staged);
            return Err(e.into());
        }
        Ok(())
    }

    /// True when `dst` resolves inside the vault directory (including via a
    /// symlinked parent): exporting ciphertext-derived plaintext back into
    /// the container could overwrite container files with decrypted data.
    fn path_inside_vault(&self, dst: &Path) -> bool {
        fn normalize(p: &Path) -> PathBuf {
            let mut out = PathBuf::new();
            for c in p.components() {
                match c {
                    std::path::Component::CurDir => {}
                    std::path::Component::ParentDir => {
                        out.pop();
                    }
                    other => out.push(other.as_os_str()),
                }
            }
            out
        }
        // Lexical pass (handles `..` and missing parents).
        if let (Ok(d), Ok(r)) = (std::path::absolute(dst), std::path::absolute(self.layout.root())) {
            if normalize(&d).starts_with(normalize(&r)) {
                return true;
            }
        }
        // Canonical pass (handles symlinked parents).
        if let (Ok(p), Ok(r)) = (
            dst.parent().map(std::fs::canonicalize).unwrap_or(Ok(PathBuf::new())),
            std::fs::canonicalize(self.layout.root()),
        ) {
            if !p.as_os_str().is_empty() && p.starts_with(&r) {
                return true;
            }
        }
        false
    }

    /// Read a small text-like payload into memory (notes, text files).
    pub fn read_text(&mut self, id: &Id) -> Result<String, CoreError> {
        self.session()?;
        let (mime, is_note, version) = {
            let m = self.manifest()?;
            let e = m.find_object(id).ok_or(CoreError::NotFound)?;
            (e.meta.mime.clone(), e.object_type == ObjectType::Note, e.version)
        };
        if !is_note && !mime.as_deref().map(is_text_mime).unwrap_or(false) {
            return Err(CoreError::Invalid("not a text object"));
        }
        let mut buf = Vec::new();
        self.read_blob_into(id, version, &mut buf)?;
        let expected = self.manifest()?.find_object(id).map(|e| e.content_hash);
        if let Some(expected) = expected {
            let hash = vault_crypto::sha256(&buf);
            if hash != expected {
                self.note_inline_integrity("text content hash mismatch");
                return Err(CoreError::Integrity("content hash mismatch"));
            }
        }
        String::from_utf8(buf).map_err(|_| CoreError::Integrity("text is not utf-8"))
    }

    pub fn delete_object(&mut self, id: &Id) -> Result<(), CoreError> {
        self.require_writable()?;
        {
            let m = self.manifest.as_mut().ok_or(CoreError::Locked)?;
            let pos = m.objects.iter().position(|o| o.id == *id).ok_or(CoreError::NotFound)?;
            m.objects.remove(pos);
        }
        // Manifest first: a crash now leaves only an orphan blob (GC'd later).
        self.commit("object.delete")?;
        fault_point("after_commit_before_blob_delete");
        let path = self.object_path(id);
        if path.exists() {
            // Best-effort: the DEK dies with the blob (crypto-erasure of this object).
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }

    pub fn set_favorite(&mut self, id: &Id, favorite: bool) -> Result<(), CoreError> {
        self.require_writable()?;
        let m = self.manifest.as_mut().ok_or(CoreError::Locked)?;
        let e = m.objects.iter_mut().find(|o| o.id == *id).ok_or(CoreError::NotFound)?;
        if favorite {
            e.flags |= vault_container::manifest::object_flags::FAVORITE;
        } else {
            e.flags &= !vault_container::manifest::object_flags::FAVORITE;
        }
        e.updated_ms = now_ms();
        self.commit("object.favorite")?;
        Ok(())
    }

    fn note_inline_integrity(&mut self, detail: &str) {
        let now = now_ms();
        self.eval_trigger(
            Trigger::new(
                "object.auth_failed",
                80,
                vault_security::Severity::Error,
                "object",
                detail.to_string(),
            ),
            now,
        );
        let d = detail.to_string();
        let _ = self.audit_event("object.integrity_fail", "object", "fail", &d);
    }

    // ----------------------------------------------------- integrity / housekeeping

    fn set_pending_commit(&mut self, pending: bool) -> Result<(), CoreError> {
        self.control.pending_commit = pending;
        let vid = self.header.vault_id;
        self.control.save(&self.layout.control_file(), &vid)?;
        Ok(())
    }

    /// Heal interrupted updates: a blob whose version is newer than the
    /// manifest entry means the crash happened between blob write and
    /// manifest commit. Re-derive size/hash from the blob and commit.
    /// Blobs that cannot be decrypted are skipped (deep integrity
    /// verification reports them); they must not abort the heal of the
    /// remaining objects or strand `pending_commit` forever.
    fn heal_pending_updates(&mut self) -> Result<(), CoreError> {
        let session_vault_id = self.session()?.vault_id;
        let data_key = self.session()?.domains.data.clone();
        let mut healed = 0u32;
        let entries: Vec<(Id, u32)> = self
            .manifest()?
            .objects
            .iter()
            .map(|o| (o.id, o.version))
            .collect();

        for (id, entry_version) in entries {
            let path = self.object_path(&id);
            let mut file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let mut header_bytes = [0u8; OBJECT_HEADER_SIZE];
            if file.read_exact(&mut header_bytes).is_err() {
                continue;
            }
            let header = match ObjectHeader::parse(&header_bytes) {
                Ok(h) => h,
                Err(_) => continue,
            };
            if header.version <= entry_version {
                continue;
            }
            // Newer blob: stream it into a hash sink to recover the
            // authenticated size+hash without buffering the payload.
            let mut sink = HashingSink::new();
            if let Err(e) =
                vault_container::open_object(&mut file, &header, &data_key, &session_vault_id, &mut sink)
            {
                self.pending_events.push((
                    now_ms(),
                    "container.heal".into(),
                    "storage".into(),
                    "fail".into(),
                    format!("{}: unreadable newer blob ({e})", vault_crypto::to_hex16(&id)),
                ));
                continue;
            }
            let total = sink.len;
            let hash = sink.hasher.finalize();
            {
                let m = self.manifest.as_mut().ok_or(CoreError::Locked)?;
                if let Some(e) = m.objects.iter_mut().find(|o| o.id == id) {
                    e.version = header.version;
                    e.size = total;
                    e.chunk_count = header.chunk_count;
                    e.content_hash = hash;
                    e.updated_ms = now_ms();
                    healed += 1;
                }
            }
        }
        if healed > 0 {
            self.commit("container.heal")?;
        }
        self.set_pending_commit(false)?;
        Ok(())
    }

    /// Remove crash debris: temp files, orphan manifests, orphan blobs.
    fn collect_garbage(&mut self) -> Result<(), CoreError> {
        let generation = self.peek_generation()?;
        let _ = cleanup_temp_files(self.layout.root());
        let _ = cleanup_temp_files(&self.layout.manifest_dir());
        let _ = cleanup_temp_files(&self.layout.objects_dir());
        let _ = cleanup_temp_files(&self.layout.state_dir());
        let _ = cleanup_temp_files(&self.layout.audit_dir());

        // Manifests newer than CURRENT are uncommitted leftovers.
        if let Ok(entries) = std::fs::read_dir(self.layout.manifest_dir()) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some(num) = name
                    .strip_prefix("manifest-")
                    .and_then(|s| s.strip_suffix(".bin"))
                    // Generation numbers are DECIMAL (`manifest-{:016}.bin`);
                    // the old hex parse made `…000000000000000a` style names
                    // parse as generation 10 — deleting the *current* manifest
                    // at generation ≥ 10 and bricking the vault.
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    if num > generation {
                        let _ = std::fs::remove_file(entry.path());
                        self.pending_events.push((
                            now_ms(),
                            "container.orphan_detected".into(),
                            "storage".into(),
                            "ok".into(),
                            format!("removed uncommitted manifest {}", num),
                        ));
                    }
                }
            }
        }

        // Blobs not referenced by the manifest are import debris.
        let manifest = self.manifest()?;
        let known: std::collections::HashSet<[u8; 16]> =
            manifest.objects.iter().map(|o| o.id).collect();
        let mut orphans: Vec<PathBuf> = Vec::new();
        if let Ok(shards) = std::fs::read_dir(self.layout.objects_dir()) {
            for shard in shards.flatten() {
                if let Ok(files) = std::fs::read_dir(shard.path()) {
                    for f in files.flatten() {
                        if let Some(name) = f.path().file_stem().map(|s| s.to_string_lossy().into_owned()) {
                            if let Some(id) = vault_container::parse_id_hex(&name) {
                                if !known.contains(&id) {
                                    orphans.push(f.path());
                                }
                            }
                        }
                    }
                }
            }
        }
        for o in orphans {
            let _ = std::fs::remove_file(o);
            self.pending_events.push((
                now_ms(),
                "container.orphan_detected".into(),
                "storage".into(),
                "ok".into(),
                "removed orphan object blob".into(),
            ));
        }
        Ok(())
    }

    /// Deep integrity verification: decrypt every object, verify content
    /// hashes and header/manifest consistency.
    ///
    /// Note: the manifest hash *chain* and the rollback witness are enforced
    /// on every state load via `read_verified_manifest_bytes` (unlock, rekey,
    /// recovery); this function walks the object layer and folds the current
    /// lockdown state into the report rather than re-walking the chain.
    pub fn verify_integrity(&mut self, deep: bool) -> Result<IntegrityReport, CoreError> {
        let s = self.session()?;
        let mut report = IntegrityReport { ok: true, checked_objects: 0, failed: Vec::new(), warnings: Vec::new() };
        let vault_id = s.vault_id;
        let data_key = s.domains.data.clone();

        let entries: Vec<(Id, u32, [u8; 32], u64, ObjectType)> = self
            .manifest()?
            .objects
            .iter()
            .map(|o| (o.id, o.version, o.content_hash, o.size, o.object_type))
            .collect();

        for (id, version, content_hash, size, _kind) in entries {
            let path = self.object_path(&id);
            let mut file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(_) => {
                    report.ok = false;
                    report.failed.push(format!("{}: blob missing", vault_crypto::to_hex16(&id)));
                    continue;
                }
            };
            let mut header_bytes = [0u8; OBJECT_HEADER_SIZE];
            if file.read_exact(&mut header_bytes).is_err() {
                report.ok = false;
                report.failed.push(format!("{}: header truncated", vault_crypto::to_hex16(&id)));
                continue;
            }
            let header = match ObjectHeader::parse(&header_bytes) {
                Ok(h) => h,
                Err(e) => {
                    report.ok = false;
                    report.failed.push(format!("{}: header invalid ({})", vault_crypto::to_hex16(&id), e));
                    continue;
                }
            };
            if header.version != version {
                report.ok = false;
                report.failed.push(format!(
                    "{}: version mismatch (blob {} vs manifest {})",
                    vault_crypto::to_hex16(&id),
                    header.version,
                    version
                ));
                continue;
            }
            report.checked_objects += 1;
            if deep {
                // Stream into a hash sink — never buffer the payload.
                let mut sink = HashingSink::new();
                match vault_container::open_object(&mut file, &header, &data_key, &vault_id, &mut sink) {
                    Ok(_) => {
                        let total = sink.len;
                        let hash = sink.hasher.finalize();
                        if hash != content_hash {
                            report.ok = false;
                            report.failed.push(format!("{}: content hash mismatch", vault_crypto::to_hex16(&id)));
                        }
                        if total != size {
                            report.ok = false;
                            report.failed.push(format!("{}: size mismatch", vault_crypto::to_hex16(&id)));
                        }
                    }
                    Err(e) => {
                        report.ok = false;
                        report.failed.push(format!("{}: decrypt failed ({})", vault_crypto::to_hex16(&id), e));
                    }
                }
            }
        }

        // A quarantined/restricted/locked vault is never "integrity ok",
        // even when every object individually verifies.
        let st = self.lockdown.state();
        if !matches!(st, VaultState::Normal | VaultState::Suspicious) {
            report.ok = false;
            report.warnings.push(format!("lockdown state: {}", st.as_str()));
        }

        if !report.failed.is_empty() {
            let now = now_ms();
            self.eval_trigger(
                Trigger::new(
                    "object.auth_failed",
                    85,
                    vault_security::Severity::Error,
                    "integrity",
                    format!("{} object(s) failed verification", report.failed.len()),
                ),
                now,
            );
        }
        let ok = report.ok;
        let detail = format!("checked={} ok={}", report.checked_objects, ok);
        self.audit_event("integrity.verify", "integrity", if ok { "ok" } else { "fail" }, &detail)?;
        Ok(report)
    }

    // ------------------------------------------------------------- recovery

    /// Generate + attach a new recovery key. Returns the display form
    /// (shown exactly once; Vault does not persist it).
    pub fn enable_recovery(&mut self) -> Result<String, CoreError> {
        // Rotating key material is a write like any other: LOCKED/RESTRICTED
        // must not be able to swap the recovery envelope.
        let s = self.require_writable()?;
        let root = s.root.clone();
        let rk = RecoveryKey::generate();
        let display = rk.to_display();
        self.header.enable_recovery(&root, &rk.as_key32());
        let bytes = self.header.to_bytes();
        atomic_write(&self.layout.header(), &bytes)?;
        fault_point("after_header_recovery_write");
        self.audit_event("recovery.enable", "recovery", "ok", "recovery key issued")?;
        Ok(display)
    }

    pub fn disable_recovery(&mut self) -> Result<(), CoreError> {
        self.require_writable()?;
        self.header.disable_recovery();
        atomic_write(&self.layout.header(), &self.header.to_bytes())?;
        self.audit_event("recovery.disable", "recovery", "ok", "recovery envelope destroyed")?;
        Ok(())
    }

    /// Recovery unlock: unwraps the root key with the recovery key, installs
    /// the session, and immediately requires a password re-wrap.
    pub fn unlock_with_recovery(
        &mut self,
        recovery_display: &str,
        new_password: &SecretBytes,
    ) -> Result<(), CoreError> {
        if self.header.rekey_pending() {
            // The pending transition's `next` envelope is password-wrapped;
            // only a password unlock can drive it to completion.
            return Err(CoreError::Refused(
                "domain rekey in progress; master password required",
            ));
        }
        if new_password.len() < 8 {
            return Err(CoreError::Invalid("new password must be at least 8 characters"));
        }
        let rk = RecoveryKey::from_display(recovery_display)?;
        let root = vault_recovery::unlock_with_recovery(&self.header, &rk)?;
        let mut new_header = self.header.clone();
        let mut new_kdf = self.header.kdf.clone();
        new_kdf.salt = vault_crypto::random_bytes();
        new_header.rewrap_root(new_kdf, new_password, &root)?;

        // Commit the new header only after full state load succeeds — routed
        // through the verified read so hash/chain/vault-id/rollback witnesses
        // and lockdown evaluation cannot be skipped on this path (the old
        // inline read verified only the CURRENT hash and then trusted the
        // result for `max_seen_generation`).
        let vault_id = self.header.vault_id;
        let domains = DomainKeys::derive(&root, &vault_id);
        let (generation, cur_hash, manifest_bytes) = self.read_verified_manifest_bytes()?;
        let manifest = Manifest::open(&domains.meta, &manifest_bytes)?;
        if manifest.generation != generation {
            return Err(CoreError::Integrity("manifest generation mismatch"));
        }

        atomic_write(&self.layout.header(), &new_header.to_bytes())?;
        self.header = new_header;
        self.session = Some(Session { root, domains, vault_id });
        self.manifest = Some(manifest);
        self.control.failed_attempts = 0;
        self.control.lockout_until_ms = 0;
        self.control.max_seen_generation = generation;
        self.control.seen_manifest_hash = vault_crypto::to_hex(&cur_hash);
        self.control.save(&self.layout.control_file(), &vault_id)?;
        let _ = self.open_audit();
        let _ = self.flush_pending_events();
        self.audit_event("recovery.unlock", "recovery", "ok", "recovered; password re-wrapped")?;
        Ok(())
    }

    /// Change the master password (requires the current password as proof).
    pub fn change_password(&mut self, current: &SecretBytes, new: &SecretBytes) -> Result<(), CoreError> {
        let s = self.session()?;
        let root = s.root.clone();
        let vault_id = s.vault_id;
        // Proof: current password must unwrap the same root key.
        let got = self.header.unwrap_root(current)?;
        if got.as_bytes() != root.as_bytes() {
            return Err(CoreError::AuthFailed);
        }
        if new.len() < 8 {
            return Err(CoreError::Invalid("new password must be at least 8 characters"));
        }
        let mut new_kdf = self.header.kdf.clone();
        new_kdf.salt = vault_crypto::random_bytes();
        self.header.rewrap_root(new_kdf, new, &root)?;
        atomic_write(&self.layout.header(), &self.header.to_bytes())?;
        fault_point("after_header_password_change");
        let _ = vault_id;
        self.audit_event("auth.password_change", "auth", "ok", "")?;
        Ok(())
    }

    // -------------------------------------------------------- crypto-erase

    /// Complete an armed two-phase domain rekey (scope `Domain`).
    ///
    /// Called from `unlock` when `rekey_state == 1` (fresh or after a crash)
    /// and from `crypto_erase(Domain)` right after arming. Every step probes
    /// old vs new keys first, so re-running after a crash migrates only what
    /// is still on the old root key — each phase is idempotent. Returns the
    /// new root key; the caller derives fresh domain keys from it.
    fn drive_rekey(&mut self, password: &SecretBytes, root_old: Key32) -> Result<Key32, CoreError> {
        if !self.header.rekey_pending() {
            return Err(CoreError::Invalid("no pending domain rekey"));
        }
        let root_new = match self.header.unwrap_next(password) {
            Ok(r) => r,
            Err(_) => {
                self.eval_trigger(
                    Trigger::new(
                        "rekey.next_auth_failed",
                        100,
                        vault_security::Severity::Critical,
                        "container",
                        "pending rekey envelope failed authentication",
                    ),
                    now_ms(),
                );
                return Err(CoreError::Integrity(
                    "pending rekey envelope authentication failed",
                ));
            }
        };
        let vault_id = self.header.vault_id;
        let d_old = DomainKeys::derive(&root_old, &vault_id);
        let d_new = DomainKeys::derive(&root_new, &vault_id);

        // Key-independent verification (CURRENT hash, hash chain, and the
        // anti-rollback witness) must pass before anything is written —
        // resume must not become a rollback bypass.
        let (generation, _cur_hash, manifest_bytes) = self.read_verified_manifest_bytes()?;

        // Probe which root key currently opens the manifest.
        let (mut manifest, manifest_is_old) = match Manifest::open(&d_old.meta, &manifest_bytes) {
            Ok(m) => (m, true),
            Err(_) => match Manifest::open(&d_new.meta, &manifest_bytes) {
                Ok(m) => (m, false),
                Err(_) => {
                    self.eval_trigger(
                        Trigger::new(
                            "rekey.manifest_undecryptable",
                            100,
                            vault_security::Severity::Critical,
                            "container",
                            "manifest opens under neither root key during rekey resume",
                        ),
                        now_ms(),
                    );
                    return Err(CoreError::Integrity(
                        "manifest undecryptable during domain rekey",
                    ));
                }
            },
        };
        if manifest.generation != generation {
            return Err(CoreError::Integrity("manifest generation mismatch"));
        }

        // Phase A: re-wrap every object DEK still on the old data key.
        let ids: Vec<Id> = manifest.objects.iter().map(|o| o.id).collect();
        for id in &ids {
            self.rewrap_blob_dek(id, &d_old.data, &d_new.data, &vault_id)?;
        }
        fault_point("after_rekey_blobs");

        // Phase B: re-seal the audit log under the new audit key when it
        // still opens with the old one (already-migrated logs are skipped).
        let audit_path = self.layout.audit_file();
        if AuditLog::open(&audit_path, d_old.audit.clone()).is_ok() {
            AuditLog::rekey(&audit_path, &d_old.audit, &d_new.audit)?;
        }
        fault_point("after_rekey_audit");

        // Phase C: re-seal the manifest under the new meta key and commit
        // generation+1 atomically (manifest file, then CURRENT, then witness).
        if manifest_is_old {
            manifest.generation = generation + 1;
            manifest.committed_at_ms = now_ms();
            let prev_bytes = vault_storage::read_file_capped(
                &self.layout.manifest_file(generation),
                512 * 1024 * 1024,
            )?;
            manifest.prev_manifest_hash = manifest_hash(&prev_bytes);
            let sealed = manifest.seal(&d_new.meta, &vault_id)?;
            let hash = manifest_hash(&sealed);
            atomic_write(&self.layout.manifest_file(manifest.generation), &sealed)?;
            atomic_write(
                &self.layout.current(),
                &encode_current(manifest.generation, &hash),
            )?;
            fault_point("after_rekey_manifest");
            self.control.max_seen_generation = manifest.generation;
            self.control.seen_manifest_hash = vault_crypto::to_hex(&hash);
            if let Err(e) = self.control.save(&self.layout.control_file(), &vault_id) {
                self.pending_events.push((
                    now_ms(),
                    "control.unavailable".into(),
                    "control".into(),
                    "fail".into(),
                    format!("rollback witness save failed after rekey commit: {e}"),
                ));
                return Err(e.into());
            }
        }

        // Phase D: promote the next envelope to current. The recovery
        // envelope still wraps the OLD root key and cannot be re-created
        // without the recovery secret — it is crypto-erased here.
        self.header.finalize_rekey()?;
        if self.header.has_recovery() {
            self.header.disable_recovery();
        }
        atomic_write(&self.layout.header(), &self.header.to_bytes())?;
        fault_point("after_rekey_finalize");
        Ok(root_new)
    }

    /// Re-wrap a single blob's DEK under the new data key (domain rekey).
    ///
    /// The rewrite is a streaming copy into a temp file + atomic rename, so
    /// a crash leaves either the complete old or the complete new header —
    /// never a torn one. Blobs whose DEK already opens under `new_data` are
    /// left untouched (idempotency); blobs missing on disk **or with a
    /// truncated/corrupt header** are skipped, not fatal — same rationale as
    /// missing blobs: their condition predates the rekey and is reported by
    /// deep integrity verification instead of bricking the migration.
    fn rewrap_blob_dek(
        &self,
        id: &Id,
        old_data: &Key32,
        new_data: &Key32,
        vault_id: &[u8; 16],
    ) -> Result<(), CoreError> {
        let path = self.object_path(id);
        let mut file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => return Ok(()),
        };
        let mut header_bytes = [0u8; OBJECT_HEADER_SIZE];
        if file.read_exact(&mut header_bytes).is_err() {
            return Ok(()); // truncated header: skipped like a missing blob
        }
        let mut header = match ObjectHeader::parse(&header_bytes) {
            Ok(h) => h,
            Err(_) => return Ok(()), // corrupt header: skipped, not fatal
        };
        let migrated = match header.rewrap_dek(old_data, new_data, vault_id) {
            Ok(v) => v,
            // DEK opens under neither key: corrupt/unreadable. Skip — after
            // finalize the old key is gone anyway (crypto-erasure of an
            // already-broken blob); deep verification reports it.
            Err(_) => return Ok(()),
        };
        if !migrated {
            return Ok(()); // already migrated
        }
        let new_header = header.to_bytes();
        atomic_write_from(&path, |out| {
            out.write_all(&new_header)?;
            std::io::copy(&mut file, out)?;
            Ok(())
        })?;
        Ok(())
    }

    /// Drive the armed domain rekey to completion and install the new
    /// session. Any error here means the container may be half-migrated —
    /// the caller must drop the session (see `crypto_erase(Domain)`).
    fn finish_domain_rekey(
        &mut self,
        pw: &SecretBytes,
        root_old: Key32,
        root_new: Key32,
        vault_id: [u8; 16],
    ) -> Result<(), CoreError> {
        let confirmed = self.drive_rekey(pw, root_old)?;
        if confirmed.as_bytes() != root_new.as_bytes() {
            return Err(CoreError::Integrity("domain rekey key mismatch"));
        }
        // Install the session under the new root and reload state
        // (the migration committed generation+1 to disk).
        let domains = DomainKeys::derive(&root_new, &vault_id);
        self.session = Some(Session {
            root: root_new,
            domains,
            vault_id,
        });
        let (_gen, _hash, bytes) = self.read_verified_manifest_bytes()?;
        let meta_key = self.session.as_ref().unwrap().domains.meta.clone();
        self.manifest = Some(Manifest::open(&meta_key, &bytes)?);
        self.audit = None;
        let _ = self.open_audit();
        let _ = self.flush_pending_events();
        Ok(())
    }

    /// Crypto-erasure. Destroys key material — never storage media.
    /// Irreversible scopes (`Vault`, `Domain`) require the master password
    /// as deliberate confirmation.
    pub fn crypto_erase(&mut self, scope: EraseScope, password: Option<&SecretBytes>) -> Result<(), CoreError> {
        match scope {
            EraseScope::Session => {
                self.lock(LockReason::Manual);
                Ok(())
            }
            EraseScope::Object => Err(CoreError::Invalid("object scope requires delete_object")),
            EraseScope::Recovery => self.disable_recovery(),
            EraseScope::Domain => {
                let pw = password.ok_or(CoreError::EraseConfirmationRequired)?;
                // Requires an unlocked vault (manifest drives blob migration)
                // and proof of possession with the current master password.
                let (root_old, vault_id) = {
                    let s = self.session()?;
                    (s.root.clone(), s.vault_id)
                };
                if self.header.rekey_pending() {
                    return Err(CoreError::Refused(
                        "a domain rekey is already pending; unlock first to resume it",
                    ));
                }
                let got = self.header.unwrap_root(pw).map_err(|_| CoreError::AuthFailed)?;
                if got.as_bytes() != root_old.as_bytes() {
                    return Err(CoreError::AuthFailed);
                }
                let had_recovery = self.header.has_recovery();

                // Phase 1 (arm): install the next root envelope while the
                // current one keeps working — a crash here is resumable.
                let root_new = Key32::random();
                let mut next_kdf = self.header.kdf.clone();
                next_kdf.salt = vault_crypto::random_bytes();
                let header_before_arm = self.header.clone();
                self.header.arm_rekey(pw, next_kdf, &root_new)?;
                if let Err(e) = atomic_write(&self.layout.header(), &self.header.to_bytes()) {
                    // Disk never saw the arm — keep memory consistent with it
                    // instead of leaving a phantom pending transition.
                    self.header = header_before_arm;
                    return Err(e.into());
                }
                fault_point("after_rekey_arm");

                // Phase 2+3: migrate blobs/audit/manifest, then finalize.
                // Probing finds everything on the old key (nothing migrated
                // yet), so this runs the full migration; on crash the next
                // unlock resumes it idempotently. Any failure drops the
                // session — never keep a session on keys that may no longer
                // match the container (the migration may be half-applied).
                if let Err(e) = self.finish_domain_rekey(pw, root_old, root_new, vault_id) {
                    self.lock(LockReason::Tamper);
                    return Err(e);
                }
                let recovery_dropped = had_recovery && !self.header.has_recovery();
                let detail = if recovery_dropped {
                    "root key rotated; recovery envelope destroyed"
                } else {
                    "root key rotated; previous domain keys unrecoverable"
                };
                self.audit_event("crypto_erase.domain", "crypto", "ok", detail)?;
                Ok(())
            }
            EraseScope::Vault => {
                let pw = password.ok_or(CoreError::EraseConfirmationRequired)?;
                // Proof of possession before irreversible destruction.
                let _ = self.header.unwrap_root(pw)?;
                // 1. Destroy the root envelope (crypto-erasure: keys die here).
                let mut garbage = self.header.to_bytes();
                for b in garbage.iter_mut() {
                    *b = vault_crypto::random_bytes::<1>()[0];
                }
                atomic_write(&self.layout.header(), &garbage)?;
                fault_point("after_key_destruction");
                // 2. Remove container files (they are ciphertext without keys).
                let _ = std::fs::remove_dir_all(self.layout.root());
                self.session = None;
                // Wipe plaintext metadata (names, tags, previews) — keys are
                // gone but the manifest may still hold readable strings.
                if let Some(mut m) = self.manifest.take() {
                    m.wipe();
                }
                self.audit = None;
                Ok(())
            }
        }
    }

    // ---------------------------------------------------------------- misc

    pub fn security_report(&mut self) -> SecurityReport {
        let recent = self
            .audit
            .as_mut()
            .and_then(|a| a.recent(50).ok())
            .unwrap_or_default();
        SecurityReport {
            lockdown_state: self.lockdown.state().as_str().to_string(),
            platform_capability: format!("{:?}", self.capability),
            binary_verified: self.control.binary_hash == vault_crypto::to_hex(&self.binary_hash),
            generation: self.manifest.as_ref().map(|m| m.generation).unwrap_or(0),
            witnessed_generation: self.control.max_seen_generation,
            has_recovery: self.header.has_recovery(),
            kdf_memory_kib: self.header.kdf.memory_kib,
            kdf_iterations: self.header.kdf.iterations,
            recent_events: recent,
            object_count: self.manifest.as_ref().map(|m| m.objects.len() as u64).unwrap_or(0),
            integrity_ok: self.lockdown.state() == VaultState::Normal
                || self.lockdown.state() == VaultState::Suspicious,
        }
    }

    pub fn audit_events(&mut self, limit: usize) -> Result<Vec<AuditEvent>, CoreError> {
        match self.audit.as_mut() {
            Some(a) => a.recent(limit),
            None => Err(CoreError::Locked),
        }
    }

    pub fn lockdown_events(&self) -> Vec<vault_security::SecurityEvent> {
        self.lockdown.events().to_vec()
    }

    pub fn acknowledge_findings(&mut self) -> Result<(), CoreError> {
        // Acknowledging requires a proven session: a locked engine cannot
        // clear findings without re-authenticating first.
        self.session()?;
        let now = now_ms();
        let before = self.lockdown.events().len();
        self.lockdown.acknowledge(now);
        self.save_lockdown();
        // `acknowledge` is a no-op unless the state was SUSPICIOUS — only
        // log when it actually recorded the acknowledgment.
        let ack_detail = {
            let evs = self.lockdown.events();
            if evs.len() > before {
                Some(evs.last().unwrap().detail.clone())
            } else {
                None
            }
        };
        if let Some(detail) = ack_detail {
            let _ = self.audit_event("operator.acknowledge", "lockdown", "ok", &detail);
        }
        Ok(())
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    pub fn vault_dir(&self) -> &Path {
        self.layout.root()
    }

    pub fn platform_capability(&self) -> PlatformCapability {
        self.capability
    }

    pub fn probe_platform() -> PlatformCapability {
        probe_capabilities()
    }
}

impl Drop for VaultEngine {
    fn drop(&mut self) {
        // Plaintext metadata (names, tags, previews) must not outlive the
        // engine even when the caller forgets to lock.
        if let Some(mut m) = self.manifest.take() {
            m.wipe();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_below_threshold_has_no_lockout() {
        assert_eq!(lockout_delay_ms(0), None);
        assert_eq!(lockout_delay_ms(4), None);
    }

    #[test]
    fn backoff_doubles_per_failure() {
        assert_eq!(lockout_delay_ms(5), Some(300_000)); // 5 min
        assert_eq!(lockout_delay_ms(6), Some(600_000)); // 10 min
        assert_eq!(lockout_delay_ms(7), Some(1_200_000)); // 20 min
        assert_eq!(lockout_delay_ms(8), Some(2_400_000)); // 40 min
    }

    #[test]
    fn backoff_caps_at_one_hour() {
        assert_eq!(lockout_delay_ms(9), Some(MAX_LOCKOUT_MS)); // would be 80 min
        assert_eq!(lockout_delay_ms(10), Some(MAX_LOCKOUT_MS));
        assert_eq!(lockout_delay_ms(100), Some(MAX_LOCKOUT_MS));
        assert_eq!(lockout_delay_ms(u32::MAX), Some(MAX_LOCKOUT_MS));
    }
}
