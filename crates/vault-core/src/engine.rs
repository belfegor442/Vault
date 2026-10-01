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
    probe_capabilities, ControlState, Lockdown, PlatformCapability, Trigger, VaultState,
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
        let mut lockdown = Lockdown::new();
        let control = match ControlState::load(&layout.control_file(), &vault_id) {
            Ok(Some(c)) => c,
            Ok(None) => ControlState::new(&vault_crypto::to_hex16(&vault_id), now_ms(), &vault_crypto::to_hex(&binary_hash)),
            Err(_) => {
                lockdown.evaluate(
                    Trigger::new(
                        "control.unavailable",
                        60,
                        vault_security::Severity::Warning,
                        "control",
                        "control state unreadable; throttle/rollback witness reset",
                    ),
                    now_ms(),
                );
                ControlState::new(&vault_crypto::to_hex16(&vault_id), now_ms(), &vault_crypto::to_hex(&binary_hash))
            }
        };

        // Tamper evidence for the executable (documented as weak: an attacker
        // with write access can update both sides).
        if !control.binary_hash.is_empty()
            && control.binary_hash != vault_crypto::to_hex(&binary_hash)
        {
            lockdown.evaluate(
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

        let capability = if control.capability == vault_security::CAPABILITY_DPAPI {
            PlatformCapability::Dpapi
        } else {
            PlatformCapability::DpapiUnavailable
        };

        Ok(Self {
            layout,
            header,
            control,
            capability,
            lockdown,
            binary_hash,
            session: None,
            manifest: None,
            audit: None,
            pending_events: Vec::new(),
        })
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
        let _ = self.control.save(&self.layout.control_file(), &vault_id);

        // Quarantine-and-restart failures are already reflected in the
        // lockdown record; unlock must not fail because of them.
        let _ = self.open_audit();
        let _ = self.flush_pending_events();
        self.lockdown.on_successful_auth(now);

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

        self.audit_event("vault.unlock", "auth", "ok", "")?;
        Ok(())
    }

    fn register_failed_attempt(&mut self, now: u64) -> Option<u64> {
        self.control.failed_attempts = self.control.failed_attempts.saturating_add(1);
        if self.control.failed_attempts >= MAX_ATTEMPTS_BEFORE_LOCKOUT {
            let steps = self.control.failed_attempts - MAX_ATTEMPTS_BEFORE_LOCKOUT;
            let backoff = BASE_LOCKOUT_MS.saturating_mul(1u64 << steps.min(3));
            let backoff = backoff.min(MAX_LOCKOUT_MS);
            self.control.lockout_until_ms = now + backoff;
        }
        if self.control.failed_attempts.is_multiple_of(MAX_ATTEMPTS_BEFORE_LOCKOUT) {
            self.lockdown.evaluate(
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
        let _ = self.control.save(&self.layout.control_file(), &self.header.vault_id);
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
        if matches!(self.lockdown.state(), VaultState::Restricted | VaultState::Critical) {
            return Err(CoreError::Refused("lockdown policy blocks writes"));
        }
        Ok(s)
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
        let manifest_path = self.layout.manifest_file(generation);
        let manifest_bytes = vault_storage::read_file_capped(&manifest_path, 512 * 1024 * 1024)?;
        if manifest_hash(&manifest_bytes) != cur_hash {
            self.lockdown.evaluate(
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
            self.lockdown.evaluate(
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
                self.lockdown.evaluate(
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
            self.lockdown.evaluate(
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
                self.lockdown.evaluate(
                    Trigger::new(
                        "audit.chain_broken",
                        85,
                        vault_security::Severity::Error,
                        "audit",
                        "audit chain failed verification; log quarantined",
                    ),
                    now_ms(),
                );
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
        }
        Ok(())
    }

    /// Atomic manifest commit: seal gen+1, write manifest file, then CURRENT,
    /// then update the rollback witness.
    fn commit(&mut self, detail: &str) -> Result<(), CoreError> {
        let s = self.session()?;
        let vault_id = s.vault_id;
        let meta_key = s.domains.meta.clone();
        let manifest = self.manifest.as_mut().ok_or(CoreError::Locked)?;
        manifest.generation += 1;
        manifest.committed_at_ms = now_ms();
        let gen = manifest.generation;

        let prev_path = self.layout.manifest_file(gen - 1);
        let prev_bytes = vault_storage::read_file_capped(&prev_path, 512 * 1024 * 1024)?;
        manifest.prev_manifest_hash = manifest_hash(&prev_bytes);

        let sealed = manifest.seal(&meta_key, &vault_id)?;
        let hash = manifest_hash(&sealed);
        atomic_write(&self.layout.manifest_file(gen), &sealed)?;
        fault_point("after_manifest_write");
        atomic_write(&self.layout.current(), &encode_current(gen, &hash))?;
        fault_point("after_current_write");

        self.control.max_seen_generation = gen;
        self.control.seen_manifest_hash = vault_crypto::to_hex(&hash);
        let _ = self.control.save(&self.layout.control_file(), &vault_id);

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

    fn read_blob_into(&self, id: &Id, out: &mut Vec<u8>) -> Result<(), CoreError> {
        let s = self.session()?;
        let path = self.object_path(id);
        let mut file = std::fs::File::open(&path)?;
        let mut header_bytes = [0u8; OBJECT_HEADER_SIZE];
        file.read_exact(&mut header_bytes)?;
        let header = ObjectHeader::parse(&header_bytes)?;
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

    pub fn get_note(&self, id: &Id) -> Result<Note, CoreError> {
        let _s = self.session()?;
        let m = self.manifest()?;
        let e = m.find_object(id).ok_or(CoreError::NotFound)?;
        if e.object_type != ObjectType::Note {
            return Err(CoreError::Invalid("not a note"));
        }
        let mut buf = Vec::new();
        self.read_blob_into(id, &mut buf)?;
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

    pub fn get_password(&self, id: &Id) -> Result<PasswordRecord, CoreError> {
        self.session()?;
        let e = self.manifest()?.find_object(id).ok_or(CoreError::NotFound)?;
        if e.object_type != ObjectType::Password {
            return Err(CoreError::Invalid("not a password entry"));
        }
        let mut buf = Vec::new();
        self.read_blob_into(id, &mut buf)?;
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
            e.flags = if favorite { vault_container::manifest::object_flags::FAVORITE } else { 0 };
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

    /// Decrypt an object to `dst` (user-chosen path, staged in its own
    /// directory and atomically renamed). Verifies the content hash.
    pub fn export_file(&mut self, id: &Id, dst: &Path) -> Result<(), CoreError> {
        let s = self.session()?;
        let m = self.manifest()?;
        let e = m.find_object(id).ok_or(CoreError::NotFound)?;
        if e.object_type != ObjectType::File {
            return Err(CoreError::Invalid("not a file"));
        }
        let expected_hash = e.content_hash;
        let expected_size = e.size;
        let path = self.object_path(id);
        let data_key = s.domains.data.clone();
        let vault_id = s.vault_id;

        atomic_write_from(dst, |f| {
            let mut file = std::fs::File::open(&path)?;
            let mut header_bytes = [0u8; OBJECT_HEADER_SIZE];
            file.read_exact(&mut header_bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let header = ObjectHeader::parse(&header_bytes)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            vault_container::open_object(&mut file, &header, &data_key, &vault_id, f)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            Ok(())
        })?;

        // Verify against the manifest's authenticated expectations.
        let mut hasher = Sha256Writer::new();
        let mut file = std::fs::File::open(dst)?;
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
        if hasher.finalize() != expected_hash {
            let _ = std::fs::remove_file(dst);
            self.note_inline_integrity("exported content hash mismatch");
            return Err(CoreError::Integrity("exported content hash mismatch"));
        }
        if total != expected_size {
            let _ = std::fs::remove_file(dst);
            return Err(CoreError::Integrity("exported size mismatch"));
        }
        Ok(())
    }

    /// Read a small text-like payload into memory (notes, text files).
    pub fn read_text(&mut self, id: &Id) -> Result<String, CoreError> {
        self.session()?;
        let (mime, is_note) = {
            let m = self.manifest()?;
            let e = m.find_object(id).ok_or(CoreError::NotFound)?;
            (e.meta.mime.clone(), e.object_type == ObjectType::Note)
        };
        if !is_note && !mime.as_deref().map(is_text_mime).unwrap_or(false) {
            return Err(CoreError::Invalid("not a text object"));
        }
        let mut buf = Vec::new();
        self.read_blob_into(id, &mut buf)?;
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
        self.lockdown.evaluate(
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
            // Newer blob: decrypt fully to recover the authenticated size+hash.
            let mut out = Vec::new();
            vault_container::open_object(&mut file, &header, &data_key, &session_vault_id, &mut out)?;
            let hash = vault_crypto::sha256(&out);
            drop(out);
            {
                let m = self.manifest.as_mut().ok_or(CoreError::Locked)?;
                if let Some(e) = m.objects.iter_mut().find(|o| o.id == id) {
                    e.version = header.version;
                    e.size = header.plaintext_len;
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
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
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
    /// hashes, manifest chain, header structure.
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
                let mut out = Vec::new();
                match vault_container::open_object(&mut file, &header, &data_key, &vault_id, &mut out) {
                    Ok(_) => {
                        if vault_crypto::sha256(&out) != content_hash {
                            report.ok = false;
                            report.failed.push(format!("{}: content hash mismatch", vault_crypto::to_hex16(&id)));
                        }
                        if out.len() as u64 != size {
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

        if !report.ok {
            let now = now_ms();
            self.lockdown.evaluate(
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
        let s = self.session()?;
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

        // Commit the new header only after full state load succeeds.
        let vault_id = self.header.vault_id;
        let domains = DomainKeys::derive(&root, &vault_id);
        let cur_bytes = vault_storage::read_file_capped(&self.layout.current(), 4096)?;
        let (generation, cur_hash) = decode_current(&cur_bytes)?;
        let manifest_bytes =
            vault_storage::read_file_capped(&self.layout.manifest_file(generation), 512 * 1024 * 1024)?;
        if manifest_hash(&manifest_bytes) != cur_hash {
            return Err(CoreError::Integrity("manifest hash mismatch"));
        }
        let manifest = Manifest::open(&domains.meta, &manifest_bytes)?;

        atomic_write(&self.layout.header(), &new_header.to_bytes())?;
        self.header = new_header;
        self.session = Some(Session { root, domains, vault_id });
        self.manifest = Some(manifest);
        self.control.failed_attempts = 0;
        self.control.lockout_until_ms = 0;
        self.control.max_seen_generation = generation;
        self.control.seen_manifest_hash = vault_crypto::to_hex(&cur_hash);
        let _ = self.control.save(&self.layout.control_file(), &vault_id);
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
                self.lockdown.evaluate(
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
                    self.lockdown.evaluate(
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
            let _ = self.control.save(&self.layout.control_file(), &vault_id);
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
    /// left untouched (idempotency); blobs missing on disk are skipped, not
    /// fatal — their absence predates the rekey and is reported by deep
    /// integrity verification instead.
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
        file.read_exact(&mut header_bytes)
            .map_err(|_| CoreError::Integrity("blob header truncated"))?;
        let mut header = ObjectHeader::parse(&header_bytes)?;
        if !header.rewrap_dek(old_data, new_data, vault_id)? {
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
                self.header.arm_rekey(pw, next_kdf, &root_new)?;
                atomic_write(&self.layout.header(), &self.header.to_bytes())?;
                fault_point("after_rekey_arm");

                // Phase 2+3: migrate blobs/audit/manifest, then finalize.
                // Probing finds everything on the old key (nothing migrated
                // yet), so this runs the full migration; on crash the next
                // unlock resumes it idempotently.
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
                self.manifest = None;
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
        let now = now_ms();
        self.lockdown.acknowledge(now);
        let ev = self.lockdown.events().last().cloned();
        if let Some(e) = ev {
            let _ = self.audit_event("operator.acknowledge", "lockdown", "ok", &e.detail);
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
