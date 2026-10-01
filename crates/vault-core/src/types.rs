//! Public data types exposed to front-ends (CLI / native UI).

use serde::{Deserialize, Serialize};

use vault_container::{Id, ObjectMeta, ObjectType};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemKind {
    File,
    Note,
    Password,
}

impl ItemKind {
    pub fn from_object_type(t: ObjectType) -> Self {
        match t {
            ObjectType::File => Self::File,
            ObjectType::Note => Self::Note,
            ObjectType::Password => Self::Password,
        }
    }
}

/// List-row metadata (already decrypted — only available while unlocked).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemSummary {
    pub id: Id,
    pub kind: ItemKind,
    pub name: String,
    pub folder: Option<Id>,
    pub size: u64,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub favorite: bool,
    pub mime: Option<String>,
    pub tags: Vec<String>,
    pub category: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub preview: Option<String>,
}

impl ItemSummary {
    pub fn from_entry(
        id: Id,
        object_type: ObjectType,
        size: u64,
        folder: Option<Id>,
        created_ms: u64,
        updated_ms: u64,
        flags: u8,
        meta: &ObjectMeta,
    ) -> Self {
        Self {
            id,
            kind: ItemKind::from_object_type(object_type),
            name: meta.name.clone(),
            folder,
            size,
            created_ms,
            updated_ms,
            favorite: flags & vault_container::manifest::object_flags::FAVORITE != 0,
            mime: meta.mime.clone(),
            tags: meta.tags.clone(),
            category: meta.category.clone(),
            username: meta.username.clone(),
            url: meta.url.clone(),
            preview: meta.preview.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    pub id: Id,
    pub title: String,
    pub content: String,
    pub folder: Option<Id>,
    pub tags: Vec<String>,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub favorite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordRecord {
    pub id: Id,
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub category: String,
    pub favorite: bool,
    pub created_ms: u64,
    pub updated_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderSummary {
    pub id: Id,
    pub parent: Option<Id>,
    pub name: String,
    pub created_ms: u64,
    pub item_count: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    pub files: u64,
    pub notes: u64,
    pub passwords: u64,
    pub folders: u64,
    pub total_bytes: u64,
    pub favorites: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatus {
    pub initialized: bool,
    pub unlocked: bool,
    pub vault_id: String,
    pub format_version: u16,
    pub app_version: u64,
    pub created_ms: u64,
    pub generation: u64,
    pub has_recovery: bool,
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub lockdown_state: String,
    pub failed_attempts: u32,
    pub lockout_until_ms: u64,
    pub platform_capability: String,
    pub binary_hash: String,
    pub binary_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub lockdown_state: String,
    pub platform_capability: String,
    pub binary_verified: bool,
    pub generation: u64,
    pub witnessed_generation: u64,
    pub has_recovery: bool,
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub recent_events: Vec<crate::audit::AuditEvent>,
    pub object_count: u64,
    pub integrity_ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub ok: bool,
    pub checked_objects: u64,
    pub failed: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EraseScope {
    /// Drop session keys (equivalent to locking).
    Session,
    /// Destroy a single object (its DEK dies with the blob).
    Object,
    /// Destroy the recovery envelope.
    Recovery,
    /// Rotate the root key: all previous domain keys become unrecoverable,
    /// every object DEK and the manifest/audit are re-wrapped. Implemented
    /// as a two-phase header transition (arm → migrate → finalize) that is
    /// resumed automatically on the next password unlock after a crash.
    /// Irreversibly destroys the recovery envelope (it wraps the previous
    /// root key); requires the master password.
    Domain,
    /// Destroy the root envelope: the entire vault becomes unrecoverable.
    Vault,
}

impl EraseScope {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "session" => Some(Self::Session),
            "object" => Some(Self::Object),
            "recovery" => Some(Self::Recovery),
            "domain" => Some(Self::Domain),
            "vault" => Some(Self::Vault),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    Manual,
    AutoTimeout,
    Tamper,
    Shutdown,
}

impl LockReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::AutoTimeout => "auto-timeout",
            Self::Tamper => "tamper",
            Self::Shutdown => "shutdown",
        }
    }
}
