//! Encrypted manifest (`manifest/manifest-<gen>.bin`).
//!
//! File layout (little-endian integers):
//!
//! | off | size | field              |
//! |-----|------|--------------------|
//! |   0 |    8 | magic `"VLTMAN01"` |
//! |   8 |    2 | format_version u16 |
//! |  10 |    2 | crypto_suite u16   |
//! |  12 |   16 | vault_id           |
//! |  28 |    8 | generation u64     |
//! |  36 |    8 | committed_at_ms    |
//! |  44 |   32 | prev_manifest_hash |
//! |  76 |   24 | AEAD nonce         |
//! | 100 |    * | sealed body        |
//!
//! AAD = bytes `[0 .. 76)` — magic, versions, vault id, generation, commit
//! time and the hash of the previous manifest file are all authenticated.
//!
//! The sealed body holds **all** user-visible metadata (names, folders, tags,
//! categories, timestamps of items). Nothing in the body is readable at rest.
//!
//! The manifest is a full snapshot per generation. `prev_manifest_hash` is
//! SHA-256 of the previous manifest *file bytes*, forming a hash chain that
//! makes splicing an older manifest detectable whenever a newer authenticated
//! generation is known (see docs/rollback.md).

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use vault_crypto::aead::{NONCE_LEN, TAG_LEN};
use vault_crypto::{open, seal, Key32, Sha256Writer};

use crate::error::ContainerError;
use crate::ids::{id_hex, Id};

pub const MANIFEST_MAGIC: &[u8; 8] = b"VLTMAN01";
pub const MANIFEST_FORMAT_VERSION: u16 = 1;
pub const MANIFEST_CRYPTO_SUITE: u16 = 1;
const PREFIX_LEN: usize = 76;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectType {
    File = 0,
    Note = 1,
    Password = 2,
}

impl ObjectType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::File),
            1 => Some(Self::Note),
            2 => Some(Self::Password),
            _ => None,
        }
    }
}

pub mod object_flags {
    pub const FAVORITE: u8 = 1 << 0;
}

/// Type-specific metadata stored inside the encrypted manifest body.
/// All fields here are confidential at rest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectMeta {
    /// User-visible display name (filename, note title, entry name).
    #[serde(default)]
    pub name: String,
    /// MIME type (files only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Password entry category (files/notes unused).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Password entry username (searchable field; secret stays in the blob).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Password entry URL (searchable field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Short preview for list rendering (note first chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ObjectEntry {
    pub id: Id,
    pub object_type: ObjectType,
    pub version: u32,
    pub size: u64,
    pub chunk_count: u64,
    pub content_hash: [u8; 32],
    pub folder: Option<Id>,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub flags: u8,
    pub meta: ObjectMeta,
}

#[derive(Debug, Clone)]
pub struct FolderEntry {
    pub id: Id,
    pub parent: Option<Id>,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub generation: u64,
    pub committed_at_ms: u64,
    pub prev_manifest_hash: [u8; 32],
    pub folders: Vec<FolderEntry>,
    pub objects: Vec<ObjectEntry>,
}

impl Manifest {
    pub fn new_initial(committed_at_ms: u64) -> Self {
        Self {
            generation: 1,
            committed_at_ms,
            prev_manifest_hash: [0u8; 32],
            folders: Vec::new(),
            objects: Vec::new(),
        }
    }

    pub fn find_object(&self, id: &Id) -> Option<&ObjectEntry> {
        self.objects.iter().find(|o| &o.id == id)
    }

    pub fn find_folder(&self, id: &Id) -> Option<&FolderEntry> {
        self.folders.iter().find(|f| &f.id == id)
    }

    fn encode_body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.folders.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.objects.len() as u32).to_le_bytes());
        for f in &self.folders {
            out.extend_from_slice(&f.id);
            out.extend_from_slice(&f.parent.unwrap_or([0u8; 16]));
            out.extend_from_slice(&f.created_ms.to_le_bytes());
            out.extend_from_slice(&f.updated_ms.to_le_bytes());
            let name = f.name.as_bytes();
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(name);
        }
        for o in &self.objects {
            out.extend_from_slice(&o.id);
            out.push(o.object_type as u8);
            out.extend_from_slice(&o.version.to_le_bytes());
            out.extend_from_slice(&o.size.to_le_bytes());
            out.extend_from_slice(&o.chunk_count.to_le_bytes());
            out.extend_from_slice(&o.content_hash);
            out.extend_from_slice(&o.folder.unwrap_or([0u8; 16]));
            out.extend_from_slice(&o.created_ms.to_le_bytes());
            out.extend_from_slice(&o.updated_ms.to_le_bytes());
            out.push(o.flags);
            let meta = serde_json::to_vec(&o.meta)
                .expect("ObjectMeta serializes to JSON");
            out.extend_from_slice(&(meta.len() as u32).to_le_bytes());
            out.extend_from_slice(&meta);
        }
        out
    }

    fn decode_body(body: &[u8]) -> Result<Self, ContainerError> {
        let mut r = Reader::new(body);
        let folder_count = r.u32()? as usize;
        let object_count = r.u32()? as usize;
        // Hostile input: refuse absurd counts that would exhaust memory.
        const MAX_ENTRIES: usize = 5_000_000;
        if folder_count > MAX_ENTRIES || object_count > MAX_ENTRIES {
            return Err(ContainerError::Malformed("entry count out of bounds"));
        }
        let mut folders = Vec::with_capacity(folder_count.min(1024));
        for _ in 0..folder_count {
            let id = r.bytes(16)?.try_into().unwrap();
            let parent_raw: [u8; 16] = r.bytes(16)?.try_into().unwrap();
            let parent = if parent_raw == [0u8; 16] { None } else { Some(parent_raw) };
            let created_ms = r.u64()?;
            let updated_ms = r.u64()?;
            let name_len = r.u16()? as usize;
            let name = String::from_utf8(r.bytes(name_len)?.to_vec())
                .map_err(|_| ContainerError::Malformed("folder name is not utf-8"))?;
            folders.push(FolderEntry { id, parent, created_ms, updated_ms, name });
        }
        let mut objects = Vec::with_capacity(object_count.min(1024));
        for _ in 0..object_count {
            let id = r.bytes(16)?.try_into().unwrap();
            let object_type = ObjectType::from_u8(r.u8()?)
                .ok_or(ContainerError::Malformed("unknown object type"))?;
            let version = r.u32()?;
            let size = r.u64()?;
            let chunk_count = r.u64()?;
            let content_hash: [u8; 32] = r.bytes(32)?.try_into().unwrap();
            let folder_raw: [u8; 16] = r.bytes(16)?.try_into().unwrap();
            let folder = if folder_raw == [0u8; 16] { None } else { Some(folder_raw) };
            let created_ms = r.u64()?;
            let updated_ms = r.u64()?;
            let flags = r.u8()?;
            let meta_len = r.u32()? as usize;
            if meta_len > 16 * 1024 * 1024 {
                return Err(ContainerError::Malformed("metadata length out of bounds"));
            }
            let meta: ObjectMeta = serde_json::from_slice(r.bytes(meta_len)?)
                .map_err(|_| ContainerError::Malformed("metadata is not valid JSON"))?;
            objects.push(ObjectEntry {
                id, object_type, version, size, chunk_count, content_hash,
                folder, created_ms, updated_ms, flags, meta,
            });
        }
        if r.remaining() != 0 {
            return Err(ContainerError::Malformed("trailing bytes in manifest body"));
        }
        Ok(Self {
            generation: 0,
            committed_at_ms: 0,
            prev_manifest_hash: [0u8; 32],
            folders,
            objects,
        })
    }

    /// Serialize + encrypt the manifest into final file bytes.
    pub fn seal(&self, meta_key: &Key32, vault_id: &[u8; 16]) -> Result<Vec<u8>, ContainerError> {
        let mut prefix = [0u8; PREFIX_LEN];
        prefix[0..8].copy_from_slice(MANIFEST_MAGIC);
        prefix[8..10].copy_from_slice(&MANIFEST_FORMAT_VERSION.to_le_bytes());
        prefix[10..12].copy_from_slice(&MANIFEST_CRYPTO_SUITE.to_le_bytes());
        prefix[12..28].copy_from_slice(vault_id);
        prefix[28..36].copy_from_slice(&self.generation.to_le_bytes());
        prefix[36..44].copy_from_slice(&self.committed_at_ms.to_le_bytes());
        prefix[44..76].copy_from_slice(&self.prev_manifest_hash);

        let body = self.encode_body();
        let sealed = seal(meta_key, &prefix, &body);
        let mut out = Vec::with_capacity(PREFIX_LEN + sealed.len());
        out.extend_from_slice(&prefix);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Decrypt + strictly validate manifest file bytes.
    pub fn open(meta_key: &Key32, file_bytes: &[u8]) -> Result<Manifest, ContainerError> {
        if file_bytes.len() < PREFIX_LEN + NONCE_LEN + TAG_LEN {
            return Err(ContainerError::Malformed("manifest too short"));
        }
        if &file_bytes[0..8] != MANIFEST_MAGIC {
            return Err(ContainerError::BadMagic("manifest"));
        }
        let fmt = u16::from_le_bytes(file_bytes[8..10].try_into().unwrap());
        if fmt != MANIFEST_FORMAT_VERSION {
            return Err(ContainerError::UnsupportedVersion { found: fmt, expected: MANIFEST_FORMAT_VERSION });
        }
        let suite = u16::from_le_bytes(file_bytes[10..12].try_into().unwrap());
        if suite != MANIFEST_CRYPTO_SUITE {
            return Err(ContainerError::UnsupportedSuite { found: suite, expected: MANIFEST_CRYPTO_SUITE });
        }
        let mut vault_id = [0u8; 16];
        vault_id.copy_from_slice(&file_bytes[12..28]);
        let generation = u64::from_le_bytes(file_bytes[28..36].try_into().unwrap());
        let committed_at_ms = u64::from_le_bytes(file_bytes[36..44].try_into().unwrap());
        let mut prev_manifest_hash = [0u8; 32];
        prev_manifest_hash.copy_from_slice(&file_bytes[44..76]);

        let prefix = &file_bytes[..PREFIX_LEN];
        let body = open(meta_key, prefix, &file_bytes[PREFIX_LEN..])?;
        let mut manifest = Manifest::decode_body(&body)?;
        manifest.generation = generation;
        manifest.committed_at_ms = committed_at_ms;
        manifest.prev_manifest_hash = prev_manifest_hash;
        Ok(manifest)
    }

    /// Extract the vault id from manifest bytes without decryption
    /// (used for substitution detection before unlock).
    pub fn peek_vault_id(file_bytes: &[u8]) -> Result<[u8; 16], ContainerError> {
        if file_bytes.len() < 28 || &file_bytes[0..8] != MANIFEST_MAGIC {
            return Err(ContainerError::BadMagic("manifest"));
        }
        Ok(file_bytes[12..28].try_into().unwrap())
    }

    pub fn peek_generation(file_bytes: &[u8]) -> Result<u64, ContainerError> {
        if file_bytes.len() < 36 || &file_bytes[0..8] != MANIFEST_MAGIC {
            return Err(ContainerError::BadMagic("manifest"));
        }
        Ok(u64::from_le_bytes(file_bytes[28..36].try_into().unwrap()))
    }

    /// The previous-manifest hash lives in the plaintext prefix
    /// (`bytes[44..76]`), so the hash chain can be verified without keys —
    /// required before deciding which root key opens the sealed body.
    pub fn peek_prev_manifest_hash(file_bytes: &[u8]) -> Result<[u8; 32], ContainerError> {
        if file_bytes.len() < 76 || &file_bytes[0..8] != MANIFEST_MAGIC {
            return Err(ContainerError::BadMagic("manifest"));
        }
        Ok(file_bytes[44..76].try_into().unwrap())
    }

    /// Best-effort zeroization of the decrypted metadata held in memory.
    ///
    /// Called when the engine locks (or drops the session) so plaintext
    /// names, tags, previews and folder names do not linger on the heap.
    /// String buffers are zeroized before being released.
    pub fn wipe(&mut self) {
        for f in &mut self.folders {
            f.name.zeroize();
        }
        for o in &mut self.objects {
            o.meta.name.zeroize();
            if let Some(v) = o.meta.mime.as_mut() {
                v.zeroize();
            }
            for t in &mut o.meta.tags {
                t.zeroize();
            }
            if let Some(v) = o.meta.category.as_mut() {
                v.zeroize();
            }
            if let Some(v) = o.meta.username.as_mut() {
                v.zeroize();
            }
            if let Some(v) = o.meta.url.as_mut() {
                v.zeroize();
            }
            if let Some(v) = o.meta.preview.as_mut() {
                v.zeroize();
            }
        }
        self.folders.clear();
        self.objects.clear();
    }
}

/// SHA-256 over the full manifest file bytes (chain element).
pub fn manifest_hash(file_bytes: &[u8]) -> [u8; 32] {
    let mut w = Sha256Writer::new();
    w.update(file_bytes);
    w.finalize()
}

/// `CURRENT` pointer file: plaintext marker binding generation to manifest hash.
///
/// Layout: magic `"VLTNOW01"` (8) || generation u64 || manifest_hash (32) = 48 bytes.
/// Its contents are verified against the manifest it points to; it grants no
/// authority by itself.
pub const CURRENT_MAGIC: &[u8; 8] = b"VLTNOW01";
pub const CURRENT_SIZE: usize = 48;

pub fn encode_current(generation: u64, hash: &[u8; 32]) -> [u8; CURRENT_SIZE] {
    let mut out = [0u8; CURRENT_SIZE];
    out[0..8].copy_from_slice(CURRENT_MAGIC);
    out[8..16].copy_from_slice(&generation.to_le_bytes());
    out[16..48].copy_from_slice(hash);
    out
}

pub fn decode_current(bytes: &[u8]) -> Result<(u64, [u8; 32]), ContainerError> {
    if bytes.len() != CURRENT_SIZE {
        return Err(ContainerError::Malformed("CURRENT file must be 48 bytes"));
    }
    if &bytes[0..8] != CURRENT_MAGIC {
        return Err(ContainerError::BadMagic("CURRENT"));
    }
    let generation = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let hash: [u8; 32] = bytes[16..48].try_into().unwrap();
    Ok((generation, hash))
}

/// Strict bounded reader over a byte slice. Any out-of-range access is an
/// error — malformed input never panics.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], ContainerError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ContainerError::Malformed("length overflow"))?;
        if end > self.buf.len() {
            return Err(ContainerError::Malformed("unexpected end of manifest body"));
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, ContainerError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ContainerError> {
        Ok(u16::from_le_bytes(self.bytes(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, ContainerError> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, ContainerError> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

pub fn folder_display(id: &Id) -> String {
    id_hex(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key32 {
        Key32::random()
    }

    fn sample_manifest() -> Manifest {
        let mut m = Manifest::new_initial(1_700_000_000_000);
        m.folders.push(FolderEntry {
            id: [1u8; 16],
            parent: None,
            created_ms: 1,
            updated_ms: 2,
            name: "Documents".into(),
        });
        m.objects.push(ObjectEntry {
            id: [2u8; 16],
            object_type: ObjectType::Note,
            version: 1,
            size: 42,
            chunk_count: 1,
            content_hash: [3u8; 32],
            folder: Some([1u8; 16]),
            created_ms: 10,
            updated_ms: 20,
            flags: object_flags::FAVORITE,
            meta: ObjectMeta {
                name: "My note".into(),
                mime: Some("text/plain".into()),
                tags: vec!["work".into(), "secret".into()],
                category: Some("email".into()),
                username: Some("user@example.com".into()),
                url: Some("https://example.com".into()),
                preview: Some("hello".into()),
            },
        });
        m
    }

    #[test]
    fn seal_open_roundtrip() {
        let k = key();
        let vid = [9u8; 16];
        let m = sample_manifest();
        let bytes = m.seal(&k, &vid).unwrap();
        let opened = Manifest::open(&k, &bytes).unwrap();
        assert_eq!(opened.generation, 1);
        assert_eq!(opened.committed_at_ms, 1_700_000_000_000);
        assert_eq!(opened.folders.len(), 1);
        assert_eq!(opened.folders[0].name, "Documents");
        assert_eq!(opened.objects.len(), 1);
        let o = &opened.objects[0];
        assert_eq!(o.meta.name, "My note");
        assert_eq!(o.meta.tags, vec!["work".to_string(), "secret".to_string()]);
        assert_eq!(o.meta.username.as_deref(), Some("user@example.com"));
        assert_eq!(o.flags, object_flags::FAVORITE);
        assert_eq!(o.folder, Some([1u8; 16]));
    }

    #[test]
    fn wrong_key_fails() {
        let k = key();
        let bytes = sample_manifest().seal(&k, &[9u8; 16]).unwrap();
        assert!(Manifest::open(&key(), &bytes).is_err());
    }

    #[test]
    fn tampered_prefix_fails() {
        let k = key();
        let mut bytes = sample_manifest().seal(&k, &[9u8; 16]).unwrap();
        bytes[28] ^= 1; // generation inside AAD
        assert!(Manifest::open(&k, &bytes).is_err());
    }

    #[test]
    fn tampered_body_fails() {
        let k = key();
        let mut bytes = sample_manifest().seal(&k, &[9u8; 16]).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(Manifest::open(&k, &bytes).is_err());
    }

    #[test]
    fn truncated_manifest_fails() {
        let k = key();
        let bytes = sample_manifest().seal(&k, &[9u8; 16]).unwrap();
        assert!(Manifest::open(&k, &bytes[..50]).is_err());
        assert!(Manifest::open(&k, &bytes[..bytes.len() - 5]).is_err());
    }

    #[test]
    fn vault_id_binding() {
        let k = key();
        let bytes = sample_manifest().seal(&k, &[1u8; 16]).unwrap();
        assert_eq!(Manifest::peek_vault_id(&bytes).unwrap(), [1u8; 16]);
        // Cross-vault manifest (same key, different vault id) must fail.
        assert!(Manifest::open(&k, &bytes).is_ok());
        let mut tampered = bytes.clone();
        tampered[12] ^= 1;
        assert!(Manifest::open(&k, &tampered).is_err());
    }

    #[test]
    fn current_pointer_roundtrip() {
        let h = [7u8; 32];
        let enc = encode_current(42, &h);
        let (gen, hash) = decode_current(&enc).unwrap();
        assert_eq!(gen, 42);
        assert_eq!(hash, h);
        assert!(decode_current(&enc[..40]).is_err());
        let mut bad = enc;
        bad[0] = b'X';
        assert!(decode_current(&bad).is_err());
    }

    #[test]
    fn decode_rejects_trailing_garbage() {
        let k = key();
        let mut bytes = sample_manifest().seal(&k, &[9u8; 16]).unwrap();
        // Corrupting the last ciphertext byte must fail auth (already covered),
        // but a structurally oversized body count must fail decode instead of panic.
        bytes.truncate(bytes.len());
        assert!(Manifest::open(&k, &bytes).is_ok());
        // Feed a body with a huge declared object count directly.
        let mut evil = Vec::new();
        evil.extend_from_slice(&0u32.to_le_bytes()); // folders
        evil.extend_from_slice(&u32::MAX.to_le_bytes()); // objects
        assert!(matches!(
            Manifest::decode_body(&evil),
            Err(ContainerError::Malformed(_))
        ));
    }
}
