//! Plaintext vault header (`VAULTHDR`, fixed 4096 bytes).
//!
//! Byte layout (little-endian integers):
//!
//! | off | size | field              | notes                              |
//! |-----|------|--------------------|------------------------------------|
//! |   0 |    8 | magic              | `"VLTCONT1"`                       |
//! |   8 |    2 | format_version     | u16, current = 1                   |
//! |  10 |    2 | crypto_suite       | u16, current = 1                   |
//! |  12 |   16 | vault_id           | random, binds every container part |
//! |  28 |    2 | kdf_id             | u16, 1 = Argon2id                  |
//! |  30 |    4 | argon2 memory_kib  | u32                                |
//! |  34 |    4 | argon2 iterations  | u32                                |
//! |  38 |    4 | argon2 parallelism | u32                                |
//! |  42 |   32 | kdf_salt           | CSPRNG                             |
//! |  74 |    2 | reserved0          | MUST be zero                       |
//! |  76 |    2 | flags              | bit0 = recovery envelope present   |
//! |  78 |   24 | root_nonce         | AEAD nonce for root envelope       |
//! | 102 |   48 | root_envelope      | ciphertext(root key) under KEK     |
//! | 150 |   32 | recovery_salt      | CSPRNG, recovery KEK derivation    |
//! | 182 |    8 | created_at_ms      | u64 unix ms (plaintext metadata)   |
//! | 190 |    8 | app_version        | u64 (major<<32\|minor<<16\|patch)  |
//! | 198 |   24 | recovery_nonce     | AEAD nonce for recovery envelope   |
//! | 222 |   48 | recovery_envelope  | ciphertext(root key) recovery KEK  |
//! | 270 |    1 | rekey_state        | 0 = none, 1 = domain rekey pending |
//! | 271 |   32 | next_kdf_salt      | CSPRNG, next root KEK derivation   |
//! | 303 |   24 | next_root_nonce    | AEAD nonce for next envelope       |
//! | 327 |   48 | next_root_envelope | ciphertext(next root key) under KEK|
//! | 375 | 3721 | reserved           | MUST be all zero                   |
//!
//! Authentication binding:
//! * root envelope AAD     = header bytes `[0 .. 76)`  (identity + KDF params)
//! * recovery envelope AAD = header bytes `[0 .. 28)`  (magic+version+suite+
//!   vault_id; deliberately excludes everything mutable)
//! * next root envelope AAD = header bytes `[0 .. 76)` of the header as it
//!   will read **after** finalization (i.e. with `kdf.salt = next_kdf_salt`),
//!   so the envelope opens only once the transition commits.
//!
//! Notes:
//! * The KDF parameters are also *implicitly* bound to the root envelope:
//!   any tamper with them produces a different KEK, so the envelope fails to
//!   open even before AAD is checked.
//! * `flags` sits **outside** the root AAD so the recovery flag can be set or
//!   cleared without invalidating the root envelope.
//! * Two-phase domain rekey: `arm_rekey` installs `next_*` while the current
//!   envelope keeps working; `finalize_rekey` promotes the next envelope to
//!   current and zeroes the region. An interrupted transition is therefore
//!   always resumable with the password (see `VaultEngine::drive_rekey`).
//! * The reserved region must be zero — a nonzero value is rejected as
//!   malformed (future versions must bump `format_version` instead).

use vault_crypto::{
    aead::{Envelope, NONCE_LEN},
    derive_kek, KdfParams, Key32, SecretBytes,
};

use crate::error::ContainerError;

pub const HEADER_MAGIC: &[u8; 8] = b"VLTCONT1";
pub const HEADER_SIZE: usize = 4096;
pub const FORMAT_VERSION: u16 = 1;
pub const CRYPTO_SUITE: u16 = 1;
pub const KDF_ARGON2ID: u16 = 1;

pub const FLAG_RECOVERY: u16 = 1 << 0;

const OFF_MAGIC: usize = 0;
const OFF_FORMAT_VERSION: usize = 8;
const OFF_SUITE: usize = 10;
const OFF_VAULT_ID: usize = 12;
const OFF_KDF_ID: usize = 28;
const OFF_MEMORY: usize = 30;
const OFF_ITERATIONS: usize = 34;
const OFF_PARALLELISM: usize = 38;
const OFF_KDF_SALT: usize = 42;
const OFF_RESERVED0: usize = 74;
const OFF_FLAGS: usize = 76;
const OFF_ROOT_NONCE: usize = 78;
const OFF_ROOT_ENVELOPE: usize = 102;
const OFF_RECOVERY_SALT: usize = 150;
const OFF_CREATED_AT: usize = 182;
const OFF_APP_VERSION: usize = 190;
const OFF_RECOVERY_NONCE: usize = 198;
const OFF_RECOVERY_ENVELOPE: usize = 222;
const OFF_REKEY_STATE: usize = 270;
const OFF_NEXT_SALT: usize = 271;
const OFF_NEXT_NONCE: usize = 303;
const OFF_NEXT_ENVELOPE: usize = 327;
const OFF_RESERVED: usize = 375;

const ROOT_AAD_LEN: usize = OFF_FLAGS; // 76
const RECOVERY_AAD_LEN: usize = OFF_VAULT_ID + 16; // 28: magic||ver||suite||vault_id
/// Ciphertext length of a wrapped 32-byte key (32 + 16-byte tag).
const ENVELOPE_LEN: usize = 48;
const _ENVELOPE_CHECK: () = assert!(ENVELOPE_LEN == 48);

pub const REKEY_STATE_NONE: u8 = 0;
pub const REKEY_STATE_PENDING: u8 = 1;

#[derive(Debug, Clone)]
pub struct VaultHeader {
    pub format_version: u16,
    pub crypto_suite: u16,
    pub vault_id: [u8; 16],
    pub kdf_id: u16,
    pub flags: u16,
    pub kdf: KdfParams,
    pub root_nonce: [u8; NONCE_LEN],
    pub root_envelope: [u8; ENVELOPE_LEN],
    pub recovery_salt: [u8; 32],
    pub created_at_ms: u64,
    pub app_version: u64,
    pub recovery_nonce: [u8; NONCE_LEN],
    pub recovery_envelope: [u8; ENVELOPE_LEN],
    pub rekey_state: u8,
    pub next_salt: [u8; 32],
    pub next_nonce: [u8; NONCE_LEN],
    pub next_envelope: [u8; ENVELOPE_LEN],
}

impl VaultHeader {
    fn root_aad_prefix(&self) -> Vec<u8> {
        self.to_bytes()[..ROOT_AAD_LEN].to_vec()
    }

    fn recovery_aad_prefix(&self) -> Vec<u8> {
        self.to_bytes()[..RECOVERY_AAD_LEN].to_vec()
    }

    /// HKDF context for the recovery KEK: `vault_id || recovery_salt`.
    /// Both `enable_recovery` and `unwrap_root_with_recovery` must derive
    /// with the same context or the envelope will not open.
    fn recovery_kek_ctx(&self) -> [u8; 48] {
        let mut ctx = [0u8; 48];
        ctx[..16].copy_from_slice(&self.vault_id);
        ctx[16..].copy_from_slice(&self.recovery_salt);
        ctx
    }

    /// Attach a recovery envelope wrapping `root_key`.
    pub fn enable_recovery(&mut self, root_key: &Key32, recovery_key: &Key32) {
        self.recovery_salt = vault_crypto::random_bytes();
        self.flags |= FLAG_RECOVERY;
        // Recovery keys are 256-bit CSPRNG output (not human passwords), so a
        // direct HKDF derivation — not Argon2id — is correct here. The KEK is
        // salted per-vault *and* per issuance (`recovery_salt`), so re-issuing
        // a recovery key derives a different KEK even under the same key.
        let kek = recovery_key.derive_labeled(b"vault:recovery-kek:v1", &self.recovery_kek_ctx());
        let aad = self.recovery_aad_prefix();
        let env = Envelope::wrap(&kek, &aad, root_key);
        self.recovery_nonce.copy_from_slice(&env.bytes[..NONCE_LEN]);
        self.recovery_envelope.copy_from_slice(&env.bytes[NONCE_LEN..]);
    }

    /// Remove recovery capability (crypto-erasure of the recovery path).
    pub fn disable_recovery(&mut self) {
        self.flags &= !FLAG_RECOVERY;
        self.recovery_nonce = [0u8; NONCE_LEN];
        self.recovery_envelope = [0u8; ENVELOPE_LEN];
        self.recovery_salt = [0u8; 32];
    }

    pub fn has_recovery(&self) -> bool {
        self.flags & FLAG_RECOVERY != 0 && !self.recovery_envelope.iter().all(|&b| b == 0)
    }

    pub fn rekey_pending(&self) -> bool {
        self.rekey_state == REKEY_STATE_PENDING
    }

    /// Candidate header bytes as they will read after `finalize_rekey`:
    /// only `kdf.salt` differs from the current header (the next envelope's
    /// AAD must match the finalized layout).
    fn finalized_view(&self, next_kdf: &KdfParams) -> [u8; HEADER_SIZE] {
        let mut view = self.clone();
        view.kdf = next_kdf.clone();
        view.to_bytes()
    }

    /// Phase 1 of the two-phase domain rekey: install a `next` root envelope
    /// wrapping `next_root` under a KEK derived from `next_kdf` (same Argon2
    /// parameters, fresh salt). The current root envelope keeps working, so
    /// a crash here leaves a fully usable vault with a resumable transition.
    pub fn arm_rekey(
        &mut self,
        password: &SecretBytes,
        next_kdf: KdfParams,
        next_root: &Key32,
    ) -> Result<(), ContainerError> {
        next_kdf.validate()?;
        // Only the salt may change: weakening Argon2 cost parameters during a
        // rekey (or arming with different ones than the current header) would
        // silently downgrade the master-password KDF.
        if next_kdf.algorithm != self.kdf.algorithm
            || next_kdf.memory_kib != self.kdf.memory_kib
            || next_kdf.iterations != self.kdf.iterations
            || next_kdf.parallelism != self.kdf.parallelism
        {
            return Err(ContainerError::Malformed(
                "rekey must not change KDF cost parameters",
            ));
        }
        if self.rekey_state != REKEY_STATE_NONE {
            return Err(ContainerError::Malformed("domain rekey already pending"));
        }
        let kek = derive_kek(password, &next_kdf)?;
        let aad = self.finalized_view(&next_kdf)[..ROOT_AAD_LEN].to_vec();
        let env = Envelope::wrap(&kek, &aad, next_root);
        self.next_salt = next_kdf.salt;
        self.next_nonce = [0u8; NONCE_LEN];
        self.next_nonce.copy_from_slice(&env.bytes[..NONCE_LEN]);
        self.next_envelope = [0u8; ENVELOPE_LEN];
        self.next_envelope.copy_from_slice(&env.bytes[NONCE_LEN..]);
        self.rekey_state = REKEY_STATE_PENDING;
        Ok(())
    }

    /// Unwrap the pending `next` root key with the password. Only valid
    /// while a rekey is armed.
    pub fn unwrap_next(&self, password: &SecretBytes) -> Result<Key32, ContainerError> {
        if !self.rekey_pending() {
            return Err(ContainerError::Malformed("no pending domain rekey"));
        }
        let mut next_kdf = self.kdf.clone();
        next_kdf.salt = self.next_salt;
        next_kdf.validate()?;
        let kek = derive_kek(password, &next_kdf)?;
        let mut sealed = [0u8; NONCE_LEN + ENVELOPE_LEN];
        sealed[..NONCE_LEN].copy_from_slice(&self.next_nonce);
        sealed[NONCE_LEN..].copy_from_slice(&self.next_envelope);
        let env = Envelope { bytes: sealed };
        let aad = self.finalized_view(&next_kdf)[..ROOT_AAD_LEN].to_vec();
        env.unwrap(&kek, &aad).map_err(Into::into)
    }

    /// Phase 2 of the domain rekey: promote the `next` envelope to current
    /// and zero the transition region. The caller is responsible for having
    /// migrated all data to the next root key first, and for dropping the
    /// recovery envelope (it still wraps the previous root key).
    pub fn finalize_rekey(&mut self) -> Result<(), ContainerError> {
        if !self.rekey_pending() {
            return Err(ContainerError::Malformed("no pending domain rekey"));
        }
        self.kdf.salt = self.next_salt;
        self.root_nonce = self.next_nonce;
        self.root_envelope = self.next_envelope;
        self.rekey_state = REKEY_STATE_NONE;
        self.next_salt = [0u8; 32];
        self.next_nonce = [0u8; NONCE_LEN];
        self.next_envelope = [0u8; ENVELOPE_LEN];
        Ok(())
    }

    /// Unwrap the root key using the password-derived KEK.
    ///
    /// Failure means either the wrong password or a tampered header — Vault
    /// deliberately reports a single deterministic error for both, so an
    /// attacker cannot distinguish the two cases.
    pub fn unwrap_root(&self, password: &SecretBytes) -> Result<Key32, ContainerError> {
        let kek = derive_kek(password, &self.kdf)?;
        let mut sealed = [0u8; NONCE_LEN + ENVELOPE_LEN];
        sealed[..NONCE_LEN].copy_from_slice(&self.root_nonce);
        sealed[NONCE_LEN..].copy_from_slice(&self.root_envelope);
        let env = Envelope { bytes: sealed };
        let aad = self.root_aad_prefix();
        env.unwrap(&kek, &aad).map_err(Into::into)
    }

    /// Unwrap the root key using the recovery key.
    pub fn unwrap_root_with_recovery(&self, recovery_key: &Key32) -> Result<Key32, ContainerError> {
        if !self.has_recovery() {
            return Err(ContainerError::Malformed("recovery envelope absent"));
        }
        let kek = recovery_key.derive_labeled(b"vault:recovery-kek:v1", &self.recovery_kek_ctx());
        let mut sealed = [0u8; NONCE_LEN + ENVELOPE_LEN];
        sealed[..NONCE_LEN].copy_from_slice(&self.recovery_nonce);
        sealed[NONCE_LEN..].copy_from_slice(&self.recovery_envelope);
        let env = Envelope { bytes: sealed };
        let aad = self.recovery_aad_prefix();
        env.unwrap(&kek, &aad).map_err(Into::into)
    }

    /// Re-wrap the root key under a new password (password change).
    ///
    /// The root key itself is unchanged, and the recovery envelope's AAD
    /// excludes the KDF/root-envelope region, so recovery material keeps
    /// working across password changes without needing the recovery key here.
    pub fn rewrap_root(
        &mut self,
        new_kdf: KdfParams,
        new_password: &SecretBytes,
        root_key: &Key32,
    ) -> Result<(), ContainerError> {
        new_kdf.validate()?;
        self.kdf = new_kdf;
        let kek = derive_kek(new_password, &self.kdf)?;
        let aad = self.root_aad_prefix();
        let env = Envelope::wrap(&kek, &aad, root_key);
        self.root_nonce.copy_from_slice(&env.bytes[..NONCE_LEN]);
        self.root_envelope.copy_from_slice(&env.bytes[NONCE_LEN..]);
        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[OFF_MAGIC..OFF_MAGIC + 8].copy_from_slice(HEADER_MAGIC);
        out[OFF_FORMAT_VERSION..OFF_FORMAT_VERSION + 2]
            .copy_from_slice(&self.format_version.to_le_bytes());
        out[OFF_SUITE..OFF_SUITE + 2].copy_from_slice(&self.crypto_suite.to_le_bytes());
        out[OFF_VAULT_ID..OFF_VAULT_ID + 16].copy_from_slice(&self.vault_id);
        out[OFF_KDF_ID..OFF_KDF_ID + 2].copy_from_slice(&self.kdf_id.to_le_bytes());
        out[OFF_MEMORY..OFF_MEMORY + 4].copy_from_slice(&self.kdf.memory_kib.to_le_bytes());
        out[OFF_ITERATIONS..OFF_ITERATIONS + 4].copy_from_slice(&self.kdf.iterations.to_le_bytes());
        out[OFF_PARALLELISM..OFF_PARALLELISM + 4].copy_from_slice(&self.kdf.parallelism.to_le_bytes());
        out[OFF_KDF_SALT..OFF_KDF_SALT + 32].copy_from_slice(&self.kdf.salt);
        // OFF_RESERVED0 stays zero.
        out[OFF_FLAGS..OFF_FLAGS + 2].copy_from_slice(&self.flags.to_le_bytes());
        out[OFF_ROOT_NONCE..OFF_ROOT_NONCE + NONCE_LEN].copy_from_slice(&self.root_nonce);
        out[OFF_ROOT_ENVELOPE..OFF_ROOT_ENVELOPE + ENVELOPE_LEN]
            .copy_from_slice(&self.root_envelope);
        out[OFF_RECOVERY_SALT..OFF_RECOVERY_SALT + 32].copy_from_slice(&self.recovery_salt);
        out[OFF_CREATED_AT..OFF_CREATED_AT + 8].copy_from_slice(&self.created_at_ms.to_le_bytes());
        out[OFF_APP_VERSION..OFF_APP_VERSION + 8].copy_from_slice(&self.app_version.to_le_bytes());
        out[OFF_RECOVERY_NONCE..OFF_RECOVERY_NONCE + NONCE_LEN]
            .copy_from_slice(&self.recovery_nonce);
        out[OFF_RECOVERY_ENVELOPE..OFF_RECOVERY_ENVELOPE + ENVELOPE_LEN]
            .copy_from_slice(&self.recovery_envelope);
        out[OFF_REKEY_STATE] = self.rekey_state;
        out[OFF_NEXT_SALT..OFF_NEXT_SALT + 32].copy_from_slice(&self.next_salt);
        out[OFF_NEXT_NONCE..OFF_NEXT_NONCE + NONCE_LEN].copy_from_slice(&self.next_nonce);
        out[OFF_NEXT_ENVELOPE..OFF_NEXT_ENVELOPE + ENVELOPE_LEN]
            .copy_from_slice(&self.next_envelope);
        out
    }

    /// Strict parse. Every structural violation is an error; nothing is
    /// silently defaulted.
    pub fn parse(bytes: &[u8]) -> Result<Self, ContainerError> {
        if bytes.len() != HEADER_SIZE {
            return Err(ContainerError::Malformed("header must be exactly 4096 bytes"));
        }
        if &bytes[OFF_MAGIC..OFF_MAGIC + 8] != HEADER_MAGIC {
            return Err(ContainerError::BadMagic("header"));
        }
        let format_version =
            u16::from_le_bytes(bytes[OFF_FORMAT_VERSION..OFF_FORMAT_VERSION + 2].try_into().unwrap());
        if format_version != FORMAT_VERSION {
            return Err(ContainerError::UnsupportedVersion {
                found: format_version,
                expected: FORMAT_VERSION,
            });
        }
        let crypto_suite = u16::from_le_bytes(bytes[OFF_SUITE..OFF_SUITE + 2].try_into().unwrap());
        if crypto_suite != CRYPTO_SUITE {
            return Err(ContainerError::UnsupportedSuite {
                found: crypto_suite,
                expected: CRYPTO_SUITE,
            });
        }
        let kdf_id = u16::from_le_bytes(bytes[OFF_KDF_ID..OFF_KDF_ID + 2].try_into().unwrap());
        if kdf_id != KDF_ARGON2ID {
            return Err(ContainerError::Malformed("unknown kdf id"));
        }
        if bytes[OFF_RESERVED0..OFF_FLAGS].iter().any(|&b| b != 0) {
            return Err(ContainerError::Malformed("nonzero reserved0"));
        }
        if bytes[OFF_RESERVED..].iter().any(|&b| b != 0) {
            return Err(ContainerError::Malformed("nonzero reserved region"));
        }
        let flags = u16::from_le_bytes(bytes[OFF_FLAGS..OFF_FLAGS + 2].try_into().unwrap());
        if flags & !FLAG_RECOVERY != 0 {
            return Err(ContainerError::Malformed("unknown flag bits set"));
        }
        let rekey_state = bytes[OFF_REKEY_STATE];
        if rekey_state != REKEY_STATE_NONE && rekey_state != REKEY_STATE_PENDING {
            return Err(ContainerError::Malformed("unknown rekey state"));
        }
        let next_region = &bytes[OFF_NEXT_SALT..OFF_RESERVED];
        if rekey_state == REKEY_STATE_NONE {
            if next_region.iter().any(|&b| b != 0) {
                return Err(ContainerError::Malformed("next-envelope region set without pending rekey"));
            }
        } else if bytes[OFF_NEXT_ENVELOPE..OFF_RESERVED]
            .iter()
            .all(|&b| b == 0)
        {
            return Err(ContainerError::Malformed("pending rekey without next envelope"));
        }

        let mut vault_id = [0u8; 16];
        vault_id.copy_from_slice(&bytes[OFF_VAULT_ID..OFF_VAULT_ID + 16]);
        let kdf = KdfParams {
            algorithm: kdf_id,
            memory_kib: u32::from_le_bytes(bytes[OFF_MEMORY..OFF_MEMORY + 4].try_into().unwrap()),
            iterations: u32::from_le_bytes(
                bytes[OFF_ITERATIONS..OFF_ITERATIONS + 4].try_into().unwrap(),
            ),
            parallelism: u32::from_le_bytes(
                bytes[OFF_PARALLELISM..OFF_PARALLELISM + 4].try_into().unwrap(),
            ),
            salt: bytes[OFF_KDF_SALT..OFF_KDF_SALT + 32].try_into().unwrap(),
        };
        kdf.validate()?;

        let mut root_nonce = [0u8; NONCE_LEN];
        root_nonce.copy_from_slice(&bytes[OFF_ROOT_NONCE..OFF_ROOT_NONCE + NONCE_LEN]);
        let mut root_envelope = [0u8; ENVELOPE_LEN];
        root_envelope
            .copy_from_slice(&bytes[OFF_ROOT_ENVELOPE..OFF_ROOT_ENVELOPE + ENVELOPE_LEN]);
        let mut recovery_salt = [0u8; 32];
        recovery_salt.copy_from_slice(&bytes[OFF_RECOVERY_SALT..OFF_RECOVERY_SALT + 32]);
        let mut recovery_nonce = [0u8; NONCE_LEN];
        recovery_nonce.copy_from_slice(&bytes[OFF_RECOVERY_NONCE..OFF_RECOVERY_NONCE + NONCE_LEN]);
        let mut recovery_envelope = [0u8; ENVELOPE_LEN];
        recovery_envelope
            .copy_from_slice(&bytes[OFF_RECOVERY_ENVELOPE..OFF_RECOVERY_ENVELOPE + ENVELOPE_LEN]);

        if root_envelope.iter().all(|&b| b == 0) {
            return Err(ContainerError::Malformed("missing root key envelope"));
        }
        let mut next_salt = [0u8; 32];
        next_salt.copy_from_slice(&bytes[OFF_NEXT_SALT..OFF_NEXT_SALT + 32]);
        let mut next_nonce = [0u8; NONCE_LEN];
        next_nonce.copy_from_slice(&bytes[OFF_NEXT_NONCE..OFF_NEXT_NONCE + NONCE_LEN]);
        let mut next_envelope = [0u8; ENVELOPE_LEN];
        next_envelope.copy_from_slice(&bytes[OFF_NEXT_ENVELOPE..OFF_NEXT_ENVELOPE + ENVELOPE_LEN]);

        Ok(Self {
            format_version,
            crypto_suite,
            vault_id,
            kdf_id,
            flags,
            kdf,
            root_nonce,
            root_envelope,
            recovery_salt,
            created_at_ms: u64::from_le_bytes(
                bytes[OFF_CREATED_AT..OFF_CREATED_AT + 8].try_into().unwrap(),
            ),
            app_version: u64::from_le_bytes(
                bytes[OFF_APP_VERSION..OFF_APP_VERSION + 8].try_into().unwrap(),
            ),
            recovery_nonce,
            recovery_envelope,
            rekey_state,
            next_salt,
            next_nonce,
            next_envelope,
        })
    }
}

/// Build a header using a password to derive the KEK that wraps `root_key`.
pub fn create_header_with_password(
    password: &SecretBytes,
    kdf: KdfParams,
    root_key: &Key32,
    recovery_key: Option<&Key32>,
    created_at_ms: u64,
    app_version: u64,
) -> Result<VaultHeader, ContainerError> {
    kdf.validate()?;
    let vault_id: [u8; 16] = vault_crypto::random_bytes();
    let kek = derive_kek(password, &kdf)?;
    let mut hdr = VaultHeader {
        format_version: FORMAT_VERSION,
        crypto_suite: CRYPTO_SUITE,
        vault_id,
        kdf_id: KDF_ARGON2ID,
        flags: 0,
        kdf,
        root_nonce: [0u8; NONCE_LEN],
        root_envelope: [0u8; ENVELOPE_LEN],
        recovery_salt: [0u8; 32],
        created_at_ms,
        app_version,
        recovery_nonce: [0u8; NONCE_LEN],
        recovery_envelope: [0u8; ENVELOPE_LEN],
        rekey_state: REKEY_STATE_NONE,
        next_salt: [0u8; 32],
        next_nonce: [0u8; NONCE_LEN],
        next_envelope: [0u8; ENVELOPE_LEN],
    };
    let aad = hdr.root_aad_prefix();
    let env = Envelope::wrap(&kek, &aad, root_key);
    hdr.root_nonce.copy_from_slice(&env.bytes[..NONCE_LEN]);
    hdr.root_envelope.copy_from_slice(&env.bytes[NONCE_LEN..]);
    if let Some(rec) = recovery_key {
        hdr.enable_recovery(root_key, rec);
    }
    Ok(hdr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_crypto::KdfParams;

    fn test_kdf() -> KdfParams {
        KdfParams {
            algorithm: 1,
            memory_kib: vault_crypto::kdf::MIN_MEMORY_KIB,
            iterations: vault_crypto::kdf::MIN_ITERATIONS,
            parallelism: 1,
            salt: [7u8; 32],
        }
    }

    fn make_header(pw: &str) -> (VaultHeader, Key32) {
        let root = Key32::random();
        let hdr = create_header_with_password(
            &SecretBytes::from_str(pw),
            test_kdf(),
            &root,
            None,
            1_700_000_000_000,
            0x0001_0000_0000,
        )
        .unwrap();
        (hdr, root)
    }

    #[test]
    fn roundtrip_parse() {
        let (hdr, _) = make_header("pw");
        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);
        let parsed = VaultHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.vault_id, hdr.vault_id);
        assert_eq!(parsed.kdf, hdr.kdf);
        assert_eq!(parsed.created_at_ms, hdr.created_at_ms);
    }

    #[test]
    fn unwrap_root_correct_password() {
        let pw = SecretBytes::from_str("correct password");
        let root = Key32::random();
        let hdr = create_header_with_password(&pw, test_kdf(), &root, None, 0, 1).unwrap();
        let recovered = hdr.unwrap_root(&pw).unwrap();
        assert_eq!(root.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn wrong_password_fails() {
        let (hdr, _) = make_header("right");
        let res = hdr.unwrap_root(&SecretBytes::from_str("wrong"));
        assert!(res.is_err());
    }

    #[test]
    fn tampered_vault_id_fails_root_unwrap() {
        let pw = SecretBytes::from_str("pw");
        let (hdr, _) = make_header("pw");
        let mut bytes = hdr.to_bytes();
        bytes[12] ^= 0x01; // vault_id inside root AAD
        let parsed = VaultHeader::parse(&bytes).unwrap();
        assert!(parsed.unwrap_root(&pw).is_err());
    }

    #[test]
    fn tampered_kdf_params_fail_root_unwrap() {
        let pw = SecretBytes::from_str("pw");
        let (hdr, _) = make_header("pw");
        let mut bytes = hdr.to_bytes();
        bytes[42] ^= 0x01; // kdf salt → different KEK
        let parsed = VaultHeader::parse(&bytes).unwrap();
        assert!(parsed.unwrap_root(&pw).is_err());
    }

    #[test]
    fn tampered_reserved_region_rejected() {
        let (hdr, _) = make_header("pw");
        let mut bytes = hdr.to_bytes();
        bytes[HEADER_SIZE - 1] = 0x41;
        assert!(VaultHeader::parse(&bytes).is_err());
        let mut bytes = hdr.to_bytes();
        bytes[OFF_RESERVED0] = 1;
        assert!(VaultHeader::parse(&bytes).is_err());
    }

    #[test]
    fn truncated_header_rejected() {
        let (hdr, _) = make_header("pw");
        let bytes = hdr.to_bytes();
        assert!(VaultHeader::parse(&bytes[..100]).is_err());
        assert!(VaultHeader::parse(&[]).is_err());
    }

    #[test]
    fn bad_magic_rejected() {
        let (hdr, _) = make_header("pw");
        let mut bytes = hdr.to_bytes();
        bytes[0] = b'X';
        assert!(matches!(VaultHeader::parse(&bytes), Err(ContainerError::BadMagic(_))));
    }

    #[test]
    fn unsupported_version_rejected() {
        let (hdr, _) = make_header("pw");
        let mut bytes = hdr.to_bytes();
        bytes[8] = 99;
        assert!(matches!(
            VaultHeader::parse(&bytes),
            Err(ContainerError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn recovery_roundtrip() {
        let pw = SecretBytes::from_str("pw");
        let root = Key32::random();
        let rec = Key32::random();
        let hdr = create_header_with_password(&pw, test_kdf(), &root, Some(&rec), 0, 1).unwrap();
        assert!(hdr.has_recovery());
        let recovered = hdr.unwrap_root_with_recovery(&rec).unwrap();
        assert_eq!(root.as_bytes(), recovered.as_bytes());
        assert!(hdr.unwrap_root_with_recovery(&Key32::random()).is_err());
        assert!(hdr.unwrap_root(&pw).is_ok());
        // Setting the recovery flag must not invalidate the root envelope.
        let mut hdr2 = create_header_with_password(&pw, test_kdf(), &root, None, 0, 1).unwrap();
        hdr2.enable_recovery(&root, &rec);
        assert!(hdr2.unwrap_root(&pw).is_ok());
        assert!(hdr2.unwrap_root_with_recovery(&rec).is_ok());
        hdr2.disable_recovery();
        assert!(!hdr2.has_recovery());
        assert!(hdr2.unwrap_root(&pw).is_ok());
    }

    #[test]
    fn rewrap_root_changes_password_keeps_data_key() {
        let pw = SecretBytes::from_str("old");
        let root = Key32::random();
        let mut hdr = create_header_with_password(&pw, test_kdf(), &root, None, 0, 1).unwrap();
        let mut new_kdf = test_kdf();
        new_kdf.salt = [9u8; 32];
        hdr.rewrap_root(new_kdf, &SecretBytes::from_str("new"), &root).unwrap();
        assert!(hdr.unwrap_root(&SecretBytes::from_str("old")).is_err());
        let got = hdr.unwrap_root(&SecretBytes::from_str("new")).unwrap();
        assert_eq!(root.as_bytes(), got.as_bytes());
    }

    #[test]
    fn password_change_keeps_recovery_when_key_supplied() {
        let pw = SecretBytes::from_str("old");
        let root = Key32::random();
        let rec = Key32::random();
        let mut hdr = create_header_with_password(&pw, test_kdf(), &root, Some(&rec), 0, 1).unwrap();
        let mut new_kdf = test_kdf();
        new_kdf.salt = [3u8; 32];
        hdr.rewrap_root(new_kdf, &SecretBytes::from_str("new"), &root).unwrap();
        assert!(hdr.unwrap_root(&SecretBytes::from_str("new")).is_ok());
        assert!(hdr.unwrap_root_with_recovery(&rec).is_ok());
    }

    #[test]
    fn domain_rekey_arm_finalize_roundtrip() {
        let pw = SecretBytes::from_str("pw");
        let (mut hdr, old_root) = make_header("pw");
        let mut next_kdf = test_kdf();
        next_kdf.salt = [42u8; 32];
        let new_root = Key32::random();

        hdr.arm_rekey(&pw, next_kdf, &new_root).unwrap();
        assert!(hdr.rekey_pending());
        // Double-arm is refused while pending.
        assert!(hdr.arm_rekey(&pw, test_kdf(), &Key32::random()).is_err());

        // Round-trips through bytes with the pending region intact.
        let parsed = VaultHeader::parse(&hdr.to_bytes()).unwrap();
        assert!(parsed.rekey_pending());
        // Old envelope still opens during the transition.
        let got_old = parsed.unwrap_root(&pw).unwrap();
        assert_eq!(got_old.as_bytes(), old_root.as_bytes());
        // Next envelope opens with the password, rejects a wrong one.
        let got_new = parsed.unwrap_next(&pw).unwrap();
        assert_eq!(got_new.as_bytes(), new_root.as_bytes());
        assert!(parsed.unwrap_next(&SecretBytes::from_str("bad")).is_err());
        // unwrap_next without a pending transition is an error.
        let (fresh, _) = make_header("pw");
        assert!(fresh.unwrap_next(&pw).is_err());

        // Finalize promotes the next envelope to current.
        let mut finalized = parsed;
        finalized.finalize_rekey().unwrap();
        assert!(!finalized.rekey_pending());
        let mut roundtrip = VaultHeader::parse(&finalized.to_bytes()).unwrap();
        assert!(!roundtrip.rekey_pending());
        let got = roundtrip.unwrap_root(&pw).unwrap();
        assert_eq!(got.as_bytes(), new_root.as_bytes());
        // Old root key is gone.
        assert!(roundtrip.unwrap_next(&pw).is_err());
        // Finalize twice is an error.
        assert!(roundtrip.finalize_rekey().is_err());
    }

    #[test]
    fn rekey_region_is_strictly_validated() {
        let (hdr, _) = make_header("pw");
        let bytes = hdr.to_bytes();

        // state=0 but next region nonzero → malformed.
        let mut bad = bytes;
        bad[OFF_NEXT_SALT] = 1;
        assert!(VaultHeader::parse(&bad).is_err());

        // Unknown state byte → malformed.
        let mut bad = bytes;
        bad[OFF_REKEY_STATE] = 2;
        assert!(VaultHeader::parse(&bad).is_err());

        // Pending state without a next envelope → malformed.
        let mut bad = bytes;
        bad[OFF_REKEY_STATE] = REKEY_STATE_PENDING;
        assert!(VaultHeader::parse(&bad).is_err());
    }

    #[test]
    fn second_reserved0_byte_must_be_zero() {
        let (hdr, _) = make_header("pw");
        let mut bytes = hdr.to_bytes();
        bytes[OFF_RESERVED0 + 1] = 1; // byte 75 — half of the 2-byte reserved0
        assert!(VaultHeader::parse(&bytes).is_err());
    }

    #[test]
    fn unknown_flag_bits_rejected() {
        let (hdr, _) = make_header("pw");

        // High byte: flag bit 15.
        let mut bytes = hdr.to_bytes();
        bytes[OFF_FLAGS + 1] |= 0x80;
        assert!(VaultHeader::parse(&bytes).is_err());

        // Low byte: flag bit 7 (only bit 0 = recovery is defined).
        let mut bytes = hdr.to_bytes();
        bytes[OFF_FLAGS] |= 0x02;
        assert!(VaultHeader::parse(&bytes).is_err());
    }

    #[test]
    fn arm_rekey_rejects_kdf_cost_change() {
        let pw = SecretBytes::from_str("pw");
        let (mut hdr, _) = make_header("pw");
        let mut next_kdf = test_kdf();
        next_kdf.iterations += 1; // cost params must not change during rekey
        assert!(hdr.arm_rekey(&pw, next_kdf, &Key32::random()).is_err());
        // Same KDF params (fresh salt) are fine.
        let mut ok_kdf = test_kdf();
        ok_kdf.salt = [77u8; 32];
        assert!(hdr.arm_rekey(&pw, ok_kdf, &Key32::random()).is_ok());
    }
}
