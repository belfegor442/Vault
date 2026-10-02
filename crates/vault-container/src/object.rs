//! Object blob format (`objects/<xx>/<hex_id>`).
//!
//! | off  | size | field          |
//! |------|------|----------------|
//! |    0 |    8 | magic `"VLTLOBJ1"` |
//! |    8 |    2 | format_version u16 |
//! |   10 |    2 | crypto_suite u16   |
//! |   12 |   16 | object_id          |
//! |   28 |    4 | object_version u32 |
//! |   32 |   16 | nonce_prefix       |
//! |   48 |    8 | plaintext_len u64  |
//! |   56 |    8 | chunk_count u64    |
//! |   64 |   72 | wrapped DEK envelope |
//! |  136 |    * | chunk stream (`ct||tag` per chunk) |
//!
//! * Each object has a fresh random 256-bit DEK; the DEK is wrapped under the
//!   **data domain key** with AAD = `vault_id || object_id || version`.
//! * Chunk AAD prefix = `vault_id || object_id || version` — a blob from
//!   another vault, another object, or another version cannot be spliced in.
//! * `nonce_prefix` is fresh for every write; chunk nonces are
//!   `nonce_prefix || chunk_index`, so nonces never repeat under one key.
//! * `plaintext_len` / `chunk_count` are authenticated indirectly: they are
//!   patched into the file after sealing and are re-checked against the
//!   decrypted stream (see `open_object`); any mismatch is a hard error.

use std::io::{Read, Seek, SeekFrom, Write};

use vault_crypto::aead::{Envelope, NONCE_LEN, TAG_LEN};
use vault_crypto::stream::{open_stream, seal_stream, StreamStats, NONCE_PREFIX_LEN};
use vault_crypto::{Key32, Sha256Writer};

use crate::error::ContainerError;
use crate::ids::Id;

pub const OBJECT_MAGIC: &[u8; 8] = b"VLTLOBJ1";
pub const OBJECT_FORMAT_VERSION: u16 = 1;
pub const OBJECT_CRYPTO_SUITE: u16 = 1;
pub const OBJECT_HEADER_SIZE: usize = 136;
const ENVELOPE_LEN: usize = NONCE_LEN + 32 + TAG_LEN; // 72

#[derive(Debug, Clone)]
pub struct ObjectHeader {
    pub object_id: Id,
    pub version: u32,
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
    pub plaintext_len: u64,
    pub chunk_count: u64,
    pub wrapped_dek: [u8; ENVELOPE_LEN],
}

fn dek_aad(vault_id: &[u8; 16], object_id: &Id, version: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 16 + 4);
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(object_id);
    aad.extend_from_slice(&version.to_le_bytes());
    aad
}

impl ObjectHeader {
    pub fn to_bytes(&self) -> [u8; OBJECT_HEADER_SIZE] {
        let mut out = [0u8; OBJECT_HEADER_SIZE];
        out[0..8].copy_from_slice(OBJECT_MAGIC);
        out[8..10].copy_from_slice(&OBJECT_FORMAT_VERSION.to_le_bytes());
        out[10..12].copy_from_slice(&OBJECT_CRYPTO_SUITE.to_le_bytes());
        out[12..28].copy_from_slice(&self.object_id);
        out[28..32].copy_from_slice(&self.version.to_le_bytes());
        out[32..48].copy_from_slice(&self.nonce_prefix);
        out[48..56].copy_from_slice(&self.plaintext_len.to_le_bytes());
        out[56..64].copy_from_slice(&self.chunk_count.to_le_bytes());
        out[64..136].copy_from_slice(&self.wrapped_dek);
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, ContainerError> {
        if bytes.len() < OBJECT_HEADER_SIZE {
            return Err(ContainerError::Malformed("object header truncated"));
        }
        if &bytes[0..8] != OBJECT_MAGIC {
            return Err(ContainerError::BadMagic("object"));
        }
        let fmt = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
        if fmt != OBJECT_FORMAT_VERSION {
            return Err(ContainerError::UnsupportedVersion { found: fmt, expected: OBJECT_FORMAT_VERSION });
        }
        let suite = u16::from_le_bytes(bytes[10..12].try_into().unwrap());
        if suite != OBJECT_CRYPTO_SUITE {
            return Err(ContainerError::UnsupportedSuite { found: suite, expected: OBJECT_CRYPTO_SUITE });
        }
        let mut object_id = [0u8; 16];
        object_id.copy_from_slice(&bytes[12..28]);
        let version = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
        if version == 0 {
            return Err(ContainerError::Malformed("object version must be >= 1"));
        }
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        nonce_prefix.copy_from_slice(&bytes[32..48]);
        let plaintext_len = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
        let chunk_count = u64::from_le_bytes(bytes[56..64].try_into().unwrap());
        if chunk_count == 0 {
            return Err(ContainerError::Malformed("object must declare >= 1 chunk"));
        }
        let mut wrapped_dek = [0u8; ENVELOPE_LEN];
        wrapped_dek.copy_from_slice(&bytes[64..136]);
        if wrapped_dek.iter().all(|&b| b == 0) {
            return Err(ContainerError::Malformed("missing wrapped DEK"));
        }
        Ok(Self { object_id, version, nonce_prefix, plaintext_len, chunk_count, wrapped_dek })
    }

    fn unwrap_dek(
        &self,
        data_key: &Key32,
        vault_id: &[u8; 16],
    ) -> Result<Key32, ContainerError> {
        let env = Envelope { bytes: self.wrapped_dek };
        let aad = dek_aad(vault_id, &self.object_id, self.version);
        env.unwrap(data_key, &aad).map_err(Into::into)
    }

    /// Re-wrap the DEK under a new data key (domain rekey).
    ///
    /// Returns `true` when the header was rewritten (`old_key` opened it)
    /// and `false` when it was already wrapped under `new_key` — making the
    /// operation idempotent for crash recovery. Errs when the DEK opens
    /// under neither key.
    pub fn rewrap_dek(
        &mut self,
        old_key: &Key32,
        new_key: &Key32,
        vault_id: &[u8; 16],
    ) -> Result<bool, ContainerError> {
        match self.unwrap_dek(old_key, vault_id) {
            Ok(dek) => {
                let aad = dek_aad(vault_id, &self.object_id, self.version);
                let env = Envelope::wrap(new_key, &aad, &dek);
                self.wrapped_dek = env.bytes;
                Ok(true)
            }
            Err(_) => {
                // Idempotency: already migrated?
                self.unwrap_dek(new_key, vault_id)?;
                Ok(false)
            }
        }
    }
}

/// Encrypt `reader` into `writer`.
///
/// `writer` must be seekable: the 136-byte header is written first with
/// placeholder statistics, then patched after the stream is sealed.
/// An interrupted write leaves an incomplete blob that is never referenced by
/// the (later, atomically committed) manifest — it is garbage-collected as an
/// orphan.
pub fn write_object<W: Write + Seek>(
    writer: &mut W,
    data_key: &Key32,
    vault_id: &[u8; 16],
    object_id: &Id,
    version: u32,
    reader: &mut impl Read,
) -> Result<ObjectHeader, ContainerError> {
    let dek = Key32::random();
    let nonce_prefix: [u8; NONCE_PREFIX_LEN] = vault_crypto::random_bytes();
    let aad = dek_aad(vault_id, object_id, version);
    let env = Envelope::wrap(data_key, &aad, &dek);

    let header = ObjectHeader {
        object_id: *object_id,
        version,
        nonce_prefix,
        plaintext_len: 0,
        chunk_count: 0,
        wrapped_dek: env.bytes,
    };
    writer.write_all(&header.to_bytes())?;

    let chunk_aad_prefix = dek_aad(vault_id, object_id, version);
    let stats = seal_stream(&dek, &nonce_prefix, &chunk_aad_prefix, reader, writer)?;

    // Patch statistics into the header.
    let mut final_header = header.clone();
    final_header.plaintext_len = stats.plaintext_len;
    final_header.chunk_count = stats.chunk_count;
    writer.seek(SeekFrom::Start(0))?;
    writer.write_all(&final_header.to_bytes())?;
    writer.seek(SeekFrom::End(0))?;
    Ok(final_header)
}

/// Decrypt an object stream into `writer`, verifying the header statistics.
///
/// `reader` must be positioned immediately after the 136-byte header and
/// must yield exactly the chunk stream (no trailing bytes allowed — the
/// caller passes a reader bounded to the blob length).
pub fn open_object(
    reader: &mut impl Read,
    header: &ObjectHeader,
    data_key: &Key32,
    vault_id: &[u8; 16],
    writer: &mut impl Write,
) -> Result<StreamStats, ContainerError> {
    let dek = header.unwrap_dek(data_key, vault_id)?;
    let chunk_aad_prefix = dek_aad(vault_id, &header.object_id, header.version);
    let stats = open_stream(
        &dek,
        &header.nonce_prefix,
        &chunk_aad_prefix,
        reader,
        writer,
        header.chunk_count,
        header.plaintext_len,
    )?;
    Ok(stats)
}

/// Stream-encrypt while computing SHA-256 of the plaintext.
///
/// Used by import so the manifest can store a content hash without a second
/// pass over the data.
pub struct HashingReader<'a, R: Read> {
    inner: &'a mut R,
    hasher: Sha256Writer,
}

impl<'a, R: Read> HashingReader<'a, R> {
    pub fn new(inner: &'a mut R) -> Self {
        Self { inner, hasher: Sha256Writer::new() }
    }

    pub fn finish(self) -> [u8; 32] {
        self.hasher.finalize()
    }
}

impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn seal_blob(
        data_key: &Key32,
        vault_id: &[u8; 16],
        object_id: &Id,
        version: u32,
        data: &[u8],
    ) -> Vec<u8> {
        let mut cur = Cursor::new(Vec::new());
        write_object(&mut cur, data_key, vault_id, object_id, version, &mut &data[..]).unwrap();
        cur.into_inner()
    }

    fn write_then_read(data: &[u8]) -> (Vec<u8>, ObjectHeader, Vec<u8>) {
        let vault_id = [5u8; 16];
        let object_id = [6u8; 16];
        let data_key = Key32::random();
        let blob = seal_blob(&data_key, &vault_id, &object_id, 1, data);

        let parsed = ObjectHeader::parse(&blob[..OBJECT_HEADER_SIZE]).unwrap();
        let mut out = Vec::new();
        open_object(
            &mut &blob[OBJECT_HEADER_SIZE..],
            &parsed,
            &data_key,
            &vault_id,
            &mut out,
        )
        .unwrap();
        assert_eq!(out, data);
        (blob, parsed, out)
    }

    #[test]
    fn roundtrip_various_sizes() {
        for size in [0usize, 1, 1000, 3 * 1024 * 1024 + 7] {
            let data: Vec<u8> = (0..size).map(|i| (i % 249) as u8).collect();
            let (_, header, out) = write_then_read(&data);
            assert_eq!(out.len(), size);
            assert_eq!(header.plaintext_len, size as u64);
            let expected_chunks = if size == 0 { 1 } else { (size as u64).div_ceil(1024 * 1024) };
            assert_eq!(header.chunk_count, expected_chunks);
        }
    }

    #[test]
    fn wrong_data_key_fails() {
        let vault_id = [5u8; 16];
        let object_id = [6u8; 16];
        let blob = seal_blob(&Key32::random(), &vault_id, &object_id, 1, b"hi");
        let parsed = ObjectHeader::parse(&blob[..OBJECT_HEADER_SIZE]).unwrap();
        let mut out = Vec::new();
        let res = open_object(
            &mut &blob[OBJECT_HEADER_SIZE..],
            &parsed,
            &Key32::random(),
            &vault_id,
            &mut out,
        );
        assert!(res.is_err());
    }

    #[test]
    fn cross_vault_blob_rejected() {
        let object_id = [6u8; 16];
        let data_key = Key32::random();
        let blob = seal_blob(&data_key, &[5u8; 16], &object_id, 1, b"hi");
        let parsed = ObjectHeader::parse(&blob[..OBJECT_HEADER_SIZE]).unwrap();
        let mut out = Vec::new();
        let res = open_object(
            &mut &blob[OBJECT_HEADER_SIZE..],
            &parsed,
            &data_key,
            &[6u8; 16], // different vault id
            &mut out,
        );
        assert!(res.is_err());
    }

    #[test]
    fn spliced_object_from_other_id_rejected() {
        let data_key = Key32::random();
        let blob_a = seal_blob(&data_key, &[5u8; 16], &[1u8; 16], 1, b"secret-a");
        // Replace object_id in header with another id (simulates substitution).
        let mut header_bytes = blob_a[..OBJECT_HEADER_SIZE].to_vec();
        header_bytes[12..28].copy_from_slice(&[2u8; 16]);
        let parsed = ObjectHeader::parse(&header_bytes).unwrap();
        let mut out = Vec::new();
        let res = open_object(
            &mut &blob_a[OBJECT_HEADER_SIZE..],
            &parsed,
            &data_key,
            &[5u8; 16],
            &mut out,
        );
        assert!(res.is_err());
    }

    #[test]
    fn tampered_header_stats_detected() {
        let data = vec![0x55u8; 2048];
        let vault_id = [5u8; 16];
        let object_id = [6u8; 16];
        let data_key = Key32::random();
        let mut blob = seal_blob(&data_key, &vault_id, &object_id, 1, &data);

        // Corrupt plaintext_len (bytes 48..56). The DEK AAD does not cover
        // this field, so detection must come from the stream statistics check.
        blob[48] ^= 0x01;
        let parsed = ObjectHeader::parse(&blob[..OBJECT_HEADER_SIZE]).unwrap();
        let mut out = Vec::new();
        let res = open_object(
            &mut &blob[OBJECT_HEADER_SIZE..],
            &parsed,
            &data_key,
            &vault_id,
            &mut out,
        );
        assert!(matches!(res, Err(ContainerError::Crypto(vault_crypto::CryptoError::StreamIntegrity(_)))));
    }

    #[test]
    fn bad_magic_and_version_rejected() {
        let blob = seal_blob(&Key32::random(), &[5u8; 16], &[6u8; 16], 1, b"x");
        let mut hb = blob[..OBJECT_HEADER_SIZE].to_vec();
        hb[0] = b'Q';
        assert!(matches!(ObjectHeader::parse(&hb), Err(ContainerError::BadMagic(_))));
        let mut hb = blob[..OBJECT_HEADER_SIZE].to_vec();
        hb[8] = 7;
        assert!(matches!(ObjectHeader::parse(&hb), Err(ContainerError::UnsupportedVersion { .. })));
        assert!(ObjectHeader::parse(&hb[..50]).is_err());
    }
}
