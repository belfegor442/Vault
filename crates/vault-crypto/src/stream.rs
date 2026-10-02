//! Chunked authenticated encryption (STREAM composition over XChaCha20-Poly1305).
//!
//! Vault encrypts objects larger than memory (videos, archives) without ever
//! buffering the whole plaintext. Each chunk is an independent AEAD
//! invocation bound to:
//!
//! * the vault id and object id (via `aad_prefix`),
//! * the chunk index (prevents reordering / splicing / replay),
//! * whether it is the final chunk (prevents truncation at a chunk boundary),
//! * the chunk length (prevents length manipulation).
//!
//! Nonce for chunk `i` = `nonce_prefix(16) || i (u64 big-endian)`.
//! The 16-byte prefix is random per object; together with the strictly
//! increasing index every (key, nonce) pair is unique for that object.
//!
//! This is the standard STREAM composition of an AEAD (Rogaway et al.), not
//! a custom primitive: each chunk is sealed with the same key under distinct
//! nonces, and the final flag is authenticated.

use std::io::{Read, Write};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::aead::{NONCE_LEN, TAG_LEN};
use crate::error::CryptoError;
use crate::keys::Key32;

/// Plaintext bytes per chunk (1 MiB).
pub const CHUNK_SIZE: usize = 1024 * 1024;
pub const NONCE_PREFIX_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamStats {
    pub plaintext_len: u64,
    pub chunk_count: u64,
}

fn build_nonce(prefix: &[u8; NONCE_PREFIX_LEN], index: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn build_chunk_aad(prefix: &[u8], index: u64, final_chunk: bool, chunk_len: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(prefix.len() + 8 + 1 + 8);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(u8::from(final_chunk));
    aad.extend_from_slice(&chunk_len.to_be_bytes());
    aad
}

/// Fill `buf` completely unless EOF is reached. Returns bytes read.
fn fill_up_to(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// Seal a plaintext stream. Writes `ciphertext || tag` per chunk with no
/// per-chunk nonce (nonce is derived from prefix + index).
pub fn seal_stream(
    key: &Key32,
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    aad_prefix: &[u8],
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<StreamStats, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| CryptoError::Malformed("bad key length"))?;

    let mut index: u64 = 0;
    let mut plaintext_len: u64 = 0;
    let mut current = vec![0u8; CHUNK_SIZE];
    let n = fill_up_to(reader, &mut current).map_err(CryptoError::Io)?;
    current.truncate(n);

    // Empty input still gets exactly one (empty, final) authenticated chunk.
    if current.is_empty() {
        let aad = build_chunk_aad(aad_prefix, 0, true, 0);
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&build_nonce(nonce_prefix, 0)),
                Payload {
                    msg: &current,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Malformed("invalid key length for aead"))?;
        writer
            .write_all(&ct)
            .map_err(CryptoError::Io)?;
        return Ok(StreamStats {
            plaintext_len: 0,
            chunk_count: 1,
        });
    }

    loop {
        let mut next = vec![0u8; CHUNK_SIZE];
        let n = fill_up_to(reader, &mut next).map_err(CryptoError::Io)?;
        next.truncate(n);

        let is_final = next.is_empty();
        let aad = build_chunk_aad(aad_prefix, index, is_final, current.len() as u64);
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&build_nonce(nonce_prefix, index)),
                Payload {
                    msg: &current,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Malformed("invalid key length for aead"))?;
        writer
            .write_all(&ct)
            .map_err(CryptoError::Io)?;

        plaintext_len += current.len() as u64;
        index += 1;

        if is_final {
            break;
        }
        current = next;
    }

    Ok(StreamStats {
        plaintext_len,
        chunk_count: index,
    })
}

/// Open (decrypt + verify) a sealed stream produced by [`seal_stream`].
///
/// `expected_chunks` / `expected_len` come from the authenticated object
/// header; a mismatch (truncation, appended data) is a hard failure.
pub fn open_stream(
    key: &Key32,
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    aad_prefix: &[u8],
    reader: &mut impl Read,
    writer: &mut impl Write,
    expected_chunks: u64,
    expected_len: u64,
) -> Result<StreamStats, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| CryptoError::Malformed("bad key length"))?;

    let mut index: u64 = 0;
    let mut plaintext_len: u64 = 0;
    let mut carry: Option<u8> = None;

    loop {
        // Read up to CHUNK_SIZE bytes, possibly starting with the carry byte.
        let mut buf = vec![0u8; CHUNK_SIZE + TAG_LEN];
        let mut n = 0;
        if let Some(b) = carry.take() {
            buf[0] = b;
            n = 1;
        }
        n += fill_up_to(reader, &mut buf[n..])?;

        // Look ahead one byte: it decides whether this chunk is final.
        let mut probe = [0u8; 1];
        let probed = reader.read(&mut probe)?;
        let has_more = probed == 1;
        if has_more {
            carry = Some(probe[0]);
        }
        let is_final = !has_more;

        if n < TAG_LEN {
            return Err(CryptoError::AuthFailed);
        }
        // AAD binds the plaintext length; the ciphertext carries TAG_LEN extra bytes.
        let plain_len = (n - TAG_LEN) as u64;
        let aad = build_chunk_aad(aad_prefix, index, is_final, plain_len);
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&build_nonce(nonce_prefix, index)),
                Payload {
                    msg: &buf[..n],
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthFailed)?;
        writer
            .write_all(&plaintext)
            .map_err(CryptoError::Io)?;

        plaintext_len += plaintext.len() as u64;
        index += 1;

        if is_final {
            break;
        }
    }

    let stats = StreamStats {
        plaintext_len,
        chunk_count: index,
    };
    if stats.chunk_count != expected_chunks || stats.plaintext_len != expected_len {
        return Err(CryptoError::StreamIntegrity(
            "decrypted stream does not match authenticated header",
        ));
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::random_bytes;

    fn roundtrip(data: &[u8]) -> (Vec<u8>, StreamStats) {
        let key = Key32::random();
        let prefix: [u8; NONCE_PREFIX_LEN] = random_bytes();
        let mut sealed = Vec::new();
        let st = seal_stream(&key, &prefix, b"vault|object", &mut &data[..], &mut sealed)
            .unwrap();
        let mut out = Vec::new();
        let st2 = open_stream(
            &key,
            &prefix,
            b"vault|object",
            &mut &sealed[..],
            &mut out,
            st.chunk_count,
            st.plaintext_len,
        )
        .unwrap();
        assert_eq!(out, data);
        assert_eq!(st, st2);
        (sealed, st)
    }

    #[test]
    fn roundtrip_various_sizes() {
        for size in [
            0usize,
            1,
            100,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            2 * CHUNK_SIZE + 12345,
        ] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let (_, st) = roundtrip(&data);
            assert_eq!(st.plaintext_len, size as u64);
            let expected_chunks = if size == 0 {
                1
            } else {
                size.div_ceil(CHUNK_SIZE) as u64
            };
            assert_eq!(st.chunk_count, expected_chunks);
        }
    }

    #[test]
    fn wrong_key_fails() {
        let key = Key32::random();
        let prefix: [u8; NONCE_PREFIX_LEN] = random_bytes();
        let mut sealed = Vec::new();
        seal_stream(&key, &prefix, b"a", &mut &b"hello"[..], &mut sealed).unwrap();
        let mut out = Vec::new();
        let res = open_stream(
            &Key32::random(),
            &prefix,
            b"a",
            &mut &sealed[..],
            &mut out,
            1,
            5,
        );
        assert!(res.is_err());
    }

    #[test]
    fn wrong_aad_prefix_fails() {
        let key = Key32::random();
        let prefix: [u8; NONCE_PREFIX_LEN] = random_bytes();
        let mut sealed = Vec::new();
        seal_stream(&key, &prefix, b"object-1", &mut &b"hello"[..], &mut sealed).unwrap();
        let mut out = Vec::new();
        let res = open_stream(
            &key,
            &prefix,
            b"object-2",
            &mut &sealed[..],
            &mut out,
            1,
            5,
        );
        assert!(res.is_err());
    }

    #[test]
    fn chunk_reordering_detected() {
        let data: Vec<u8> = (0..(2 * CHUNK_SIZE + 100)).map(|i| (i % 250) as u8).collect();
        let key = Key32::random();
        let prefix: [u8; NONCE_PREFIX_LEN] = random_bytes();
        let mut sealed = Vec::new();
        let st = seal_stream(&key, &prefix, b"a", &mut &data[..], &mut sealed).unwrap();
        assert_eq!(st.chunk_count, 3);

        let c0 = &sealed[..CHUNK_SIZE + TAG_LEN];
        let c1 = &sealed[CHUNK_SIZE + TAG_LEN..2 * (CHUNK_SIZE + TAG_LEN)];
        let c2 = &sealed[2 * (CHUNK_SIZE + TAG_LEN)..];
        let mut swapped = Vec::new();
        swapped.extend_from_slice(c1);
        swapped.extend_from_slice(c0);
        swapped.extend_from_slice(c2);

        let mut out = Vec::new();
        let res = open_stream(&key, &prefix, b"a", &mut &swapped[..], &mut out, 3, data.len() as u64);
        assert!(matches!(res, Err(CryptoError::AuthFailed)));
    }

    #[test]
    fn truncation_at_chunk_boundary_detected() {
        let data: Vec<u8> = vec![0xAB; CHUNK_SIZE + 10];
        let key = Key32::random();
        let prefix: [u8; NONCE_PREFIX_LEN] = random_bytes();
        let mut sealed = Vec::new();
        let st = seal_stream(&key, &prefix, b"a", &mut &data[..], &mut sealed).unwrap();
        assert_eq!(st.chunk_count, 2);

        // Drop the final chunk: stream now ends after a chunk sealed as
        // non-final, so the final-flag AAD mismatches.
        let truncated = &sealed[..CHUNK_SIZE + TAG_LEN];
        let mut out = Vec::new();
        let res = open_stream(&key, &prefix, b"a", &mut &truncated[..], &mut out, 2, data.len() as u64);
        assert!(res.is_err());
    }

    #[test]
    fn truncation_inside_chunk_detected() {
        let data: Vec<u8> = vec![0xCD; 5000];
        let key = Key32::random();
        let prefix: [u8; NONCE_PREFIX_LEN] = random_bytes();
        let mut sealed = Vec::new();
        seal_stream(&key, &prefix, b"a", &mut &data[..], &mut sealed).unwrap();
        let mut out = Vec::new();
        let res = open_stream(&key, &prefix, b"a", &mut &sealed[..sealed.len() - 1], &mut out, 1, 5000);
        assert!(res.is_err());
    }

    #[test]
    fn appended_chunk_detected() {
        let data: Vec<u8> = vec![0x11; 100];
        let key = Key32::random();
        let prefix: [u8; NONCE_PREFIX_LEN] = random_bytes();
        let mut sealed = Vec::new();
        seal_stream(&key, &prefix, b"a", &mut &data[..], &mut sealed).unwrap();
        // Splice a valid chunk from another object.
        let mut other_prefix: [u8; NONCE_PREFIX_LEN] = random_bytes();
        other_prefix.copy_from_slice(&prefix);
        let mut other = Vec::new();
        seal_stream(&key, &other_prefix, b"b", &mut &data[..], &mut other).unwrap();

        let mut combined = sealed.clone();
        combined.extend_from_slice(&other);
        let mut out = Vec::new();
        let res = open_stream(&key, &prefix, b"a", &mut &combined[..], &mut out, 1, 100);
        assert!(res.is_err());
    }

    #[test]
    fn header_length_mismatch_detected() {
        let data: Vec<u8> = vec![0x22; 100];
        let key = Key32::random();
        let prefix: [u8; NONCE_PREFIX_LEN] = random_bytes();
        let mut sealed = Vec::new();
        let st = seal_stream(&key, &prefix, b"a", &mut &data[..], &mut sealed).unwrap();
        let mut out = Vec::new();
        // Claim wrong plaintext length.
        let res = open_stream(&key, &prefix, b"a", &mut &sealed[..], &mut out, st.chunk_count, 99);
        assert!(matches!(res, Err(CryptoError::StreamIntegrity(_))));
    }
}
