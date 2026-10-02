# Cryptographic specification

All constructions are standard, composition-of-standard-primitives only —
no custom cipher, MAC, or mode.

## Primitives

| Purpose | Algorithm | Reference |
|---|---|---|
| Password KDF | Argon2id | RFC 9106 |
| Subkey derivation | HKDF-SHA256 (labeled) | RFC 5869 |
| AEAD (envelopes, manifest, audit) | XChaCha20-Poly1305 | libsodium / RFC 8439 variant |
| Large-object encryption | STREAM of XChaCha20-Poly1305 over 1 MiB chunks | Rogaway et al. |
| Hashing (chain, content) | SHA-256 | FIPS 180-4 |
| All random values | OS CSPRNG (`OsRng`) | — |

## Argon2id parameters

| Profile | memory | iterations | lanes |
|---|---|---|---|
| Production (default) | 65536 KiB | 3 | 1 |
| Floor (tests/CI) | 19456 KiB | 2 | 1 |

Parameters are stored in the header (`kdf_id=1`, m, t, p, 32-byte salt) and
validated on parse (`m ≥ 19456`, `t ≥ 2`, `p ≥ 1`).

## Key hierarchy

```text
master password ──Argon2id(salt, m, t, p)──► KEK
                                              │  unwrap (AAD = hdr[0..76))
                                              ▼
                          root key RK (32 B, CSPRNG at creation)
                                              │ HKDF-SHA256
              ┌───────────────┬───────────────┼───────────────┬──────────────┐
              ▼               ▼               ▼               ▼              ▼
     data (blob DEKs)   manifest/meta   audit chain     integrity       control
              │               │               │            (reserved)   (reserved)
     objects/<xx>/<id>   manifest-N.bin   audit.bin
```

HKDF labels (salt/context = `vault_id`, except the recovery KEK below):

```text
vault:domain:data:v1        vault:domain:meta:v1
vault:domain:integrity:v1   vault:domain:control:v1
vault:domain:recovery:v1    vault:domain:audit:v1
```

Recovery KEK: `HKDF(recovery_key → "vault:recovery-kek:v1", ctx=vault_id||recovery_salt)`
— no Argon2, because the recovery input is already 256 bits of CSPRNG output.
The `recovery_salt` binds the envelope to the specific recovery material, so
a stolen *old* recovery key cannot unwrap a re-issued envelope.

## Envelope (wrapped key)

```text
envelope := nonce(24) || ciphertext(32) || tag(16)   = 72 B raw
            └ stored as 48 B ciphertext+tag after stripping the nonce slot
key-encryption  = XChaCha20-Poly1305(kek, aad, key)
```

AAD regions of the header:

| Envelope | AAD |
|---|---|
| root (current) | `hdr[0..76)` — magic, versions, vault_id, KDF params |
| recovery | `hdr[0..28)` — magic, versions, vault_id |
| next (pending rekey) | `hdr[0..76)` as it reads **after** finalization (`kdf.salt = next_salt`) |

## Object blobs (STREAM)

* Per-object random 256-bit DEK, wrapped under the **data** domain key with
  AAD = `vault_id || object_id || version`.
* Chunk plaintext size: 1 MiB. Chunk nonce = `nonce_prefix(16) || u64_be(i)`.
* Chunk AAD = `vault_id || object_id || version || u64_be(i) || final_flag ||
  u64_be(chunk_len)` — reordering, splicing across objects/vaults, truncation
  and length manipulation are all detected.
* Empty plaintext is still one authenticated (empty, final) chunk.
* Header statistics (`plaintext_len`, `chunk_count`) are re-checked against
  the decrypted stream; mismatch is a hard error.

## Manifest

Sealed with `XChaCha20-Poly1305(meta_key, aad = 76-byte plaintext prefix,
body)`; the prefix carries magic `VLTMAN01`, versions, `vault_id`,
`generation`, `committed_at_ms`, `prev_manifest_hash`. File integrity =
`sha256(file bytes)`, recorded in `CURRENT` and chained via
`prev_manifest_hash`.

## Audit chain

```text
record := u32_le(len) || sealed
sealed := AEAD(audit_key, aad = u64_le(seq) || sha256(prev record), json_event)
```

Removing, reordering or mutating any record breaks verification. Events
never carry secrets.

## Domain rekey (crypto-erase scope `domain`)

Two-phase header transition (see `container-format.md` for the region):

1. **arm** — fresh RK′, fresh password salt; next envelope installed while
   the current envelope keeps working,
2. **migrate** — blob DEKs re-wrapped (streaming temp + rename), audit
   re-sealed, manifest re-committed under the new domain keys,
3. **finalize** — next envelope promoted to current, recovery envelope
   destroyed (it wraps the dead root key).

Every step probes old vs new keys, so a crash at any named
`after_rekey_*` fault point resumes idempotently on the next password
unlock. Recovery unlock is refused while a rekey is pending.

## Uniform failure

`unwrap_root` returns one deterministic error for wrong password and for
header tamper (the AAD/KDF binding makes both fail identically), so no
oracle distinguishes them.
