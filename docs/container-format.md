# Container format

## Directory layout

```text
<vault root>/
├── VAULTHDR                     4096 B plaintext header (VLTCONT1)
├── CURRENT                       48 B generation pointer (VLTNOW01)
├── manifest/
│   ├── manifest-<hex gen>.bin    sealed manifest, one per generation
│   └── *.tmp                    debris — GC'd at unlock
├── objects/
│   └── <xx>/<hex id>            sealed object blobs (sharded by id prefix)
├── state/
│   └── ctl.bin                  control state (DPAPI 'D' / plaintext 'P')
└── audit/
    └── audit.bin                hash-chained encrypted audit log
```

## `VAULTHDR` — 4096 B, magic `VLTCONT1`

| off | size | field | notes |
|---:|---:|---|---|
| 0 | 8 | magic | `"VLTCONT1"` |
| 8 | 2 | format_version | u16 = 1 |
| 10 | 2 | crypto_suite | u16 = 1 |
| 12 | 16 | vault_id | CSPRNG; binds every container part |
| 28 | 2 | kdf_id | 1 = Argon2id |
| 30 | 4 | memory_kib | u32 |
| 34 | 4 | iterations | u32 |
| 38 | 4 | parallelism | u32 |
| 42 | 32 | kdf_salt | CSPRNG |
| 74 | 2 | reserved0 | must be 0 |
| 76 | 2 | flags | bit0 = recovery present |
| 78 | 24 | root_nonce | |
| 102 | 48 | root_envelope | RK under password KEK |
| 150 | 32 | recovery_salt | |
| 182 | 8 | created_at_ms | u64 |
| 190 | 8 | app_version | u64 |
| 198 | 24 | recovery_nonce | |
| 222 | 48 | recovery_envelope | RK under recovery KEK |
| 270 | 1 | rekey_state | 0 = none, 1 = pending domain rekey |
| 271 | 32 | next_kdf_salt | pending rekey password salt |
| 303 | 24 | next_root_nonce | |
| 327 | 48 | next_root_envelope | RK′ under next KEK |
| 375 | 3721 | reserved | must be all zero |

Validation is strict: wrong magic/version/suite, nonzero reserved bytes,
nonzero next-region while `rekey_state = 0`, pending state without a next
envelope, or a zeroed root envelope are all hard errors. See
`header.rs` for the AAD table.

## `CURRENT` — 48 B, magic `VLTNOW01`

```text
8 B magic || u64_le(generation) || 32 B sha256(manifest file)
```

## Manifest — magic `VLTMAN01`

```text
prefix (76 B, plaintext): magic, fmt u16, suite u16, vault_id,
                          generation u64, committed_at_ms u64,
                          prev_manifest_hash 32 B
body: AEAD(meta_key, aad = prefix, encode(folders, objects))
```

Folder entries: `id, parent, created, updated, name`.
Object entries: `id, type, version, size, chunk_count, content_hash,
folder, created, updated, flags, meta-json` (name, mime, username, url,
category, tags, preview). Hostile-input guards: ≤ 5 000 000 entries,
meta ≤ 16 MiB, strict UTF-8, no trailing bytes.

## Object blob — magic `VLTLOBJ1`, 136 B header

| off | size | field |
|---:|---:|---|
| 0 | 8 | magic `"VLTLOBJ1"` |
| 8 | 2 | format_version = 1 |
| 10 | 2 | crypto_suite = 1 |
| 12 | 16 | object_id |
| 28 | 4 | object_version (u32, ≥ 1) |
| 32 | 16 | nonce_prefix |
| 48 | 8 | plaintext_len u64 |
| 56 | 8 | chunk_count u64 (≥ 1) |
| 64 | 72 | wrapped DEK (nonce slot + ct + tag) |
| 136 | * | chunk stream, 1 MiB plaintext per chunk |

## Audit log — `audit/audit.bin`

`u32_le(len) || AEAD(...)` records chained by
`aad = seq || sha256(previous record)` (see `crypto-spec.md`).

## Control state — `state/ctl.bin`

```text
'D' || DPAPI(blob)      protected with vault_id entropy
'P' || json             degraded mode (DPAPI unavailable)
```

Fields: format, vault_id, failed_attempts, lockout_until_ms,
max_seen_generation, seen_manifest_hash, binary_hash, capability
(`dpapi`/`degraded`), updated_ms, pending_commit.

## Durability

All replaces: write `<name>.<rand>.tmp` → `fsync` → atomic rename →
best-effort dir sync (no-op on Windows — documented limit). Fault points:
`after_data_write`, `after_fsync`, `after_rename`, `after_dir_sync`, plus
operation-specific points (`after_header_write`, `after_initial_commit`,
`after_manifest_write`, `after_current_write`, `after_blob_write`,
`after_commit_before_blob_delete`, `after_header_recovery_write`,
`after_header_password_change`, `after_key_destruction`,
`after_rekey_arm`, `after_rekey_blobs`, `after_rekey_audit`,
`after_rekey_manifest`, `after_rekey_finalize`).
