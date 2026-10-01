# Architecture

## Layering

```text
front-end (vault-cli / vault-ui)
        │  restricted API
        ▼
 vault-core::VaultEngine ── Session (keys, zeroized on lock)
        │
   ┌────┼──────────┬─────────────┐
   ▼    ▼          ▼             ▼
 header  manifest  object blobs  audit log      (vault-container)
   │        │          │            │
   └────────┴──────────┴────────────┘
             vault-storage (atomic writes, fault injection)
             vault-security (lockdown, control state, DPAPI)
             vault-crypto / vault-recovery (primitives, recovery keys)
```

| Crate | Responsibility |
|---|---|
| `vault-crypto` | Argon2id, HKDF labels, XChaCha20-Poly1305 envelopes, STREAM chunks, zeroizing key types |
| `vault-container` | header / manifest / blob / `CURRENT` binary formats, strict parsers |
| `vault-storage` | temp-file + rename atomic writes, size caps, temp GC, fault injection |
| `vault-security` | lockdown state machine, DPAPI-backed control state, binary hashing |
| `vault-recovery` | 256-bit recovery key generation/display |
| `vault-core` | `VaultEngine`: sessions, unlock, commits, CRUD, integrity, crypto-erase |
| `vault-cli` | non-interactive command line (env/TTY passwords only — never argv) |
| `vault-ui` | native Slint desktop front-end |

## Commit protocol (crash safety)

Mutating operations follow one protocol:

1. write object blob (temp + `fsync` + atomic rename),
2. seal generation *N+1* to `manifest/manifest-<hex N+1>.bin`,
3. atomically replace `CURRENT` with `(N+1, sha256(manifest file))`,
4. update the control-state witness,
5. append the audit event.

An interruption at any point leaves either the previous complete state or
the new complete state; partially written files are `.tmp` debris removed at
the next unlock. Manifest files newer than `CURRENT` are orphan-collected.
Interrupted *updates* (blob newer than manifest) are healed from the blob via
the `pending_commit` witness in control state.

Every critical write site is a named fault point (`VAULT_FAULT_POINT=<name>`
hard-exits the process), and `crash.rs` drives the binary through each one
to assert the recovery invariant.

## Unlock pipeline

```text
header parse ── control load (DPAPI) ── binary/lockdown checks
   │
   ├─ rekey pending? ─► drive_rekey (idempotent resume, password only)
   ▼
Argon2id unwrap root ─► derive domain keys
   ▼
CURRENT → manifest file → sha256 check → vault_id check →
hash-chain check → anti-rollback witness
   ▼
AEAD-open manifest → install Session → control reset/witness →
open audit chain → flush pending events → GC → heal pending → audit unlock
```

Failure at every stage maps to a single deterministic error class; wrong
password and tampered header are indistinguishable (`AuthFailed`).

## Search model

`search` decrypts item metadata in memory and matches the query; no
persistent index exists, so search leaves no plaintext trace on disk
(see `docs/secure-memory.md`).
