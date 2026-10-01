# Key management

## Hierarchy

```text
master password (user, never persisted)
   └─ Argon2id(m, t, p, header salt) ─► KEK
         └─ XChaCha20-Poly1305 unwrap ─► root key RK   (header envelope)
               └─ HKDF-SHA256(label, ctx=vault_id)
                     ├─ data      ─ wraps per-object DEKs (blob headers)
                     ├─ meta      ─ seals the manifest
                     ├─ audit     ─ seals the audit chain
                     ├─ integrity ─ reserved
                     ├─ control   ─ reserved
                     └─ recovery  ─ reserved

recovery key (256-bit CSPRNG, shown once)
   └─ HKDF("vault:recovery-kek:v1", ctx=vault_id) ─► same root envelope
```

Per-object DEKs are fresh 256-bit values; the payload key of an object is
never reused across objects or versions.

## Lifecycle

| Event | Key action |
|---|---|
| `init` | RK generated; header written; domain keys derived in memory |
| `unlock` | Argon2id → RK → domain keys; Session installed (zeroized on lock) |
| `lock` | Session dropped, manifest `wipe()` called, audit handle dropped |
| `password-change` | same RK, new salt + new envelope; recovery envelope untouched (its AAD excludes the KDF region) |
| `recovery enable` | recovery envelope added (AAD excludes KDF/root region → password changes don't invalidate it) |
| `recover` | RK unwrapped with recovery key; immediate password re-wrap with fresh salt; old password dies |
| `domain rekey` | fresh RK′: blobs/manifest/audit re-wrapped, next envelope promoted, recovery envelope destroyed |
| `vault erase` | header overwritten with random bytes, directory removed — everything unreadable |
| `delete item` | object's DEK dies with its blob + manifest entry (commit first, blob removed after) |

## Confirmation rules

Irreversible operations (`vault`, `domain` scopes of crypto-erase) require
the master password as deliberate proof of possession; missing confirmation
is `EraseConfirmationRequired`, wrong password is `AuthFailed`.

## Zeroization

* `Key32`, `SecretBytes`, `DomainKeys` derive `Zeroize/ZeroizeOnDrop`.
* `Session` drop relies on the above.
* `Manifest::wipe()` clears names, previews, tags, usernames, URLs on lock.
* The password buffer is wiped after deriving the KEK (`SecretBytes` drop).
* CLI reads passwords from the TTY (echo off) or `VAULT_PASSWORD`
  (test/automation; a warning is printed). Passwords are **never** passed
  as command-line arguments.

Zeroization is best-effort in a GC'd language runtime: it covers Vault's own
buffers, not copies the allocator or OS may have made (documented in
`secure-memory.md`).
