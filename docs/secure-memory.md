# Secure memory

## Guarantees Vault aims for

1. **No plaintext at rest** — item content, metadata, audit events and the
   control state are ciphertext; the only plaintext on disk is the fixed
   header (identity/KDF parameters/timestamps) and generation pointers.
2. **No long-lived plaintext keys in memory** — key material lives in
   `Key32`/`SecretBytes`/`DomainKeys`, all of which zeroize on drop.
3. **Bounded plaintext lifetime** — the master password exists as
   `SecretBytes` only long enough to derive the KEK; the Session (root +
   domain keys) exists only between unlock and lock.
4. **No persistent plaintext index** — search decrypts metadata in memory
   and discards it; nothing searchable is written to disk.

## Mechanisms

| Mechanism | Where |
|---|---|
| `Zeroize` + `ZeroizeOnDrop` on `Key32`, `SecretBytes`, `DomainKeys` | `vault-crypto` |
| `Session` drop ⇒ keys gone | `vault-core` engine |
| `Manifest::wipe()` — names, previews, tags, usernames, URLs zeroed on lock | `vault-container` |
| Password via TTY echo-off (`rpassword`) or env var with warning; never argv | `vault-cli` |
| Blob/manifest/audit plaintext buffers dropped as soon as the operation ends | engine |
| Recovery key shown once, never stored | `vault-recovery` |

## Honest limitations

* **Rust is memory-safe but not an HSM.** Copies made by `String`
  reallocation, formatter buffers, or the allocator are not reliably
  wiped; `zeroize` covers the types that own secrets.
* **Swapping/hibernation:** Vault does not call `mlock`/`VirtualLock`.
  An attacker with the swap file or a hibernation image of an *unlocked*
  session may recover keys. The OS page file is out of Vault's control.
* **Compiler elision:** volatile zeroization (`zeroize` crate) resists
  dead-store elimination but cannot prove against every optimizer pass;
  this is the standard accepted approach in the Rust ecosystem.
* **Crash dumps:** a core dump of an unlocked process contains keys.
* **Process-memory attackers are out of scope** (see `threat-model.md`).

## Password handling detail

* `master_password()` reads `VAULT_PASSWORD` when set (automation; prints
  a stderr warning), otherwise prompts with echo disabled.
* `init`/`password-change`/`recover` require the new password twice
  (typo check) from independent sources (`VAULT_NEW_PASSWORD` or prompt).
* Minimum length 8 characters, enforced at `create`/`change`/`recover`.
* Failed unlock attempts never echo or log the password; errors are a
  single uniform class.
