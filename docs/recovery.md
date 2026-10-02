# Recovery

## Recovery key

* 32 bytes from the OS CSPRNG — full entropy, therefore **no Argon2**
  (stretching a CSPRNG value would be wasted work).
* Display form: base64 in groups joined by `-` (e.g. from
  `vault-cli init --recovery` or `vault-cli recovery enable`).
* Shown **exactly once**; Vault never persists it. `from_display` accepts
  the grouped form with or without spaces and rejects anything else.

## How it works

The recovery key derives a recovery KEK (`HKDF-SHA256`,
label `vault:recovery-kek:v1`, context `vault_id || recovery_salt`) and
unwraps the **same** root envelope slot — it is a second way to obtain the
root key, not a separate data key. Binding the salt into the KDF context
ties the envelope to this exact recovery key, so a stolen *old* recovery
key cannot unwrap a re-issued envelope.

The recovery envelope's AAD is only `hdr[0..28)` (magic, versions,
vault_id), deliberately excluding the KDF/root-envelope/flags region so:

* password changes don't invalidate recovery, and
* recovery-material tampering is still detected (any edit to those 28
  bytes fails the AEAD).

## Flow

```text
vault-cli recover
  VAULT_RECOVERY_KEY=... VAULT_NEW_PASSWORD=...
```

1. parse + validate the display form,
2. unwrap the root key with the recovery KEK,
3. load and verify the manifest **before** committing anything,
4. write a new password envelope (fresh Argon2 salt),
5. audit `recovery.unlock`.

The old master password stops working immediately (new salt + new
envelope); the recovery key itself remains valid until re-issued or
disabled.

## Interactions

| Situation | Behavior |
|---|---|
| password change | recovery keeps working (AAD excludes KDF region) |
| `recovery disable` | envelope zeroized — crypto-erasure of the recovery path |
| `crypto_erase --scope domain` | **recovery envelope destroyed** — it wraps the old root key and cannot be re-created without the recovery secret. The audit event records `recovery envelope destroyed`. |
| domain rekey pending | recovery unlock is refused: only the master password can drive the transition to completion |

## CLI

```text
vault-cli recovery enable      # issue a new key (shown once)
vault-cli recovery disable     # destroy the recovery envelope
vault-cli recover              # recover with VAULT_RECOVERY_KEY + new password
vault-cli status               # shows "recovery: configured / not configured"
```
