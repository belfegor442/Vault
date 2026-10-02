# Threat model

## Assets

| Asset | Where it lives | Protection |
|---|---|---|
| Item contents (notes, files, passwords) | `objects/<xx>/<id>` blobs | XChaCha20-Poly1305, per-object DEK |
| Item metadata (names, usernames, URLs, previews, tags) | encrypted manifest | XChaCha20-Poly1305 under the meta domain key |
| Audit trail | `audit/audit.bin` | XChaCha20-Poly1305 + hash chain |
| Master password | never persisted | memory only, zeroized after KDF |
| Root key / domain keys | wrapped in `VAULTHDR`, else memory | Argon2id-wrapped envelope |
| Recovery key | shown exactly once, never persisted | 256-bit CSPRNG output |
| Anti-rollback witness | `state/ctl.bin` | DPAPI-protected (degraded: plaintext) |

## Adversary capabilities in scope

1. **Offline storage attacker** — full read/write access to the vault
   directory at rest (stolen laptop, backup leak, filesystem image).
   Defenses: AEAD on every stored byte of content/metadata, hash-chained
   manifest, `CURRENT` + witnessed generation counter, per-record audit chain.
2. **Interactive brute-force attacker** — can call the unlock API repeatedly.
   Defenses: Argon2id cost, uniform `AuthFailed` for wrong password *and*
   tampered header, exponential lockout after 5 failures (300 s · 2^(n−5),
   capped at 1 h), lockdown state machine records repeated failures.
3. **Rollback attacker** — restores an older consistent container snapshot.
   Defenses: `max_seen_generation` + `seen_manifest_hash` witnessed in
   control state; a lower generation is refused, escalates to LOCKED and
   destroys the session (re-auth restores at most `SUSPICIOUS`).
4. **Live tamperer (limited)** — modifies blobs, manifest, `CURRENT`,
   header fields. Defenses: AEAD + hash chain detect every stored structure;
   the header's root-envelope AAD covers identity and KDF parameters.
5. **Malicious replacement of the executable** — weakly detected by hashing
   the running binary against the value recorded in control state
   (documented as *weak*: an attacker with write access can update both).

## Out of scope / accepted limitations

* An attacker with code execution **while the vault is unlocked** (keys are
  in process memory; OS-level malware defeats any user-space vault).
* Kernel/hibernation attacks on live memory; swapping of unlocked memory.
* An attacker who can write *both* the binary and its recorded hash.
* Traffic analysis: Vault has no network component at all.
* Multi-user access control: one vault = one owner.
* Hardware-backed key storage (TPM/secure-enclave) — not implemented;
  DPAPI only protects the small control-state file, not the container.

## Security posture by state

| Lockdown state | Meaning | Writes |
|---|---|---|
| NORMAL | clean session | allowed |
| SUSPICIOUS | low-confidence findings acknowledged or pending | allowed |
| RESTRICTED | sustained failures / integrity warnings | blocked by policy |
| LOCKED | auth suspended until backoff expires | blocked |
| CRITICAL | reserved for operator-declared compromise | blocked; requires `resolve_critical` |

`CRITICAL` is reachable only through `Lockdown::escalate_critical`
(an explicit operator declaration); no rule-table trigger maps to it —
tamper-class findings (rollback, manifest/vault-id mismatch, rekey
failures) land in `LOCKED` with session destruction instead, and are never
used as a generic error path.
