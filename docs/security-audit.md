# Security audit

Status: **internal review, pre-release** — this document is an engineering
self-audit of the implemented controls and their test evidence, not a
third-party assessment.

## Design review (implemented controls)

| Control | Location | Evidence |
|---|---|---|
| Argon2id with validated floors (m ≥ 19456 KiB, t ≥ 2) | `vault-crypto/kdf.rs` | `kdf.rs` tests, header validation |
| Uniform `AuthFailed` (no wrong-password/tamper oracle) | `header.rs unwrap_root`, engine unlock | `create_lock_unlock_roundtrip`, CLI `wrong_password_is_rejected` |
| Exponential unlock lockout (5 → 300 s·2^(n−5) ≤ 1 h) | engine `register_failed_attempt` | `repeated_failures_cause_lockout` |
| Lockdown state machine, CRITICAL only via explicit triggers | `vault-security/lockdown.rs` | 13 security-crate tests |
| Anti-rollback witness checked on every unlock path | `read_verified_manifest_bytes` | `rollback_of_container_is_detected` |
| Hash-chained manifest + `CURRENT` binding | container + engine | blob/CURRENT corruption tests |
| Tamper-evident audit log (seq+prev-hash AAD) | `audit.rs` | chain/tamper/truncate tests |
| STREAM chunk AAD binds index/finality/length | `vault-crypto/stream.rs` | reordering/truncation/splice tests |
| Cross-vault/object/version blob binding | `object.rs` AAD | substitution tests |
| Atomic temp+rename with fsync, temp GC | `vault-storage/atomic.rs` | fault-point crash matrix (21 points) |
| Interrupted-update healing (`pending_commit`) | engine `heal_pending_updates` | crash heal tests |
| Orphan manifest/blob collection at unlock | `collect_garbage` | crash GC tests |
| Two-phase domain rekey, idempotent resume | `drive_rekey` + header region | 5 `after_rekey_*` crash tests |
| Recovery unlock refused during pending rekey | `unlock_with_recovery` | `pending_domain_rekey_blocks_recovery_unlock` |
| Irreversible erases require password proof | `crypto_erase` | `crypto_erase_scopes`, domain proof test |
| DPAPI-protected control state, plaintext fallback labeled | `vault-security/control.rs` | control round-trip tests |
| Hostile-input caps (entry counts, meta size, record sizes, read caps) | manifest/audit/parse paths | malformed-input tests |
| Strict parsers: reserved bytes, versions, magic, lengths | all container formats | header/manifest/blob negative tests |
| Passwords never in argv; TTY or env with warning | `vault-cli` | CLI integration tests |

## Test evidence

`cargo test --workspace` — 130 tests: unit (crypto/container/storage/
security/recovery/core), end-to-end engine suite, fault-injection crash
suite (child-process hard-exit at named points), CLI integration suite
against the real binary.

## Findings & accepted risks

| ID | Severity | Status |
|---|---|---|
| F-1 Binary-hash self-check is weak (attacker can update both sides) | Low | Accepted, documented in threat model |
| F-2 Control-state witness degrades to plaintext without DPAPI | Medium | Accepted on non-DPAPI platforms; documented |
| F-3 Windows: directory fsync is a no-op (documented durability limit) | Low | Accepted; file-level fsync+rename still atomic |
| F-4 Best-effort zeroization (allocator/swap copies) | Medium | Documented in `secure-memory.md` |
| F-5 No mlock/VirtualLock — unlocked keys may reach swap | Medium | Documented; out of scope pre-1.0 |
| F-6 Recovery capability is destroyed by a domain rekey | Info | By design; audited + documented |
| F-7 `control.unavailable` resets the rollback witness on first load | Low | Accepted; warning + audit event recorded |
| F-8 Slint UI layer not yet adversarially reviewed | — | Pending (see roadmap) |

## Dependency audit

`cargo audit` (RustSec advisory DB, 1279 advisories, 608 locked
dependencies) run 2026-10-01:

- **0 known vulnerabilities.**
- 2 *unmaintained* warnings, both transitive UI-stack dependencies that
  never see vault secrets or container bytes:
  - `bincode 2.0.1` (RUSTSEC-2025-0141) ← `typed-index-collections` ←
    `i-slint-compiler` (build-time Slint compiler only).
  - `ttf-parser 0.25.1` (RUSTSEC-2026-0192) ← `ab_glyph` ← `winit`/`sctk-adwaita`
    (font rasterization for the UI).

Accepted: replacing either would require forking Slint's dependency tree;
monitored via the CI audit job.

## Residual engineering work before a real audit

1. External review of `drive_rekey` interleavings (crash matrix expanded
   to nested fault pairs).
2. Constant-time review of compare paths (current compares rely on
   AEAD failure for secrets; explicit `ct_eq` for remaining byte compares).
3. Fuzzing targets for header/manifest/blob/audit parsers (`cargo-fuzz`).
4. ~~Dependency audit (`cargo audit`) in CI.~~ Done: `.github/workflows/ci.yml`
   runs `rustsec/audit-check` on every push/PR.
