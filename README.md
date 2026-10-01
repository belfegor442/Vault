# Vault

Native desktop security vault — written in Rust with a Slint UI. No
Electron, no Node, no HTML/JS runtime.

Vault encrypts notes, files and passwords in a versioned, tamper-evident
container with anti-rollback protection, crypto-erasure, a lockdown state
machine and crash-safe atomic storage.

## Features

* **Argon2id key hierarchy** — master password → KEK → root key → labeled
  HKDF domain keys (data / meta / audit / …), per-object DEKs.
* **Versioned container** — strict binary formats (`VLTCONT1` header,
  `VLTMAN01` manifest, `VLTNOW01` generation pointer, `VLTLOBJ1` blobs).
* **XChaCha20-Poly1305 everywhere** — envelopes, manifest, audit, and a
  1 MiB STREAM chunk mode binding index/finality/length.
* **Anti-rollback** — witnessed generation counter in DPAPI-protected
  control state; snapshot rollback escalates to CRITICAL lockdown.
* **Crypto-erasure** — scopes: `session`, `object`, `recovery`, `domain`
  (two-phase root-key rekey, crash-resumable), `vault`.
* **Lockdown state machine** — NORMAL → SUSPICIOUS → RESTRICTED → LOCKED
  → CRITICAL with exponential unlock lockout.
* **Crash safety** — temp + fsync + atomic rename everywhere, orphan GC,
  interrupted-update healing; every critical write is a named fault point
  exercised by the crash-test suite.
* **Recovery key** — 256-bit CSPRNG, shown exactly once, survives password
  changes.
* **Encrypted audit log** — hash-chained, tamper-evident.
* **Zero persistent plaintext** — search decrypts in memory; no index.

## Layout

```text
crates/
  vault-crypto      primitives (Argon2id, HKDF, AEAD, STREAM, zeroizing keys)
  vault-container   header/manifest/blob/CURRENT formats
  vault-storage     atomic writes, temp GC, fault injection
  vault-security    lockdown machine, control state (DPAPI)
  vault-recovery    recovery key generation/display
  vault-core        VaultEngine (sessions, unlock, commits, erase)
  vault-cli         command line front-end
  vault-ui          native Slint front-end (WIP)
legacy/electron/    original Electron implementation (reference only)
docs/               threat model, specs, audit
```

## Building

Prerequisites: Rust stable (1.75+), MSVC Build Tools on Windows.

```powershell
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets
```

Binaries: `target/release/vault-cli.exe`, `target/release/vault-ui.exe`.

## CLI quick start

```text
vault-cli init [--recovery]              create a vault (password via TTY/env)
vault-cli status                         vault info, lockdown, KDF params
vault-cli add note --title T --text ...
vault-cli add password --name N --username U --password ... [--url ...]
vault-cli import <file> [--folder ID]    encrypt a file
vault-cli list [--kind note|password|file] [--folder ID]
vault-cli search <query>                 decrypt-and-search (memory only)
vault-cli export <ID> --out <path>
vault-cli note <ID> / password <ID>      reveal content
vault-cli folder create|list|delete
vault-cli stats | verify [--deep] | audit | security
vault-cli password-change                rotate master password
vault-cli recovery enable|disable|recover
vault-cli erase --scope session|recovery|domain|vault [--yes]
vault-cli lock  (via UI)                 passwords never passed as argv
```

Passwords come from the TTY prompt or `VAULT_PASSWORD`
(automation only — a warning is printed).

## Documentation

| Doc | Content |
|---|---|
| [docs/threat-model.md](docs/threat-model.md) | assets, adversary, scope |
| [docs/architecture.md](docs/architecture.md) | layering, commit protocol |
| [docs/crypto-spec.md](docs/crypto-spec.md) | algorithms, AADs, key hierarchy |
| [docs/container-format.md](docs/container-format.md) | binary formats, durability |
| [docs/key-management.md](docs/key-management.md) | key lifecycle, zeroization |
| [docs/recovery.md](docs/recovery.md) | recovery key flows |
| [docs/rollback.md](docs/rollback.md) | anti-rollback witness |
| [docs/secure-memory.md](docs/secure-memory.md) | memory hygiene + limits |
| [docs/security-audit.md](docs/security-audit.md) | internal audit + findings |

## Status

Core engine, CLI, crash suite and docs are complete (130 tests passing).
The Slint UI is under construction. Pre-release: expect the security audit
items listed in `docs/security-audit.md` to be finished before 1.0.

## License

MIT — see [LICENSE](LICENSE).
