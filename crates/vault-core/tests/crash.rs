//! Crash-recovery tests via fault injection (`VAULT_FAULT_POINT`).
//!
//! The helper test below runs in a child process (same test binary) with
//! `VAULT_FAULT_POINT` set; the process hard-exits (code 9) when it reaches
//! the named point. The runner then reopens the vault and asserts the
//! documented recovery invariant for that interruption.

use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

use vault_core::{CreateOptions, VaultEngine};
use vault_crypto::kdf::{MIN_ITERATIONS, MIN_MEMORY_KIB};
use vault_crypto::{KdfParams, SecretBytes, KDF_ARGON2ID};

fn pw(s: &str) -> SecretBytes {
    SecretBytes::from_str(s)
}

const MASTER: &str = "crash-test-password";

fn fast_kdf() -> KdfParams {
    KdfParams {
        algorithm: KDF_ARGON2ID,
        memory_kib: MIN_MEMORY_KIB,
        iterations: MIN_ITERATIONS,
        parallelism: 1,
        salt: [7u8; 32],
    }
}

fn opts() -> CreateOptions {
    CreateOptions { kdf: Some(fast_kdf()), with_recovery: false }
}

/// Child-process entry point. Does nothing unless invoked by the runner.
///
/// The fault is armed only *after* the vault has been created and seeded, so
/// the named point is hit inside the operation under test — not during setup.
#[test]
fn fault_helper() {
    let Ok(want) = std::env::var("VAULT_FAULT_WANT") else {
        return;
    };
    let mode = std::env::var("VAULT_FAULT_MODE").unwrap_or_default();
    let dir = std::env::var("VAULT_FAULT_DIR").expect("VAULT_FAULT_DIR");
    let path = Path::new(&dir);

    let (mut e, seed) = match mode.as_str() {
        "create" => {
            // Crash inside initialization itself.
            std::env::set_var("VAULT_FAULT_POINT", &want);
            let created = VaultEngine::create(path, &pw(MASTER), opts()).unwrap();
            panic!("create finished without crashing: {:?}", created.1.is_some());
        }
        "add_note" => (VaultEngine::create(path, &pw(MASTER), opts()).unwrap().0, None),
        "update_note" | "delete_note" => {
            let (mut e, _) = VaultEngine::create(path, &pw(MASTER), opts()).unwrap();
            let id = e.add_note("first", "content-v1", None).unwrap();
            (e, Some(id))
        }
        "erase_vault" => {
            let (e, _) = VaultEngine::create(path, &pw(MASTER), opts()).unwrap();
            (e, None)
        }
        "domain_erase" => {
            let (mut e, _) = VaultEngine::create(path, &pw(MASTER), opts()).unwrap();
            e.add_note("first", "content-v1", None).unwrap();
            e.add_note("second", "content-b", None).unwrap();
            (e, None)
        }
        other => panic!("unknown VAULT_FAULT_MODE {other:?}"),
    };

    // Setup complete: arm the fault and perform the operation under test.
    std::env::set_var("VAULT_FAULT_POINT", &want);
    match mode.as_str() {
        "add_note" => {
            e.add_note("first", "content-v1", None).unwrap();
        }
        "update_note" => {
            let id = seed.expect("seed note");
            e.update_note(&id, "first", "content-v2").unwrap();
        }
        "delete_note" => {
            let id = seed.expect("seed note");
            e.delete_object(&id).unwrap();
        }
        "erase_vault" => {
            e.crypto_erase(vault_core::EraseScope::Vault, Some(&pw(MASTER)))
                .unwrap();
        }
        "domain_erase" => {
            e.crypto_erase(vault_core::EraseScope::Domain, Some(&pw(MASTER)))
                .unwrap();
        }
        other => panic!("unknown VAULT_FAULT_MODE {other:?}"),
    }
    // Reaching here means the requested fault point was never hit.
    panic!(
        "fault point {:?} was not reached",
        std::env::var("VAULT_FAULT_WANT")
    );
}

fn run_crash(point: &str, mode: &str, dir: &TempDir) {
    let exe = std::env::current_exe().expect("test binary path");
    let out = Command::new(exe)
        .args(["--exact", "fault_helper", "--nocapture"])
        .env("VAULT_FAULT_WANT", point)
        .env("VAULT_FAULT_DIR", dir.path())
        .env("VAULT_FAULT_MODE", mode)
        .env("VAULT_FAULT_HELPER", "1")
        .output()
        .expect("spawn fault helper");
    assert_eq!(
        out.status.code(),
        Some(9),
        "fault point {point:?} in mode {mode:?} not hit\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn reopen_and_unlock(dir: &TempDir) -> VaultEngine {
    let mut engine = VaultEngine::open(dir.path()).expect("vault must reopen after crash");
    engine
        .unlock(&pw(MASTER))
        .expect("vault must unlock after crash");
    engine
}

fn assert_no_temp_litter(dir: &TempDir) {
    for sub in ["", "manifest", "state", "audit"] {
        let d = if sub.is_empty() {
            dir.path().to_path_buf()
        } else {
            dir.path().join(sub)
        };
        if let Ok(entries) = std::fs::read_dir(d) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                assert!(
                    !name.ends_with(".tmp"),
                    "temp litter left after crash: {name}"
                );
            }
        }
    }
}

fn note_content(engine: &mut VaultEngine) -> Option<String> {
    let items = engine.list(None).ok()?;
    let id = items.first()?.id;
    Some(engine.get_note(&id).ok()?.content)
}

// ---------------------------------------------------------------- create

#[test]
fn crash_during_header_write_leaves_recoverable_error() {
    let dir = TempDir::new().unwrap();
    run_crash("after_header_write", "create", &dir);

    // Header exists but no manifest/CURRENT: init must refuse, not clobber.
    assert!(VaultEngine::create(dir.path(), &pw(MASTER), opts()).is_err());
    // And no unlock may silently succeed on the half-written container.
    if let Ok(mut engine) = VaultEngine::open(dir.path()) {
        assert!(engine.unlock(&pw(MASTER)).is_err());
    }
}

#[test]
fn crash_after_initial_commit_recovers() {
    let dir = TempDir::new().unwrap();
    run_crash("after_initial_commit", "create", &dir);

    // Container was fully committed; only the control-state write was lost.
    let mut engine = reopen_and_unlock(&dir);
    assert_eq!(engine.status().generation, 1);
    assert!(engine.verify_integrity(true).unwrap().ok);
    assert_no_temp_litter(&dir);
}

// ------------------------------------------------------- atomic write points

#[test]
fn crash_mid_blob_write_recovers_to_previous_state() {
    for point in ["after_data_write", "after_fsync", "after_rename", "after_dir_sync"] {
        let dir = TempDir::new().unwrap();
        run_crash(point, "add_note", &dir);

        let mut engine = reopen_and_unlock(&dir);
        // The blob write was interrupted before any commit: no note exists.
        assert!(engine.list(None).unwrap().is_empty(), "{point}");
        assert!(engine.verify_integrity(true).unwrap().ok, "{point}");
        assert_no_temp_litter(&dir);
    }
}

// ------------------------------------------------------------ commit points

#[test]
fn crash_after_manifest_write_discards_uncommitted_generation() {
    let dir = TempDir::new().unwrap();
    run_crash("after_manifest_write", "add_note", &dir);

    let mut engine = reopen_and_unlock(&dir);
    // Manifest file exists but CURRENT was never updated: the orphan
    // generation is garbage-collected and the note never materializes.
    assert!(engine.list(None).unwrap().is_empty());
    assert!(engine.verify_integrity(true).unwrap().ok);
    assert_no_temp_litter(&dir);
    let manifest_dir = dir.path().join("manifest");
    let count = std::fs::read_dir(manifest_dir).unwrap().count();
    assert_eq!(count, 1, "orphan manifest must be collected");
}

#[test]
fn crash_after_current_write_keeps_committed_generation() {
    let dir = TempDir::new().unwrap();
    run_crash("after_current_write", "add_note", &dir);

    let mut engine = reopen_and_unlock(&dir);
    // CURRENT was updated: the commit is durable; only the control witness
    // write was lost, and it is repaired at unlock.
    assert_eq!(engine.list(None).unwrap().len(), 1);
    assert_eq!(engine.status().generation, 2);
    assert!(engine.verify_integrity(true).unwrap().ok);
    assert_no_temp_litter(&dir);
}

// ------------------------------------------------------------------ healing

#[test]
fn crash_after_blob_write_heals_from_newer_blob() {
    let dir = TempDir::new().unwrap();
    run_crash("after_blob_write", "update_note", &dir);

    let mut engine = reopen_and_unlock(&dir);
    // The new blob exists but the manifest still references the old version:
    // pending-commit healing must re-commit it.
    assert_eq!(note_content(&mut engine).as_deref(), Some("content-v2"));
    assert!(engine.verify_integrity(true).unwrap().ok);
}

#[test]
fn crash_after_manifest_write_during_update_heals() {
    let dir = TempDir::new().unwrap();
    run_crash("after_manifest_write", "update_note", &dir);

    let mut engine = reopen_and_unlock(&dir);
    assert_eq!(note_content(&mut engine).as_deref(), Some("content-v2"));
    assert!(engine.verify_integrity(true).unwrap().ok);
}

#[test]
fn crash_after_current_write_during_update_is_durable() {
    let dir = TempDir::new().unwrap();
    run_crash("after_current_write", "update_note", &dir);

    let mut engine = reopen_and_unlock(&dir);
    assert_eq!(note_content(&mut engine).as_deref(), Some("content-v2"));
    assert!(engine.verify_integrity(true).unwrap().ok);
}

// ------------------------------------------------------------------ delete

#[test]
fn crash_between_delete_commit_and_blob_removal_gcs_orphan() {
    let dir = TempDir::new().unwrap();
    run_crash("after_commit_before_blob_delete", "delete_note", &dir);

    let mut engine = reopen_and_unlock(&dir);
    // The deletion is committed; the leftover blob is collected as an orphan.
    assert!(engine.list(None).unwrap().is_empty());
    assert!(engine.verify_integrity(true).unwrap().ok);
    assert_no_temp_litter(&dir);
}

// ------------------------------------------------------------------- erase

#[test]
fn crash_after_key_destruction_leaves_unusable_vault() {
    let dir = TempDir::new().unwrap();
    run_crash("after_key_destruction", "erase_vault", &dir);

    // Header was overwritten with random bytes: the vault must refuse to
    // open (no silent recovery, no data exposure).
    assert!(VaultEngine::open(dir.path()).is_err());
}

// ----------------------------------------------------------- domain rekey

/// Every interruption inside the two-phase domain rekey must be resumable:
/// unlocking with the master password completes the transition, the data
/// survives, and the header ends up finalized (no pending state).
#[test]
fn crash_during_domain_rekey_resumes_on_unlock() {
    for point in [
        "after_rekey_arm",
        "after_rekey_blobs",
        "after_rekey_audit",
        "after_rekey_manifest",
        "after_rekey_finalize",
    ] {
        let dir = TempDir::new().unwrap();
        run_crash(point, "domain_erase", &dir);

        let mut engine = reopen_and_unlock(&dir);
        // Resume drove the transition to completion.
        assert!(!engine.header().rekey_pending(), "{point}");
        // Data survived the key rotation (both notes, original content).
        let items = engine.list(None).unwrap();
        assert_eq!(items.len(), 2, "{point}");
        let contents: Vec<String> = items
            .iter()
            .map(|it| engine.get_note(&it.id).unwrap().content)
            .collect();
        assert!(contents.contains(&"content-v1".to_string()), "{point}");
        assert!(contents.contains(&"content-b".to_string()), "{point}");
        // The generation advanced past the pre-rekey commit.
        assert!(engine.status().generation >= 2, "{point}");
        assert!(engine.verify_integrity(true).unwrap().ok, "{point}");
        assert_no_temp_litter(&dir);

        // And the vault relocks/reopens cleanly under the new root key.
        engine.lock(vault_core::LockReason::Manual);
        engine.unlock(&pw(MASTER)).expect("relock after resume");
        assert!(!engine.header().rekey_pending(), "{point}");
    }
}

/// While a rekey is pending, the recovery path must refuse (only the
/// password can drive the transition) — but the vault with the *old*
/// recovery key still resumes via password unlock.
#[test]
fn pending_domain_rekey_blocks_recovery_unlock() {
    let dir = TempDir::new().unwrap();
    run_crash("after_rekey_arm", "domain_erase", &dir);

    // Recovery unlock is refused while pending (before any password unlock).
    let mut engine = VaultEngine::open(dir.path()).unwrap();
    assert!(engine.header().rekey_pending());
    let res = engine.unlock_with_recovery("AAAA-BBBB-CCCC", &pw(MASTER));
    assert!(res.is_err(), "recovery unlock must refuse during pending rekey");

    // Password unlock resumes and completes.
    engine.unlock(&pw(MASTER)).expect("resume via password");
    assert!(!engine.header().rekey_pending());
    assert!(engine.verify_integrity(true).unwrap().ok);
}
