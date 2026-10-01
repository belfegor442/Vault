//! End-to-end engine tests: sessions, CRUD, integrity, rollback, recovery.

use std::path::PathBuf;

use tempfile::TempDir;

use vault_core::{CoreError, CreateOptions, EraseScope, ItemKind, VaultEngine};
use vault_crypto::kdf::{MIN_ITERATIONS, MIN_MEMORY_KIB};
use vault_crypto::{KdfParams, SecretBytes, KDF_ARGON2ID};

fn pw(s: &str) -> SecretBytes {
    SecretBytes::from_str(s)
}

fn fast_kdf() -> KdfParams {
    KdfParams {
        algorithm: KDF_ARGON2ID,
        memory_kib: MIN_MEMORY_KIB,
        iterations: MIN_ITERATIONS,
        parallelism: 1,
        salt: [9u8; 32],
    }
}

fn opts(with_recovery: bool) -> CreateOptions {
    CreateOptions { kdf: Some(fast_kdf()), with_recovery }
}

fn create_vault(dir: &TempDir, with_recovery: bool) -> (VaultEngine, Option<String>) {
    VaultEngine::create(dir.path(), &pw("test-master-password"), opts(with_recovery))
        .expect("create vault")
}

#[test]
fn create_lock_unlock_roundtrip() {
    let dir = TempDir::new().unwrap();
    let (mut engine, _) = create_vault(&dir, false);

    let st = engine.status();
    assert!(st.initialized && st.unlocked);
    assert_eq!(st.generation, 1);
    assert!(st.kdf_memory_kib >= MIN_MEMORY_KIB);
    assert!(!st.has_recovery);

    engine.lock(vault_core::LockReason::Manual);
    assert!(!engine.status().unlocked);
    assert!(matches!(engine.list(None), Err(CoreError::Locked)));

    engine.unlock(&pw("test-master-password")).unwrap();
    assert!(engine.status().unlocked);

    engine.lock(vault_core::LockReason::Manual);
    assert!(matches!(
        engine.unlock(&pw("wrong-password")),
        Err(CoreError::AuthFailed)
    ));
}

#[test]
fn repeated_failures_cause_lockout() {
    let dir = TempDir::new().unwrap();
    let (mut engine, _) = create_vault(&dir, false);
    engine.lock(vault_core::LockReason::Manual);

    let mut saw_lockout = false;
    for _ in 0..7 {
        match engine.unlock(&pw("wrong")) {
            Err(CoreError::LockedOut { retry_in_secs }) => {
                assert!(retry_in_secs > 0);
                saw_lockout = true;
                break;
            }
            Err(CoreError::AuthFailed) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }
    assert!(saw_lockout, "lockout never triggered");
    // Lockout applies to the correct password as well.
    assert!(matches!(
        engine.unlock(&pw("test-master-password")),
        Err(CoreError::LockedOut { .. })
    ));
}

#[test]
fn notes_crud_search_and_delete() {
    let dir = TempDir::new().unwrap();
    let (mut engine, _) = create_vault(&dir, false);

    let id = engine
        .add_note("Shopping", "milk, eggs, SECRET-ITEM", None)
        .unwrap();
    let note = engine.get_note(&id).unwrap();
    assert_eq!(note.title, "Shopping");
    assert_eq!(note.content, "milk, eggs, SECRET-ITEM");

    engine
        .update_note(&id, "Shopping list", "milk, eggs, flour")
        .unwrap();
    let note = engine.get_note(&id).unwrap();
    assert_eq!(note.title, "Shopping list");
    assert_eq!(note.content, "milk, eggs, flour");

    let listed = engine.list(None).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].kind, ItemKind::Note);
    assert!(listed[0].preview.as_deref().unwrap().contains("milk"));

    assert!(engine.search("shopping").unwrap().len() == 1);
    assert!(engine.search("EGGS").unwrap().len() == 1);
    assert!(engine.search("no-such-thing").unwrap().is_empty());

    engine.set_favorite(&id, true).unwrap();
    assert_eq!(engine.stats().unwrap().favorites, 1);

    engine.delete_object(&id).unwrap();
    assert!(engine.list(None).unwrap().is_empty());
    assert!(engine.get_note(&id).is_err());
    assert_eq!(engine.stats().unwrap().notes, 0);

    engine.lock(vault_core::LockReason::Manual);
    engine.unlock(&pw("test-master-password")).unwrap();
    assert!(engine.list(None).unwrap().is_empty());
    let report = engine.verify_integrity(true).unwrap();
    assert!(report.ok, "integrity failed: {:?}", report.failed);
}

#[test]
fn folders_hierarchy_and_promotion() {
    let dir = TempDir::new().unwrap();
    let (mut engine, _) = create_vault(&dir, false);

    let docs = engine.create_folder("Documents", None).unwrap();
    let sub = engine.create_folder("Work", Some(docs)).unwrap();
    assert_ne!(docs, sub);

    let _note = engine.add_note("Inside", "body", Some(docs)).unwrap();
    let folders = engine.list_folders().unwrap();
    assert_eq!(folders.len(), 2);
    let root_folder = folders.iter().find(|f| f.id == docs).unwrap();
    assert_eq!(root_folder.item_count, 1);

    // Deleting the parent promotes the child to the root level.
    engine.delete_folder(&docs).unwrap();
    let folders = engine.list_folders().unwrap();
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0].id, sub);
    assert!(folders[0].parent.is_none());

    // The note was promoted to the root as well.
    assert_eq!(engine.list(None).unwrap().len(), 1);

    assert!(matches!(
        engine.delete_folder(&[0xEE; 16]),
        Err(CoreError::NotFound)
    ));
    assert!(matches!(
        engine.create_folder("", None),
        Err(CoreError::Invalid(_))
    ));
}

#[test]
fn passwords_crud_and_update() {
    let dir = TempDir::new().unwrap();
    let (mut engine, _) = create_vault(&dir, false);

    let id = engine
        .add_password(
            "GitHub",
            "belfegor",
            "hunter2",
            "https://github.com",
            "2fa enabled",
            "dev",
            false,
        )
        .unwrap();

    let rec = engine.get_password(&id).unwrap();
    assert_eq!(rec.name, "GitHub");
    assert_eq!(rec.username, "belfegor");
    assert_eq!(rec.password, "hunter2");
    assert_eq!(rec.category, "dev");
    assert!(!rec.favorite);

    engine
        .update_password(
            &id,
            "GitHub",
            "belfegor",
            "hunter3",
            "https://github.com",
            "rotated",
            "dev",
            true,
        )
        .unwrap();
    let rec = engine.get_password(&id).unwrap();
    assert_eq!(rec.password, "hunter3");
    assert!(rec.favorite);

    // Searchable metadata lives in the manifest; the secret lives in the blob.
    assert_eq!(engine.search("belfegor").unwrap().len(), 1);

    let report = engine.verify_integrity(true).unwrap();
    assert!(report.ok, "{:?}", report.failed);
}

#[test]
fn file_import_export_multi_chunk_roundtrip() {
    let dir = TempDir::new().unwrap();
    let (mut engine, _) = create_vault(&dir, false);

    // 2.5 MiB -> 3 STREAM chunks (chunk size 1 MiB).
    let src: PathBuf = dir.path().join("src.bin");
    let payload: Vec<u8> = (0..(2 * 1024 * 1024 + 512 * 1024))
        .map(|i| (i % 251) as u8)
        .collect();
    std::fs::write(&src, &payload).unwrap();

    let id = engine.import_file(&src, None, None).unwrap();
    let listed = engine.list(None).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].kind, ItemKind::File);
    assert_eq!(listed[0].size, payload.len() as u64);

    let dst = dir.path().join("out.bin");
    engine.export_file(&id, &dst).unwrap();
    assert_eq!(std::fs::read(&dst).unwrap(), payload);

    // Binary payloads are not readable as text.
    assert!(matches!(engine.read_text(&id), Err(CoreError::Invalid(_))));

    let report = engine.verify_integrity(true).unwrap();
    assert!(report.ok, "{:?}", report.failed);
}

#[test]
fn integrity_detects_corrupted_blob_and_manifest() {
    let dir = TempDir::new().unwrap();
    let (mut engine, _) = create_vault(&dir, false);
    let id = engine.add_note("Secret", "classified", None).unwrap();

    // Corrupt the ciphertext of the object blob.
    let blob = dir.path().join("objects").join(&{
        let hex: String = id.iter().map(|b| format!("{:02x}", b)).collect();
        hex[..2].to_string()
    }).join({
        let hex: String = id.iter().map(|b| format!("{:02x}", b)).collect();
        hex
    });
    let mut bytes = std::fs::read(&blob).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&blob, &bytes).unwrap();

    let report = engine.verify_integrity(true).unwrap();
    assert!(!report.ok);
    assert!(!report.failed.is_empty());
    // Reading the corrupted note must fail cleanly.
    assert!(engine.get_note(&id).is_err());

    drop(engine);

    // Corrupt the CURRENT pointer: unlock must refuse.
    let current = dir.path().join("CURRENT");
    let mut cur = std::fs::read(&current).unwrap();
    cur[20] ^= 0x01;
    std::fs::write(&current, &cur).unwrap();
    let mut engine = VaultEngine::open(dir.path()).unwrap();
    assert!(matches!(
        engine.unlock(&pw("test-master-password")),
        Err(CoreError::Integrity(_))
    ));
}

#[test]
fn rollback_of_container_is_detected() {
    let dir = TempDir::new().unwrap();
    let (mut engine, _) = create_vault(&dir, false);

    // Snapshot the generation-1 commit.
    let saved_current = std::fs::read(dir.path().join("CURRENT")).unwrap();
    engine.add_note("n", "body", None).unwrap(); // generation 2
    assert_eq!(engine.status().generation, 2);
    drop(engine);

    // Attacker restores the older CURRENT pointer (classic rollback).
    std::fs::write(dir.path().join("CURRENT"), &saved_current).unwrap();

    let mut engine = VaultEngine::open(dir.path()).unwrap();
    assert!(matches!(
        engine.unlock(&pw("test-master-password")),
        Err(CoreError::RollbackDetected)
    ));
    // Lockdown recorded the attempt.
    assert!(!engine.lockdown_events().is_empty());
}

#[test]
fn change_password_requires_current_and_rewraps() {
    let dir = TempDir::new().unwrap();
    let (mut engine, _) = create_vault(&dir, false);
    engine.add_note("n", "body", None).unwrap();

    engine
        .change_password(&pw("test-master-password"), &pw("brand-new-password"))
        .unwrap();
    drop(engine);

    let mut engine = VaultEngine::open(dir.path()).unwrap();
    engine.unlock(&pw("brand-new-password")).unwrap();
    assert_eq!(engine.list(None).unwrap().len(), 1);

    engine.lock(vault_core::LockReason::Manual);
    assert!(matches!(
        engine.unlock(&pw("test-master-password")),
        Err(CoreError::AuthFailed)
    ));
}

#[test]
fn recovery_unlock_restores_access_and_requires_new_password() {
    let dir = TempDir::new().unwrap();
    let (mut engine, recovery) = create_vault(&dir, true);
    let display = recovery.expect("recovery key issued at create");
    engine.add_note("n", "recoverable body", None).unwrap();
    engine.lock(vault_core::LockReason::Manual);
    drop(engine);

    // Forgot the password: recover with the recovery key + choose a new one.
    let mut engine = VaultEngine::open(dir.path()).unwrap();
    assert!(engine.status().has_recovery);
    engine
        .unlock_with_recovery(&display, &pw("recovered-password"))
        .unwrap();
    assert_eq!(engine.list(None).unwrap().len(), 1);
    drop(engine);

    let mut engine = VaultEngine::open(dir.path()).unwrap();
    engine.unlock(&pw("recovered-password")).unwrap();
    // Recovery must not leave the old password working.
    engine.lock(vault_core::LockReason::Manual);
    assert!(matches!(
        engine.unlock(&pw("test-master-password")),
        Err(CoreError::AuthFailed)
    ));
}

#[test]
fn enable_and_disable_recovery_at_runtime() {
    let dir = TempDir::new().unwrap();
    let (mut engine, _) = create_vault(&dir, false);
    assert!(!engine.status().has_recovery);

    let display = engine.enable_recovery().unwrap();
    assert!(engine.status().has_recovery);
    drop(engine);

    let mut engine = VaultEngine::open(dir.path()).unwrap();
    engine.unlock(&pw("test-master-password")).unwrap();
    engine.disable_recovery().unwrap();
    assert!(!engine.status().has_recovery);
    drop(engine);

    let mut engine = VaultEngine::open(dir.path()).unwrap();
    assert!(matches!(
        engine.unlock_with_recovery(&display, &pw("another-password")),
        Err(CoreError::Recovery(_))
    ));
}

#[test]
fn crypto_erase_scopes() {
    let dir = TempDir::new().unwrap();
    let (mut engine, _) = create_vault(&dir, true);
    assert!(engine.status().has_recovery);

    // Session scope == lock.
    engine.crypto_erase(EraseScope::Session, None).unwrap();
    assert!(!engine.status().unlocked);

    // Recovery scope destroys the recovery envelope.
    engine
        .unlock(&pw("test-master-password"))
        .unwrap();
    engine.crypto_erase(EraseScope::Recovery, None).unwrap();
    assert!(!engine.status().has_recovery);

    // Irreversible scopes require password confirmation.
    assert!(matches!(
        engine.crypto_erase(EraseScope::Vault, None),
        Err(CoreError::EraseConfirmationRequired)
    ));
    assert!(matches!(
        engine.crypto_erase(EraseScope::Vault, Some(&pw("wrong"))),
        Err(CoreError::Container(_) | CoreError::Crypto(_))
    ));

    engine.crypto_erase(EraseScope::Vault, Some(&pw("test-master-password"))).unwrap();
    assert!(
        !dir.path().join("VAULTHDR").exists(),
        "vault directory should be gone after erase"
    );
}

#[test]
fn domain_rekey_rotates_root_and_keeps_data() {
    let dir = TempDir::new().unwrap();
    let (mut engine, recovery) = create_vault(&dir, true);
    let recovery = recovery.expect("recovery display");
    let note = engine.add_note("keep", "secret body", None).unwrap();
    engine.add_note("second", "more", None).unwrap();
    let gen_before = engine.status().generation;

    engine
        .crypto_erase(EraseScope::Domain, Some(&pw("test-master-password")))
        .unwrap();

    // The session continues under the new root key.
    assert!(!engine.header().rekey_pending());
    assert!(
        !engine.header().has_recovery(),
        "recovery envelope wraps the old root key and must be crypto-erased"
    );
    assert_eq!(engine.get_note(&note).unwrap().content, "secret body");
    assert!(engine.status().generation > gen_before, "manifest re-committed");
    assert!(engine.verify_integrity(true).unwrap().ok);

    // Reopen with the SAME password (fresh KDF salt) after the rotation.
    drop(engine);
    let mut engine = VaultEngine::open(dir.path()).unwrap();
    assert!(!engine.status().has_recovery);
    engine.unlock(&pw("test-master-password")).unwrap();
    assert_eq!(engine.get_note(&note).unwrap().content, "secret body");
    assert_eq!(engine.list(None).unwrap().len(), 2);
    assert!(engine.verify_integrity(true).unwrap().ok);

    // The old recovery key is dead: no recovery envelope exists at all.
    assert!(engine
        .unlock_with_recovery(&recovery, &pw("brand-new-password"))
        .is_err());

    // Wrong password still fails after the rotation.
    engine.lock(vault_core::LockReason::Manual);
    assert!(matches!(
        engine.unlock(&pw("wrong-password")),
        Err(CoreError::AuthFailed)
    ));

    // Audit recorded the domain rotation.
    engine.unlock(&pw("test-master-password")).unwrap();
    let events = engine.audit_events(100).unwrap();
    assert!(
        events.iter().any(|e| e.event == "crypto_erase.domain"),
        "domain rekey must be audited"
    );
}

#[test]
fn domain_rekey_requires_unlocked_vault_and_password_proof() {
    let dir = TempDir::new().unwrap();
    let (mut engine, _) = create_vault(&dir, false);
    let note = engine.add_note("n", "b", None).unwrap();

    // Locked vault: no manifest to migrate.
    engine.lock(vault_core::LockReason::Manual);
    assert!(matches!(
        engine.crypto_erase(EraseScope::Domain, Some(&pw("test-master-password"))),
        Err(CoreError::Locked)
    ));

    // Wrong password must not be able to rotate keys.
    engine.unlock(&pw("test-master-password")).unwrap();
    assert!(matches!(
        engine.crypto_erase(EraseScope::Domain, Some(&pw("wrong-password"))),
        Err(CoreError::AuthFailed)
    ));

    // Deliberate confirmation is mandatory.
    assert!(matches!(
        engine.crypto_erase(EraseScope::Domain, None),
        Err(CoreError::EraseConfirmationRequired)
    ));

    // Failed attempts left everything intact and un-pended.
    assert!(!engine.header().rekey_pending());
    assert_eq!(engine.get_note(&note).unwrap().content, "b");
    assert!(engine.verify_integrity(true).unwrap().ok);
}

#[test]
fn audit_log_records_security_events() {
    let dir = TempDir::new().unwrap();
    let (mut engine, _) = create_vault(&dir, false);
    engine.lock(vault_core::LockReason::Manual);
    engine.unlock(&pw("test-master-password")).unwrap();
    engine.add_note("n", "body", None).unwrap();

    let events = engine.audit_events(100).unwrap();
    let names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
    assert!(names.contains(&"vault.create"), "{names:?}");
    assert!(names.contains(&"vault.unlock"), "{names:?}");
    assert!(names.contains(&"vault.lock"), "{names:?}");
    assert!(
        events
            .iter()
            .any(|e| e.event == "container.commit" && e.detail == "note.create"),
        "{names:?}"
    );

    // The audit chain must survive a reopen.
    drop(engine);
    let mut engine = VaultEngine::open(dir.path()).unwrap();
    engine.unlock(&pw("test-master-password")).unwrap();
    assert!(engine.audit_events(100).unwrap().len() >= events.len());
}

#[test]
fn status_reports_platform_capability_and_versions() {
    let dir = TempDir::new().unwrap();
    let (engine, _) = create_vault(&dir, false);
    let st = engine.status();
    assert_eq!(st.format_version, vault_container::FORMAT_VERSION);
    assert_eq!(st.vault_id.len(), 32);
    assert_eq!(st.binary_hash.len(), 64);
    assert!(st.binary_verified, "hash of running test binary must match");
    assert!(st.platform_capability.to_lowercase().contains("dpapi"));
    assert_eq!(st.lockdown_state, "NORMAL");
}
