//! End-to-end tests for the `vault-cli` binary.

use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_vault-cli");
const PW: &str = "cli-test-master-password";

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn run(dir: &Path, args: &[&str]) -> Out {
    let out = Command::new(BIN)
        .args(args)
        .arg("--dir")
        .arg(dir)
        .env("VAULT_PASSWORD", PW)
        .output()
        .expect("run vault-cli");
    Out {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn run_env(dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Out {
    let mut cmd = Command::new(BIN);
    cmd.args(args).arg("--dir").arg(dir).env("VAULT_PASSWORD", PW);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run vault-cli");
    Out {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn init_vault(dir: &TempDir) -> Out {
    run(dir.path(), &["init"])
}

fn extract_id(stdout: &str, marker: &str) -> String {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(marker))
        .unwrap_or_else(|| panic!("no {marker:?} in stdout: {stdout}"))
        .trim()
        .to_string()
}

fn extract_recovery_key(stdout: &str) -> String {
    stdout
        .lines()
        .find(|l| {
            l.contains('-')
                && !l.contains(' ')
                && l.len() >= 20
                && l.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '=' || c == '+' || c == '/' || c == '-')
        })
        .unwrap_or_else(|| panic!("no recovery key line in stdout: {stdout}"))
        .to_string()
}

#[test]
fn init_status_and_double_init_rejected() {
    let dir = TempDir::new().unwrap();
    let out = init_vault(&dir);
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("vault created"), "{}", out.stdout);
    assert!(out.stdout.contains("vault id:"));

    let out = run(dir.path(), &["status"]);
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("initialized:"), "{}", out.stdout);
    assert!(out.stdout.contains("true"));
    assert!(out.stdout.contains("lockdown:"), "{}", out.stdout);
    assert!(out.stdout.contains("NORMAL"));

    // Second init must refuse.
    let out = init_vault(&dir);
    assert!(!out.ok);
    assert!(out.stderr.contains("already exists"), "{}", out.stderr);
}

#[test]
fn notes_folders_search_favorite_delete() {
    let dir = TempDir::new().unwrap();
    assert!(init_vault(&dir).ok);

    let out = run(dir.path(), &["folder", "create", "Work"]);
    assert!(out.ok, "{}", out.stderr);
    let folder = extract_id(&out.stdout, "folder:");

    let out = run(
        dir.path(),
        &["add", "note", "--title", "Meeting", "--text", "discuss ROADMAP", "--folder", &folder],
    );
    assert!(out.ok, "{}", out.stderr);
    let note = extract_id(&out.stdout, "note added:");

    let out = run(dir.path(), &["list", "--kind", "note"]);
    assert!(out.ok);
    assert!(out.stdout.contains(&note));
    assert!(out.stdout.contains("Meeting"));

    // Folder listing shows the note count.
    let out = run(dir.path(), &["folder", "list"]);
    assert!(out.stdout.contains("items=1"), "{}", out.stdout);

    let out = run(dir.path(), &["note", &note]);
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("discuss ROADMAP"));

    let out = run(dir.path(), &["search", "roadmap"]);
    assert!(out.ok);
    assert!(out.stdout.contains(&note), "{}", out.stdout);

    let out = run(dir.path(), &["favorite", &note]);
    assert!(out.ok);

    let out = run(dir.path(), &["stats"]);
    assert!(out.ok);
    assert!(out.stdout.contains("notes:     1"));
    assert!(out.stdout.contains("favorites: 1"));

    let out = run(dir.path(), &["delete", &note]);
    assert!(out.ok, "{}", out.stderr);
    let out = run(dir.path(), &["list"]);
    assert!(out.stdout.contains("(no items)"), "{}", out.stdout);

    // Deleting the folder (promotes children) works.
    let out = run(dir.path(), &["folder", "delete", &folder]);
    assert!(out.ok, "{}", out.stderr);
}

#[test]
fn password_entry_roundtrip() {
    let dir = TempDir::new().unwrap();
    assert!(init_vault(&dir).ok);

    let out = run(
        dir.path(),
        &[
            "add", "password",
            "--name", "GitHub",
            "--username", "belfegor",
            "--password", "s3cret-pass",
            "--url", "https://github.com",
            "--category", "dev",
            "--favorite",
        ],
    );
    assert!(out.ok, "{}", out.stderr);
    let id = extract_id(&out.stdout, "password entry added:");

    let out = run(dir.path(), &["password", &id]);
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("password: s3cret-pass"));
    assert!(out.stdout.contains("username: belfegor"));
    assert!(out.stdout.contains("favorite: true"));

    let out = run(dir.path(), &["list", "--kind", "password"]);
    assert!(out.stdout.contains(&id));
    // The secret must not appear in list output.
    assert!(!out.stdout.contains("s3cret-pass"), "{}", out.stdout);
}

#[test]
fn import_export_and_deep_verify() {
    let dir = TempDir::new().unwrap();
    assert!(init_vault(&dir).ok);

    let src = dir.path().join("payload.bin");
    let payload: Vec<u8> = (0..1_500_000).map(|i| (i % 250) as u8).collect();
    std::fs::write(&src, &payload).unwrap();

    let out = run(
        dir.path(),
        &["import", src.to_str().unwrap(), "--name", "payload.bin"],
    );
    assert!(out.ok, "{}", out.stderr);
    let id = extract_id(&out.stdout, "imported:");

    // Export must target a path OUTSIDE the vault directory (self-export
    // into the container is deliberately refused).
    let out_dir = TempDir::new().unwrap();
    let dst = out_dir.path().join("restored.bin");
    let out = run(
        dir.path(),
        &["export", &id, "--out", dst.to_str().unwrap()],
    );
    assert!(out.ok, "{}", out.stderr);
    assert_eq!(std::fs::read(&dst).unwrap(), payload);

    // …and the container itself must refuse an in-vault destination.
    let bad_dst = dir.path().join("inside.bin");
    let out = run(
        dir.path(),
        &["export", &id, "--out", bad_dst.to_str().unwrap()],
    );
    assert!(!out.ok, "export into the vault dir must fail");
    assert!(!bad_dst.exists());

    let out = run(dir.path(), &["verify", "--deep"]);
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("result:  OK"));
    assert!(out.stdout.contains("objects: 1"));
}

#[test]
fn audit_security_and_status_reports() {
    let dir = TempDir::new().unwrap();
    assert!(init_vault(&dir).ok);
    assert!(run(dir.path(), &["add", "note", "--title", "t", "--text", "x"]).ok);

    let out = run(dir.path(), &["audit"]);
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("vault.create"));
    assert!(out.stdout.contains("container.commit"));

    let out = run(dir.path(), &["security"]);
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("lockdown:"), "{}", out.stdout);
    assert!(out.stdout.contains("NORMAL"));
    assert!(out.stdout.contains("binary check:"), "{}", out.stdout);
    assert!(out.stdout.contains("verified"));

    let out = run(dir.path(), &["status"]);
    assert!(out.ok);
    assert!(out.stdout.contains("generation:"), "{}", out.stdout);
    assert!(out.stdout.contains("not configured"));
}

#[test]
fn wrong_password_is_rejected() {
    let dir = TempDir::new().unwrap();
    assert!(init_vault(&dir).ok);

    let out = Command::new(BIN)
        .args(["list", "--dir"])
        .arg(dir.path())
        .env("VAULT_PASSWORD", "definitely-wrong")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("authentication failed"), "{stderr}");
}

#[test]
fn password_change_rotates_credentials() {
    let dir = TempDir::new().unwrap();
    assert!(init_vault(&dir).ok);
    assert!(run(dir.path(), &["add", "note", "--title", "t", "--text", "keep-me"]).ok);

    let out = run_env(
        dir.path(),
        &["password-change"],
        &[("VAULT_NEW_PASSWORD", "brand-new-cli-password")],
    );
    assert!(out.ok, "{}", out.stderr);

    // Old password no longer works.
    let out = Command::new(BIN)
        .args(["list", "--dir"])
        .arg(dir.path())
        .env("VAULT_PASSWORD", PW)
        .output()
        .unwrap();
    assert!(!out.status.success());

    // New password works and data survived.
    let out = run_env(
        dir.path(),
        &["list"],
        &[("VAULT_PASSWORD", "brand-new-cli-password")],
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("note"));
}

#[test]
fn recovery_enable_and_recover_flow() {
    let dir = TempDir::new().unwrap();
    assert!(init_vault(&dir).ok);
    assert!(run(dir.path(), &["add", "note", "--title", "t", "--text", "survivor"]).ok);

    let out = run(dir.path(), &["recovery", "enable"]);
    assert!(out.ok, "{}", out.stderr);
    let key = extract_recovery_key(&out.stdout);
    assert!(run(dir.path(), &["status"]).stdout.contains("configured"));

    // Recover with a brand-new password.
    let out = run_env(
        dir.path(),
        &["recover"],
        &[
            ("VAULT_RECOVERY_KEY", &key),
            ("VAULT_NEW_PASSWORD", "after-recovery-password"),
        ],
    );
    assert!(out.ok, "{}", out.stderr);

    // Data intact; old password dead; new one works.
    let out = run_env(
        dir.path(),
        &["list"],
        &[("VAULT_PASSWORD", "after-recovery-password")],
    );
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("t"));

    let out = Command::new(BIN)
        .args(["list", "--dir"])
        .arg(dir.path())
        .env("VAULT_PASSWORD", PW)
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn erase_vault_requires_yes_then_destroys() {
    let dir = TempDir::new().unwrap();
    assert!(init_vault(&dir).ok);

    let out = run(dir.path(), &["erase", "--scope", "vault"]);
    assert!(!out.ok);
    assert!(out.stderr.contains("--yes"), "{}", out.stderr);
    assert!(dir.path().join("VAULTHDR").exists());

    let out = run(dir.path(), &["erase", "--scope", "vault", "--yes"]);
    assert!(out.ok, "{}", out.stderr);
    assert!(!dir.path().join("VAULTHDR").exists());
}

#[test]
fn erase_domain_rotates_keys_but_keeps_data() {
    let dir = TempDir::new().unwrap();
    assert!(init_vault(&dir).ok);
    let out = run(
        dir.path(),
        &["add", "note", "--title", "t", "--text", "survive-domain"],
    );
    assert!(out.ok, "{}", out.stderr);
    let id = extract_id(&out.stdout, "note added:");

    // Irreversible: requires --yes.
    let out = run(dir.path(), &["erase", "--scope", "domain"]);
    assert!(!out.ok);
    assert!(out.stderr.contains("--yes"), "{}", out.stderr);

    let out = run(dir.path(), &["erase", "--scope", "domain", "--yes"]);
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("root key rotated"), "{}", out.stdout);

    // Same password opens the rotated vault; data intact.
    let out = run(dir.path(), &["note", &id]);
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("survive-domain"));

    let out = run(dir.path(), &["verify", "--deep"]);
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("result:  OK"));
}

#[test]
fn help_lists_commands() {
    let dir = TempDir::new().unwrap();
    let out = run(dir.path(), &["--help"]);
    assert!(out.ok);
    for needle in [
        "init", "status", "add note", "add password", "import", "verify",
        "recovery", "erase", "--dir",
    ] {
        assert!(out.stdout.contains(needle), "missing {needle:?}");
    }
}
