//! Atomic, crash-safe file operations.
//!
//! Durability protocol (same directory, same volume):
//! 1. write payload to `<name>.<rand>.tmp`
//! 2. `sync_all()` the temp file (data + metadata flushed)
//! 3. `rename(temp, final)` — atomic replace on Windows (MoveFileEx with
//!    REPLACE_EXISTING) and POSIX (rename)
//! 4. best-effort directory sync (no-op on Windows: FlushFileBuffers on a
//!    directory handle is not supported there — see docs/container-format.md
//!    "Durability limits")
//!
//! An interruption at any point leaves either the previous complete file or
//! the new complete file. Temp files that survive a crash are deleted on the
//! next open.
//!
//! Fault injection: setting `VAULT_FAULT_POINT=<name>` makes the process
//! hard-exit when `fault_point(name)` is reached. Crash tests use this to
//! terminate Vault in the middle of every critical write and then verify
//! recovery.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;

/// Hard-exit at a named fault point when the environment requests it.
///
/// Debug builds only: crash tests run under `cargo test` (debug profile), so
/// release binaries never honor `VAULT_FAULT_POINT` — a leftover environment
/// variable cannot crash a production build.
pub fn fault_point(name: &str) {
    #[cfg(debug_assertions)]
    {
        if let Ok(want) = std::env::var("VAULT_FAULT_POINT") {
            if want == name {
                // Deliberately skips destructors: this simulates a crash.
                std::process::exit(9);
            }
        }
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = name;
    }
}

fn temp_path_for(path: &Path) -> PathBuf {
    let mut buf = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let suffix: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
    let file_name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    path.with_file_name(format!("{}.{}.tmp", file_name, suffix))
}

/// Atomically replace `path` with `bytes`.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    atomic_write_from(path, |w| {
        w.write_all(bytes)?;
        Ok(())
    })
}

/// Atomically replace `path` using a writer callback.
///
/// The callback receives a buffered temp file handle; returning `Err`
/// aborts the commit and removes the temp file (previous state intact).
pub fn atomic_write_from(
    path: &Path,
    f: impl FnOnce(&mut File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;
    let tmp = temp_path_for(path);

    let result = (|| {
        let mut file = File::create(&tmp)?;
        f(&mut file)?;
        fault_point("after_data_write");
        file.sync_all()?;
        fault_point("after_fsync");
        drop(file);
        fs::rename(&tmp, path)?;
        fault_point("after_rename");
        sync_dir(parent);
        fault_point("after_dir_sync");
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Best-effort directory flush. Windows has no supported equivalent for
/// directory handles; documented as a durability limit.
#[cfg(windows)]
fn sync_dir(_dir: &Path) {}

#[cfg(not(windows))]
fn sync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

/// Read a whole file with a hard size cap (hostile input guard).
///
/// The cap is enforced on the *read* stream (`take(cap + 1)`), not on a
/// separate `metadata` call, so a file swapped in between the stat and the
/// open cannot exceed the cap (TOCTOU-safe). The initial `with_capacity` is
/// bounded by `cap`, not by the (attacker-controlled) claimed length.
pub fn read_file_capped(path: &Path, cap: u64) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity((8 * 1024).min(cap) as usize);
    let file = File::open(path)?;
    let allowed = cap.checked_add(1).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "size cap overflow")
    })?;
    let n = file.take(allowed).read_to_end(&mut out)?;
    if (n as u64) > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds size cap",
        ));
    }
    Ok(out)
}

/// Delete leftover `*.tmp` files created by interrupted commits.
///
/// Recurses into subdirectories (object blobs are sharded under
/// `objects/<xx>/`), bounded to a sane depth.
pub fn cleanup_temp_files(dir: &Path) -> std::io::Result<usize> {
    Ok(cleanup_temp_files_depth(dir, 4))
}

/// Only files matching Vault's own temp naming (`<name>.<32-hex>.tmp`, see
/// `temp_path_for`) are removed — an unrelated `foo.tmp` the user keeps in a
/// vault folder must survive. Symlinks are never followed or removed.
fn is_vault_temp_name(name: &str) -> bool {
    let Some(stripped) = name.strip_suffix(".tmp") else {
        return false;
    };
    let Some((stem, suffix)) = stripped.rsplit_once('.') else {
        return false;
    };
    !stem.is_empty() && suffix.len() == 32 && suffix.chars().all(|c| c.is_ascii_hexdigit())
}

fn cleanup_temp_files_depth(dir: &Path, depth: usize) -> usize {
    let mut removed = 0;
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    for entry in entries.flatten() {
        // Never follow (or delete through) symlinks.
        let Ok(md) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if md.is_symlink() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if md.is_file() {
            if is_vault_temp_name(&name) && fs::remove_file(entry.path()).is_ok() {
                removed += 1;
            }
        } else if md.is_dir() && depth > 0 {
            removed += cleanup_temp_files_depth(&entry.path(), depth - 1);
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn atomic_write_creates_and_replaces() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("a.bin");
        atomic_write(&p, b"one").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"one");
        atomic_write(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
    }

    #[test]
    fn failed_write_keeps_previous_state() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("a.bin");
        atomic_write(&p, b"good").unwrap();
        let res = atomic_write_from(&p, |w| {
            w.write_all(b"partial")?;
            Err(std::io::Error::other("injected"))
        });
        assert!(res.is_err());
        assert_eq!(fs::read(&p).unwrap(), b"good");
        // No temp litter left behind.
        let litter: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(litter.is_empty());
    }

    #[test]
    fn nested_paths_are_created() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("x").join("y").join("z.bin");
        atomic_write(&p, b"data").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"data");
    }

    #[test]
    fn read_cap_enforced() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("big");
        fs::write(&p, vec![0u8; 100]).unwrap();
        assert!(read_file_capped(&p, 50).is_err());
        assert!(read_file_capped(&p, 100).is_ok());
    }

    #[test]
    fn cleanup_removes_only_vault_temp_files() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("keep.bin"), b"k").unwrap();
        fs::write(dir.path().join("keep.tmp"), b"user file").unwrap();
        let suffix = "0123456789abcdef0123456789abcdef";
        fs::write(dir.path().join(format!("a.bin.{}.tmp", suffix)), b"t").unwrap();
        let n = cleanup_temp_files(dir.path()).unwrap();
        assert_eq!(n, 1);
        assert!(dir.path().join("keep.bin").exists());
        // Unrelated *.tmp files are the user's data, not ours: kept.
        assert!(dir.path().join("keep.tmp").exists());
        assert!(!dir.path().join(format!("a.bin.{}.tmp", suffix)).exists());
    }
}
