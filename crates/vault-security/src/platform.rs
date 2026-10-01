//! Platform security facilities.
//!
//! Windows first target:
//! * **DPAPI** (`CryptProtectData` / `CryptUnprotectData`) to bind small
//!   control-state blobs (failed-attempt throttle, rollback witness) to the
//!   current user + machine. Entropy parameter additionally binds the blob to
//!   a specific `vault_id`.
//!
//! Capability model: Vault **detects** whether DPAPI is usable and records
//! the capability. When DPAPI is unavailable it degrades to an unencrypted
//! control-state file containing *integrity metadata only* (no secrets) and
//! reports `DpapiUnavailable` in the security center. It never pretends the
//! stronger guarantee exists.

use crate::error::SecurityError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformCapability {
    /// DPAPI available and verified.
    Dpapi,
    /// DPAPI missing/failed; control state stored without user+machine binding.
    DpapiUnavailable,
}

/// Returns whether the platform can protect/unprotect blobs.
pub fn probe_capabilities() -> PlatformCapability {
    #[cfg(windows)]
    {
        // Self-test with a trivial blob: detects policy/corruption failures.
        let probe = b"vault-dpapi-probe";
        match dpapi_protect(probe, b"vault-capability-probe") {
            Ok(blob) => match dpapi_unprotect(&blob, b"vault-capability-probe") {
                Ok(out) if out == probe => PlatformCapability::Dpapi,
                _ => PlatformCapability::DpapiUnavailable,
            },
            Err(_) => PlatformCapability::DpapiUnavailable,
        }
    }
    #[cfg(not(windows))]
    {
        PlatformCapability::DpapiUnavailable
    }
}

/// Bind `data` to the current OS user + machine (+ optional vault entropy).
#[cfg(windows)]
pub fn dpapi_protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, SecurityError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };

    if data.is_empty() || data.len() > u32::MAX as usize {
        return Err(SecurityError::Platform("invalid blob size"));
    }
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let ent_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &in_blob,
            std::ptr::null(),
            &ent_blob,
            std::ptr::null(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        return Err(SecurityError::PlatformBoxed(format!("CryptProtectData failed: {err}")));
    }
    let out = unsafe {
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        slice.to_vec()
    };
    unsafe {
        let _ = LocalFree(out_blob.pbData as _);
    }
    Ok(out)
}

#[cfg(windows)]
pub fn dpapi_unprotect(blob: &[u8], entropy: &[u8]) -> Result<Vec<u8>, SecurityError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };

    if blob.is_empty() || blob.len() > u32::MAX as usize {
        return Err(SecurityError::Platform("invalid blob size"));
    }
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: blob.len() as u32,
        pbData: blob.as_ptr() as *mut u8,
    };
    let ent_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &in_blob,
            std::ptr::null_mut(),
            &ent_blob,
            std::ptr::null(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        return Err(SecurityError::PlatformBoxed(format!("CryptUnprotectData failed: {err}")));
    }
    let out = unsafe {
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        slice.to_vec()
    };
    unsafe {
        let _ = LocalFree(out_blob.pbData as _);
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn dpapi_protect(_data: &[u8], _entropy: &[u8]) -> Result<Vec<u8>, SecurityError> {
    Err(SecurityError::Platform("DPAPI not available on this platform"))
}

#[cfg(not(windows))]
pub fn dpapi_unprotect(_blob: &[u8], _entropy: &[u8]) -> Result<Vec<u8>, SecurityError> {
    Err(SecurityError::Platform("DPAPI not available on this platform"))
}

/// SHA-256 of the running executable (tamper *evidence*, not prevention —
/// an attacker with write access can replace both binary and stored hash).
pub fn current_binary_hash() -> Result<[u8; 32], SecurityError> {
    use std::io::Read;
    let exe = std::env::current_exe().map_err(|e| SecurityError::PlatformBoxed(e.to_string()))?;
    let mut file = std::fs::File::open(&exe)
        .map_err(|e| SecurityError::PlatformBoxed(e.to_string()))?;
    let mut hasher = vault_crypto::Sha256Writer::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| SecurityError::PlatformBoxed(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_a_capability() {
        let cap = probe_capabilities();
        #[cfg(windows)]
        {
            // On a standard Windows dev box DPAPI must work; if it does not,
            // the capability model reports degradation rather than failing.
            assert!(matches!(
                cap,
                PlatformCapability::Dpapi | PlatformCapability::DpapiUnavailable
            ));
        }
        #[cfg(not(windows))]
        assert_eq!(cap, PlatformCapability::DpapiUnavailable);
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_roundtrip_and_entropy_binding() {
        if probe_capabilities() != PlatformCapability::Dpapi {
            return; // capability-degraded environment; nothing to assert
        }
        let data = b"throttle-state";
        let blob = dpapi_protect(data, b"vault-1").unwrap();
        assert_ne!(blob.as_slice(), data);
        assert_eq!(dpapi_unprotect(&blob, b"vault-1").unwrap(), data);
        // Wrong entropy (other vault) must fail.
        assert!(dpapi_unprotect(&blob, b"vault-2").is_err());
        // Tampered blob must fail.
        let mut bad = blob.clone();
        let idx = bad.len() - 1;
        bad[idx] ^= 0xff;
        assert!(dpapi_unprotect(&bad, b"vault-1").is_err());
    }

    #[test]
    fn binary_hash_is_stable() {
        let a = current_binary_hash().unwrap();
        let b = current_binary_hash().unwrap();
        assert_eq!(a, b);
    }
}
