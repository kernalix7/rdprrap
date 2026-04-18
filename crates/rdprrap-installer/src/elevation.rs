//! Administrator / elevation detection.
//!
//! Registry writes under `HKLM\SYSTEM\...`, SCM changes (`ChangeServiceConfig`),
//! and firewall rule management (`INetFwPolicy2`) all require the caller to be
//! a member of the Administrators group AND, on UAC-enabled systems, to be
//! running with a full (elevated) token.

use anyhow::{Context, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Returns `true` if the current process is running with an elevated token.
///
/// Uses `OpenProcessToken` + `GetTokenInformation(TokenElevation)`. Any failure
/// is bubbled up as an `anyhow::Error` rather than silently returning `false`
/// so the caller can distinguish "not elevated" from "could not determine".
pub fn is_elevated() -> Result<bool> {
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that never needs to
    // be closed and is always valid. `OpenProcessToken` writes into the `token`
    // out-parameter which we initialise to a default-valued `HANDLE`. On
    // success we own the returned handle and close it before returning.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("OpenProcessToken(TOKEN_QUERY) failed")?;

        // Wrap the handle so it is always closed, even on panic / early return.
        let guard = TokenHandle(token);

        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len: u32 = 0;
        let size = core::mem::size_of::<TOKEN_ELEVATION>() as u32;

        // SAFETY: `elevation` is a locally-owned struct, `size` matches its layout,
        // and `ret_len` is a valid u32 out-parameter.
        GetTokenInformation(
            guard.0,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            size,
            &mut ret_len,
        )
        .context("GetTokenInformation(TokenElevation) failed")?;

        Ok(elevation.TokenIsElevated != 0)
    }
}

/// RAII guard that closes a Windows `HANDLE` on drop.
struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` was obtained from a successful `OpenProcessToken`
            // and is not used after this call. `CloseHandle` tolerates being
            // called exactly once per valid handle.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}
