//! Detect whether the current process has an elevated token.
//!
//! Reads under `HKLM\SYSTEM\...` generally succeed without elevation, but any
//! write into TermService / Terminal Server / Policies subkeys requires it.
//! `rdprrap-conf` runs in "read-only" mode when not elevated (Apply disabled).

use anyhow::{Context, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub fn is_elevated() -> Result<bool> {
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that is always
    // valid and never needs to be closed. `OpenProcessToken` writes into
    // `token` on success; we wrap it in a drop-guard so it is always closed.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("OpenProcessToken(TOKEN_QUERY) failed")?;
        let guard = TokenHandle(token);

        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len: u32 = 0;
        let size = core::mem::size_of::<TOKEN_ELEVATION>() as u32;

        // SAFETY: `elevation` is a locally-owned struct matching `size`; both
        // `ret_len` and `elevation` are valid writable locals.
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

struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` was obtained from a successful OpenProcessToken
            // call and is not used after this close.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}
