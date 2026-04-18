//! Administrator / elevation detection.
//!
//! Modifying `HKLM\SYSTEM\...\WinStations\RDP-Tcp` values (SecurityLayer,
//! UserAuthentication) for the NLA-off loopback test requires the caller to
//! run with a full (elevated) token on UAC-enabled systems.
//!
//! Copied from `rdprrap-installer/src/elevation.rs` to keep this crate
//! self-contained; any changes here should be mirrored there (and vice versa)
//! until the two are factored into a shared util crate.

use anyhow::{Context, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Returns `true` if the current process is running with an elevated token.
pub fn is_elevated() -> Result<bool> {
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that never needs to
    // be closed and is always valid. `OpenProcessToken` writes into the `token`
    // out-parameter. On success we own the returned handle and the RAII
    // `TokenHandle` guard ensures it is closed before returning.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("OpenProcessToken(TOKEN_QUERY) failed")?;

        let guard = TokenHandle(token);

        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len: u32 = 0;
        let size = core::mem::size_of::<TOKEN_ELEVATION>() as u32;

        // SAFETY: `elevation` is a locally-owned struct, `size` matches its
        // layout, and `ret_len` is a valid u32 out-parameter.
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
