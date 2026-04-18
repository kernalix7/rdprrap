//! RAII guard for temporarily disabling NLA / security-layer on the loopback
//! RDP listener so the in-process test client can connect without credentials.
//!
//! On construction:
//!   1. Open `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
//!      with `KEY_WOW64_64KEY` (so a 32-bit build reaches the same physical
//!      key as a 64-bit build).
//!   2. Snapshot the current `SecurityLayer` and `UserAuthentication` values
//!      (each may be absent — recorded as `None`).
//!   3. Snapshot the `PortNumber` value (default 3389 if absent) for the
//!      caller to route mstsc / MSTSCAX at the right port.
//!   4. Write `SecurityLayer = 0` and `UserAuthentication = 0`.
//!
//! On drop:
//!   For each of the two NLA-related values, restore the original state:
//!     * Some(v) → write back `v`
//!     * None    → delete the value
//!   A failure to restore is logged via `OutputDebugString` and does NOT panic,
//!   because Drop is often called during stack unwind and panicking there
//!   would abort the process.
//!
//! The guard is intentionally the *first* RAII object constructed in `main()`,
//! so it outlives the GUI event loop and the Win32 RDP client — including
//! panic paths where the event loop unwinds.

use anyhow::{anyhow, Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Debug::OutputDebugStringW;
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, KEY_WRITE, REG_DWORD, REG_VALUE_TYPE,
};

/// Registry path under HKLM that stores the TCP RDP listener configuration.
const RDP_TCP_KEY: &str =
    "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp";

const VAL_SECURITY_LAYER: &str = "SecurityLayer";
const VAL_USER_AUTH: &str = "UserAuthentication";
const VAL_PORT_NUMBER: &str = "PortNumber";

/// Default RDP port used when `PortNumber` is absent from the registry.
pub const DEFAULT_RDP_PORT: u16 = 3389;

/// RAII NLA guard. Dropping restores the original `SecurityLayer` and
/// `UserAuthentication` values (or deletes them if they were absent).
pub struct NlaGuard {
    key: HKEY,
    orig_security_layer: Option<u32>,
    orig_user_auth: Option<u32>,
    /// Observed `PortNumber` (default 3389). Exposed via [`Self::port`].
    port: u16,
}

impl NlaGuard {
    /// Snapshot current values and install `SecurityLayer = 0`,
    /// `UserAuthentication = 0` on the RDP-Tcp listener.
    pub fn install() -> Result<Self> {
        let key = open_rdp_tcp_key()?;

        // Snapshot originals before we touch anything — if we fail to write the
        // new values we just close the key without side effects.
        let orig_security_layer =
            read_dword(key, VAL_SECURITY_LAYER).context("reading original SecurityLayer value")?;
        let orig_user_auth =
            read_dword(key, VAL_USER_AUTH).context("reading original UserAuthentication value")?;
        let port = read_dword(key, VAL_PORT_NUMBER)
            .context("reading PortNumber")?
            .and_then(|v| u16::try_from(v).ok())
            .unwrap_or(DEFAULT_RDP_PORT);

        // Apply NLA-off values.
        if let Err(e) = write_dword(key, VAL_SECURITY_LAYER, 0) {
            // Close the key before returning — Drop won't run if we return an
            // Err from this constructor.
            close_key(key);
            return Err(e).context("writing SecurityLayer = 0");
        }
        if let Err(e) = write_dword(key, VAL_USER_AUTH, 0) {
            // Try to roll back SecurityLayer before bailing so we leave the
            // system as close to its original state as possible.
            match orig_security_layer {
                Some(v) => {
                    let _ = write_dword(key, VAL_SECURITY_LAYER, v);
                }
                None => {
                    let _ = delete_value(key, VAL_SECURITY_LAYER);
                }
            }
            close_key(key);
            return Err(e).context("writing UserAuthentication = 0");
        }

        debug_log(&format!(
            "[rdprrap-check] NLA guard installed: orig SecurityLayer={orig_security_layer:?} \
             UserAuthentication={orig_user_auth:?} PortNumber={port}"
        ));

        Ok(Self {
            key,
            orig_security_layer,
            orig_user_auth,
            port,
        })
    }

    /// Observed RDP listener port, or the default 3389 if absent from the
    /// registry.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for NlaGuard {
    fn drop(&mut self) {
        // Restore SecurityLayer first. If that succeeds, proceed with
        // UserAuthentication. If SecurityLayer restore FAILS we intentionally
        // leave `UserAuthentication` at its guard-set value (0) so the
        // listener stays in the coherent pair (SecurityLayer=0,
        // UserAuthentication=0) — i.e. the same relaxed state the guard
        // itself installed. Restoring only one of the two yields the
        // broken combination (SecurityLayer=0, UserAuthentication=orig);
        // on hosts where the original `UserAuthentication` was 1 / absent
        // that can reject every inbound RDP connection until manual fix-up.
        // Each restore failure is logged via `OutputDebugStringW` and never
        // panics — Drop runs during unwind and a panic here would abort
        // with less useful diagnostics than a debug-string log.
        let sec_layer_restored = match self.orig_security_layer {
            Some(v) => match write_dword(self.key, VAL_SECURITY_LAYER, v) {
                Ok(()) => true,
                Err(e) => {
                    debug_log(&format!(
                        "[rdprrap-check] FAILED to restore SecurityLayer={v}: {e:#}"
                    ));
                    false
                }
            },
            None => match delete_value(self.key, VAL_SECURITY_LAYER) {
                Ok(()) => true,
                Err(e) => {
                    debug_log(&format!(
                        "[rdprrap-check] FAILED to delete SecurityLayer: {e:#}"
                    ));
                    false
                }
            },
        };

        if sec_layer_restored {
            match self.orig_user_auth {
                Some(v) => {
                    if let Err(e) = write_dword(self.key, VAL_USER_AUTH, v) {
                        debug_log(&format!(
                            "[rdprrap-check] FAILED to restore UserAuthentication={v}: {e:#}"
                        ));
                    }
                }
                None => {
                    if let Err(e) = delete_value(self.key, VAL_USER_AUTH) {
                        debug_log(&format!(
                            "[rdprrap-check] FAILED to delete UserAuthentication: {e:#}"
                        ));
                    }
                }
            }
        } else {
            debug_log(
                "[rdprrap-check] NlaGuard: SecurityLayer restore failed — \
                 skipping UserAuthentication restore to preserve coherence \
                 (listener left in the guard-set (SecurityLayer=0, \
                 UserAuthentication=0) pair)",
            );
        }
        close_key(self.key);
        debug_log("[rdprrap-check] NLA guard restored and dropped");
    }
}

fn open_rdp_tcp_key() -> Result<HKEY> {
    let wide = to_wide(RDP_TCP_KEY);
    let mut handle = HKEY::default();
    // SAFETY: `wide` is NUL-terminated UTF-16. `handle` is a writable out-param.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wide.as_ptr()),
            0,
            KEY_READ | KEY_WRITE | KEY_WOW64_64KEY,
            &mut handle,
        )
    };
    win32_ok(status).with_context(|| format!("RegOpenKeyExW HKLM\\{RDP_TCP_KEY}"))?;
    Ok(handle)
}

fn read_dword(key: HKEY, name: &str) -> Result<Option<u32>> {
    let wname = to_wide(name);
    let mut ty = REG_VALUE_TYPE(0);
    let mut buf = [0u8; 4];
    let mut size: u32 = buf.len() as u32;
    // SAFETY: `buf` is a local [u8; 4], matching DWORD size. All out-params
    // are writable. `wname` is NUL-terminated UTF-16.
    let status = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(wname.as_ptr()),
            None,
            Some(&mut ty),
            Some(buf.as_mut_ptr()),
            Some(&mut size),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    win32_ok(status).with_context(|| format!("RegQueryValueExW({name})"))?;
    if size != 4 {
        return Err(anyhow!(
            "unexpected value size {size} for DWORD {name}; expected 4"
        ));
    }
    Ok(Some(u32::from_ne_bytes(buf)))
}

fn write_dword(key: HKEY, name: &str, value: u32) -> Result<()> {
    let wname = to_wide(name);
    let bytes = value.to_ne_bytes();
    // SAFETY: `bytes` is a local [u8; 4]; `wname` is NUL-terminated UTF-16.
    let status = unsafe { RegSetValueExW(key, PCWSTR(wname.as_ptr()), 0, REG_DWORD, Some(&bytes)) };
    win32_ok(status).with_context(|| format!("RegSetValueExW({name}, DWORD={value})"))
}

fn delete_value(key: HKEY, name: &str) -> Result<()> {
    let wname = to_wide(name);
    // SAFETY: `wname` is NUL-terminated UTF-16.
    let status = unsafe { RegDeleteValueW(key, PCWSTR(wname.as_ptr())) };
    if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(anyhow!(
            "RegDeleteValueW({name}) failed: 0x{:08x}",
            status.0
        ))
    }
}

fn close_key(key: HKEY) {
    if !key.is_invalid() {
        // SAFETY: `key` was obtained from a successful RegOpenKeyExW above
        // and is not used after this call.
        unsafe {
            let _ = RegCloseKey(key);
        }
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

fn win32_ok(status: WIN32_ERROR) -> Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(anyhow!("Win32 error 0x{:08x}", status.0))
    }
}

fn debug_log(msg: &str) {
    let wide = to_wide(msg);
    // SAFETY: `wide` is NUL-terminated UTF-16; OutputDebugStringW only reads it.
    unsafe {
        OutputDebugStringW(PCWSTR(wide.as_ptr()));
    }
}
