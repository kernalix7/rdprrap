//! Small registry helper tailored for `rdprrap-conf`.
//!
//! This mirrors, but does **not** depend on, `rdprrap-installer::registry`.
//! Keeping it local avoids pulling the installer crate (which contains
//! SCM/firewall side effects) into the GUI binary.

use anyhow::{anyhow, Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS,
    REG_VALUE_TYPE,
};

/// Canonical HKLM paths used by the configuration UI.
pub mod keys {
    pub const TERMINAL_SERVER: &str = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server";
    pub const WINSTATIONS_RDP_TCP: &str =
        "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp";
    /// Policy mirror for `Shadow` — the original RDPConf writes both locations.
    pub const POLICIES_TS: &str = "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services";
    pub const POLICIES_SYSTEM: &str =
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    pub const TERMSERVICE_PARAMETERS: &str =
        "SYSTEM\\CurrentControlSet\\Services\\TermService\\Parameters";
}

/// RAII wrapper around an `HKEY`.
pub struct RegKey {
    handle: HKEY,
}

impl RegKey {
    pub fn open_hklm(subkey: &str, access: REG_SAM_FLAGS) -> Result<Self> {
        let wide = to_wide(subkey);
        let mut handle = HKEY::default();
        // SAFETY: `wide` is NUL-terminated UTF-16; `handle` is a writable out-param.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(wide.as_ptr()),
                0,
                access,
                &mut handle,
            )
        };
        win32_ok(status).with_context(|| format!("RegOpenKeyExW HKLM\\{subkey}"))?;
        Ok(Self { handle })
    }

    /// Open-or-create — required to write policy keys that may not exist yet.
    pub fn create_hklm(subkey: &str, access: REG_SAM_FLAGS) -> Result<Self> {
        let wide = to_wide(subkey);
        let mut handle = HKEY::default();
        // SAFETY: Pointers are to locals; RegCreateKeyExW writes only to the
        // out-params. `wide` is NUL-terminated UTF-16.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(wide.as_ptr()),
                0,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                access,
                None,
                &mut handle,
                None,
            )
        };
        win32_ok(status).with_context(|| format!("RegCreateKeyExW HKLM\\{subkey}"))?;
        Ok(Self { handle })
    }

    pub fn get_dword(&self, name: &str) -> Result<Option<u32>> {
        let wname = to_wide(name);
        let mut ty = REG_VALUE_TYPE(0);
        let mut buf = [0u8; 4];
        let mut size: u32 = 4;
        // SAFETY: `buf` is 4 bytes (DWORD layout); `ty`/`size` are writable locals.
        let status = unsafe {
            RegQueryValueExW(
                self.handle,
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
            return Err(anyhow!("unexpected DWORD size {size} for {name}"));
        }
        Ok(Some(u32::from_ne_bytes(buf)))
    }

    pub fn set_dword(&self, name: &str, value: u32) -> Result<()> {
        let wname = to_wide(name);
        let bytes = value.to_ne_bytes();
        // SAFETY: `bytes` is a local [u8; 4]; `wname` is NUL-terminated UTF-16.
        let status = unsafe {
            RegSetValueExW(
                self.handle,
                PCWSTR(wname.as_ptr()),
                0,
                REG_DWORD,
                Some(&bytes),
            )
        };
        win32_ok(status).with_context(|| format!("RegSetValueExW({name}, DWORD)"))
    }

    pub fn get_string(&self, name: &str) -> Result<Option<String>> {
        let wname = to_wide(name);
        let mut ty = REG_VALUE_TYPE(0);
        let mut size: u32 = 0;
        // SAFETY: Probe call — both out-params are writable locals; `None` for
        // the data buffer is explicitly supported.
        let status = unsafe {
            RegQueryValueExW(
                self.handle,
                PCWSTR(wname.as_ptr()),
                None,
                Some(&mut ty),
                None,
                Some(&mut size),
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        win32_ok(status).with_context(|| format!("RegQueryValueExW({name}) probe"))?;
        if size == 0 {
            return Ok(Some(String::new()));
        }
        let u16_len = (size as usize).div_ceil(2);
        let mut buf = vec![0u16; u16_len];
        let mut size2 = size;
        // SAFETY: `buf` has `u16_len * 2 >= size` writable bytes.
        let status = unsafe {
            RegQueryValueExW(
                self.handle,
                PCWSTR(wname.as_ptr()),
                None,
                Some(&mut ty),
                Some(buf.as_mut_ptr() as *mut u8),
                Some(&mut size2),
            )
        };
        win32_ok(status).with_context(|| format!("RegQueryValueExW({name}) data"))?;
        while buf.last().copied() == Some(0) {
            buf.pop();
        }
        Ok(Some(String::from_utf16_lossy(&buf)))
    }
}

impl Drop for RegKey {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: `self.handle` is owned and not used after drop.
            unsafe {
                let _ = RegCloseKey(self.handle);
            }
        }
    }
}

/// Convenience: read a DWORD under HKLM at `(subkey, value)`. Absent key *or*
/// absent value are both reported as `Ok(None)`.
pub fn read_hklm_dword(subkey: &str, value: &str) -> Result<Option<u32>> {
    match RegKey::open_hklm(subkey, KEY_READ) {
        Ok(k) => k.get_dword(value),
        Err(_) => Ok(None),
    }
}

/// Convenience: write a DWORD under HKLM (creates the key if necessary).
pub fn write_hklm_dword(subkey: &str, value: &str, data: u32) -> Result<()> {
    let k = RegKey::create_hklm(subkey, KEY_WRITE)?;
    k.set_dword(value, data)
}

pub(crate) fn to_wide(s: &str) -> Vec<u16> {
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
