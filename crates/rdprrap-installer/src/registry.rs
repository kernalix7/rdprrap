//! Safe helpers around the Windows registry for the install/uninstall flow.
//!
//! The helpers wrap `windows-rs` Win32 functions and normalise error handling
//! into `anyhow::Result`. All unsafe is confined to the thin FFI wrappers at
//! the bottom of this module.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    LocalFree, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, HLOCAL, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyValueW, RegDeleteTreeW, RegGetValueW, RegOpenKeyExW,
    RegQueryValueExW, RegSetKeySecurity, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    KEY_WOW64_64KEY, KEY_WRITE, REG_CREATE_KEY_DISPOSITION, REG_DWORD, REG_EXPAND_SZ,
    REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE, RRF_RT_ANY,
};

/// Canonical registry locations we touch during install/uninstall.
pub mod keys {
    pub const TERMSERVICE_PARAMETERS: &str =
        "SYSTEM\\CurrentControlSet\\Services\\TermService\\Parameters";
    pub const TERMINAL_SERVER: &str = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server";
    pub const WINSTATIONS_RDP_TCP: &str =
        "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp";
    pub const LICENSING_CORE: &str =
        "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Licensing Core";
    /// Parent key for the three virtual-channel AddIn subkeys. If this key
    /// already exists before install we leave the entire AddIns configuration
    /// alone — matching upstream `RDPWInst.dpr`'s `if not Reg.KeyExists('AddIns')`
    /// guard.
    pub const ADDINS_PARENT: &str = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\AddIns";
    pub const ADDINS_CLIP: &str =
        "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\AddIns\\Clip Redirector";
    pub const ADDINS_DND: &str =
        "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\AddIns\\DND Redirector";
    pub const ADDINS_DVC: &str =
        "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\AddIns\\Dynamic VC";

    /// Private rdprrap-installer subkey used to persist uninstall metadata
    /// (original `ServiceDll` value, install path, version).
    pub const INSTALLER_STATE: &str = "SOFTWARE\\rdprrap\\Installer";
}

/// Value name of the TermService `ServiceDll` REG_EXPAND_SZ entry.
pub const VALUE_SERVICE_DLL: &str = "ServiceDll";

/// Restrictive DACL applied to the installer-state key:
///   - NT AUTHORITY\SYSTEM : Full
///   - BUILTIN\Administrators : Full
///   - (everyone else: no access)
///
/// `P` = SDDL_PROTECTED (block inheritance from HKLM\SOFTWARE's default ACL so
/// a low-priv administrator / authenticated user cannot modify the key and
/// forge the `OriginalServiceDll` value we later use to restore TermService.)
///
/// Access mask `KA` = KEY_ALL_ACCESS.
const INSTALLER_STATE_SDDL: &str = "D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)";

/// RAII wrapper around a registry `HKEY` that closes on drop.
pub struct RegKey {
    handle: HKEY,
}

impl RegKey {
    /// Open an existing key under `HKEY_LOCAL_MACHINE` with the given access rights.
    pub fn open_local_machine(subkey: &str, access: REG_SAM_FLAGS) -> Result<Self> {
        let wide = to_wide(subkey);
        let mut handle = HKEY::default();
        // SAFETY: `wide` is NUL-terminated UTF-16, `handle` is a writable out-param.
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

    /// Create (or open if it already exists) a subkey under `HKEY_LOCAL_MACHINE`.
    pub fn create_local_machine(subkey: &str, access: REG_SAM_FLAGS) -> Result<Self> {
        Self::create_local_machine_inner(subkey, access).map(|(k, _)| k)
    }

    /// Create (or open) a subkey and also report the disposition.
    /// Used when we need to apply a DACL only on first creation.
    fn create_local_machine_inner(
        subkey: &str,
        access: REG_SAM_FLAGS,
    ) -> Result<(Self, REG_CREATE_KEY_DISPOSITION)> {
        let wide = to_wide(subkey);
        let mut handle = HKEY::default();
        let mut disposition = REG_CREATE_KEY_DISPOSITION::default();
        // SAFETY: Pointers are to locals; `RegCreateKeyExW` writes to both
        // `handle` and `disposition` only. `wide` is NUL-terminated UTF-16.
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
                Some(&mut disposition),
            )
        };
        win32_ok(status).with_context(|| format!("RegCreateKeyExW HKLM\\{subkey}"))?;
        Ok((Self { handle }, disposition))
    }

    /// Apply a self-relative security descriptor (parsed from `sddl`) to the key.
    pub fn set_sddl(&self, sddl: &str) -> Result<()> {
        let wsddl = to_wide(sddl);
        let mut psd = PSECURITY_DESCRIPTOR(core::ptr::null_mut());
        // SAFETY: `wsddl` is NUL-terminated UTF-16. `psd` receives a heap
        // pointer owned by the caller (must be freed with `LocalFree`). We
        // pass `None` for the returned size as we don't inspect it.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wsddl.as_ptr()),
                SDDL_REVISION_1,
                &mut psd,
                None,
            )
        }
        .context("ConvertStringSecurityDescriptorToSecurityDescriptorW")?;

        // Guard to guarantee LocalFree even on error paths.
        let _guard = LocalPtr(psd.0);

        let info = OBJECT_SECURITY_INFORMATION(
            DACL_SECURITY_INFORMATION.0 | PROTECTED_DACL_SECURITY_INFORMATION.0,
        );
        // SAFETY: `self.handle` is a valid HKEY opened with WRITE_DAC rights
        // (KEY_WRITE | WRITE_DAC). `psd` was populated by the Convert*
        // function above and remains live until `_guard` drops at end of scope.
        let status = unsafe { RegSetKeySecurity(self.handle, info, psd) };
        win32_ok(status).context("RegSetKeySecurity")
    }

    /// Write a `REG_DWORD` value.
    pub fn set_dword(&self, name: &str, value: u32) -> Result<()> {
        let wname = to_wide(name);
        let bytes = value.to_ne_bytes();
        // SAFETY: `bytes` is a locally-owned `[u8; 4]`; `wname` is NUL-terminated UTF-16.
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

    /// Read a `REG_DWORD` value. Returns `Ok(None)` if absent.
    pub fn get_dword(&self, name: &str) -> Result<Option<u32>> {
        let wname = to_wide(name);
        let mut ty = REG_VALUE_TYPE(0);
        let mut buf = [0u8; 4];
        let mut size: u32 = buf.len() as u32;
        // SAFETY: `buf` is exactly 4 bytes, matching DWORD layout. `ty`/`size`
        // are writable out-params.
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
        win32_ok(status).with_context(|| format!("RegQueryValueExW({name}, DWORD)"))?;
        if size != 4 {
            return Err(anyhow!(
                "unexpected value size {size} for DWORD-probed {name}"
            ));
        }
        Ok(Some(u32::from_ne_bytes(buf)))
    }

    /// Write a `REG_SZ` or `REG_EXPAND_SZ` string value.
    pub fn set_string(&self, name: &str, value: &str, expand: bool) -> Result<()> {
        let wname = to_wide(name);
        let wvalue = to_wide(value);
        // SAFETY: `wvalue` is a locally-owned `Vec<u16>` that outlives the call
        // (moved into `wvalue` above; dropped at end of function scope — after
        // `RegSetValueExW` returns). We form a read-only byte slice over its
        // full u16-sized span (includes trailing NUL required by REG_SZ).
        let byte_slice: &[u8] = unsafe {
            core::slice::from_raw_parts(
                wvalue.as_ptr() as *const u8,
                wvalue.len() * core::mem::size_of::<u16>(),
            )
        };
        let ty = if expand { REG_EXPAND_SZ } else { REG_SZ };
        // SAFETY: `byte_slice` is a valid read-only view of `wvalue` for the exact
        // byte length derived above; `wvalue` lives until the end of this function
        // which is after `RegSetValueExW` returns.
        let status =
            unsafe { RegSetValueExW(self.handle, PCWSTR(wname.as_ptr()), 0, ty, Some(byte_slice)) };
        win32_ok(status).with_context(|| format!("RegSetValueExW({name}, {ty:?})"))
    }

    /// Read a string (REG_SZ or REG_EXPAND_SZ) value. Returns `Ok(None)` if absent.
    pub fn get_string(&self, name: &str) -> Result<Option<String>> {
        let wname = to_wide(name);
        let mut ty = REG_VALUE_TYPE(0);
        let mut size: u32 = 0;
        // First call with a null buffer pointer to discover the size.
        // SAFETY: Both `ty` and `size` are writeable out-params; we pass `None`
        // for the data buffer which `RegQueryValueExW` explicitly supports.
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
        win32_ok(status).with_context(|| format!("RegQueryValueExW({name}) [size probe]"))?;

        if size == 0 {
            return Ok(Some(String::new()));
        }
        // Round up to whole u16 units.
        let u16_len = (size as usize).div_ceil(2);
        let mut buf = vec![0u16; u16_len];
        let mut size2 = size;
        // SAFETY: `buf.as_mut_ptr() as *mut u8` points to `buf.len() * 2` bytes of
        // writable storage; we pass `size2` equal to that byte length.
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
        win32_ok(status).with_context(|| format!("RegQueryValueExW({name}) [data]"))?;

        // Drop trailing NULs.
        while buf.last().copied() == Some(0) {
            buf.pop();
        }
        Ok(Some(String::from_utf16_lossy(&buf)))
    }

    /// Delete a single named value (tolerates "not found").
    pub fn delete_value(&self, name: &str) -> Result<()> {
        let wname = to_wide(name);
        // SAFETY: `wname` is NUL-terminated UTF-16.
        let status =
            unsafe { RegDeleteKeyValueW(self.handle, PCWSTR::null(), PCWSTR(wname.as_ptr())) };
        if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            Err(anyhow!(
                "RegDeleteKeyValueW({name}) failed: 0x{:08x}",
                status.0
            ))
        }
    }
}

impl Drop for RegKey {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: `self.handle` is an owned HKEY returned by RegOpen/Create
            // and is not used after this call.
            unsafe {
                let _ = RegCloseKey(self.handle);
            }
        }
    }
}

/// RAII guard that `LocalFree`s a pointer returned by Win32.
struct LocalPtr(*mut core::ffi::c_void);
impl Drop for LocalPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was returned by
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW`, which
            // documents that the caller must free it with `LocalFree`. In
            // windows-rs 0.58 `LocalFree` is `LocalFree<P0: Param<HLOCAL>>`
            // and accepts an `HLOCAL` directly; we already null-checked.
            unsafe {
                let _ = LocalFree(HLOCAL(self.0));
            }
        }
    }
}

/// Check whether a subkey exists under `HKEY_LOCAL_MACHINE`. Returns
/// `Ok(false)` only for `ERROR_FILE_NOT_FOUND`; any other error propagates so
/// callers can distinguish "key missing" from "access denied".
pub fn key_exists_local_machine(subkey: &str) -> Result<bool> {
    let wide = to_wide(subkey);
    let mut handle = HKEY::default();
    // SAFETY: `wide` is NUL-terminated UTF-16, `handle` is a writable out-param.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wide.as_ptr()),
            0,
            KEY_READ,
            &mut handle,
        )
    };
    if status == ERROR_SUCCESS {
        // SAFETY: `handle` is owned by us for the duration of this block.
        unsafe {
            let _ = RegCloseKey(handle);
        }
        Ok(true)
    } else if status == ERROR_FILE_NOT_FOUND {
        Ok(false)
    } else {
        Err(anyhow!(
            "RegOpenKeyExW HKLM\\{subkey} failed: 0x{:08x}",
            status.0
        ))
    }
}

/// Delete a registry subkey tree under HKLM (tolerates "not found").
pub fn delete_tree_local_machine(subkey: &str) -> Result<()> {
    let parent = match RegKey::open_local_machine("", KEY_WRITE) {
        Ok(k) => k,
        Err(_) => {
            // Fall back to a direct RegDeleteTreeW on the full path below.
            return delete_tree_from_root(subkey);
        }
    };
    let wsub = to_wide(subkey);
    // SAFETY: `wsub` NUL-terminated; parent handle is valid.
    let status = unsafe { RegDeleteTreeW(parent.handle, PCWSTR(wsub.as_ptr())) };
    if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(anyhow!(
            "RegDeleteTreeW({subkey}) failed: 0x{:08x}",
            status.0
        ))
    }
}

fn delete_tree_from_root(subkey: &str) -> Result<()> {
    let wsub = to_wide(subkey);
    // SAFETY: Use HKEY_LOCAL_MACHINE directly; wsub is NUL-terminated UTF-16.
    let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(wsub.as_ptr())) };
    if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(anyhow!(
            "RegDeleteTreeW({subkey}) failed: 0x{:08x}",
            status.0
        ))
    }
}

/// Write the ServiceDll value as REG_EXPAND_SZ, pointing at `dll_path`.
pub fn set_service_dll(dll_path: &Path) -> Result<()> {
    let key = RegKey::open_local_machine(keys::TERMSERVICE_PARAMETERS, KEY_WRITE)?;
    let as_str = dll_path
        .to_str()
        .ok_or_else(|| anyhow!("install path is not valid UTF-8: {}", dll_path.display()))?;
    key.set_string(VALUE_SERVICE_DLL, as_str, /*expand=*/ true)
}

/// Read the current ServiceDll value (REG_EXPAND_SZ or REG_SZ).
pub fn get_service_dll() -> Result<Option<String>> {
    // Use RegGetValueW directly so we transparently expand REG_EXPAND_SZ if needed.
    let wpath = to_wide(keys::TERMSERVICE_PARAMETERS);
    let wname = to_wide(VALUE_SERVICE_DLL);
    let mut size: u32 = 0;
    // SAFETY: First call with null data pointer to probe required size. RRF_RT_ANY
    // accepts any string type.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wpath.as_ptr()),
            PCWSTR(wname.as_ptr()),
            RRF_RT_ANY,
            None,
            None,
            Some(&mut size),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    win32_ok(status).context("RegGetValueW(ServiceDll) size probe")?;
    if size == 0 {
        return Ok(Some(String::new()));
    }
    let u16_len = (size as usize).div_ceil(2);
    let mut buf = vec![0u16; u16_len];
    let mut size2 = size;
    // SAFETY: `buf` has `u16_len * 2 >= size` bytes of writable storage.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wpath.as_ptr()),
            PCWSTR(wname.as_ptr()),
            RRF_RT_ANY,
            None,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            Some(&mut size2),
        )
    };
    win32_ok(status).context("RegGetValueW(ServiceDll) data")?;
    while buf.last().copied() == Some(0) {
        buf.pop();
    }
    Ok(Some(String::from_utf16_lossy(&buf)))
}

/// Persist uninstall-time metadata so we can restore the exact original values.
///
/// The installer-state key is created with a restrictive DACL (SYSTEM + Admins
/// only) on the first install so that a subsequent low-privilege user cannot
/// forge `OriginalServiceDll` and trick uninstall into loading an arbitrary
/// DLL as TermService (H1).
///
/// `prev_fdeny` is the `fDenyTSConnections` value observed *before* install
/// (`None` if the value was absent).
///
/// `prev_allow_multi` is the `AllowMultipleTSSessions` value observed *before*
/// install under `HKLM\...\Winlogon` (`None` if the value was absent). Captured
/// so uninstall can restore the Winlogon knob verbatim (C1).
///
/// `addins_created_by_us` records whether the `AddIns` parent key was absent
/// pre-install and was therefore created by this installer. When true,
/// uninstall is allowed to remove the three `AddIns` subkeys and the parent
/// key; when false the pre-existing AddIns configuration is left alone (H5).
pub fn save_uninstall_state(
    original_service_dll: &str,
    install_dir: &Path,
    prev_fdeny: Option<u32>,
    prev_allow_multi: Option<u32>,
    addins_created_by_us: bool,
) -> Result<()> {
    // Use KEY_WOW64_64KEY so that a 32-bit build writes to the same physical
    // key as a 64-bit build reads on uninstall (M5). `WRITE_DAC` (0x40000) is
    // required to call `RegSetKeySecurity` below.
    const WRITE_DAC: u32 = 0x0004_0000;
    let (key, _disposition) = RegKey::create_local_machine_inner(
        keys::INSTALLER_STATE,
        KEY_WRITE | KEY_READ | KEY_WOW64_64KEY | REG_SAM_FLAGS(WRITE_DAC),
    )?;

    // Always tighten the DACL. On first install this restricts a brand-new
    // key; on reinstall it heals any tampering performed while the previous
    // key was (briefly) open to wider modification.
    key.set_sddl(INSTALLER_STATE_SDDL)
        .context("tightening installer-state DACL")?;

    key.set_string(
        "OriginalServiceDll",
        original_service_dll,
        /*expand=*/ true,
    )?;
    let dir_str = install_dir
        .to_str()
        .ok_or_else(|| anyhow!("install dir is not valid UTF-8"))?;
    key.set_string("InstallDir", dir_str, /*expand=*/ false)?;
    key.set_string("Version", env!("CARGO_PKG_VERSION"), /*expand=*/ false)?;
    if let Some(v) = prev_fdeny {
        key.set_dword("PrevDenyTS", v)?;
        key.set_dword("PrevDenyTSPresent", 1)?;
    } else {
        key.set_dword("PrevDenyTSPresent", 0)?;
    }
    if let Some(v) = prev_allow_multi {
        key.set_dword("PrevAllowMultipleTSSessions", v)?;
        key.set_dword("PrevAllowMultipleTSSessionsPresent", 1)?;
    } else {
        key.set_dword("PrevAllowMultipleTSSessionsPresent", 0)?;
    }
    key.set_dword("AddInsCreatedByUs", u32::from(addins_created_by_us))?;
    Ok(())
}

/// Load uninstall-time metadata written by `save_uninstall_state`.
pub fn load_uninstall_state() -> Result<Option<UninstallState>> {
    let key = match RegKey::open_local_machine(keys::INSTALLER_STATE, KEY_READ | KEY_WOW64_64KEY) {
        Ok(k) => k,
        Err(_) => return Ok(None),
    };
    let original = key.get_string("OriginalServiceDll")?;
    let dir = key.get_string("InstallDir")?;
    let prev_present = key.get_dword("PrevDenyTSPresent")?.unwrap_or(0) != 0;
    let prev_fdeny = if prev_present {
        key.get_dword("PrevDenyTS")?
    } else {
        None
    };
    let prev_allow_multi_present = key
        .get_dword("PrevAllowMultipleTSSessionsPresent")?
        .unwrap_or(0)
        != 0;
    let prev_allow_multi = if prev_allow_multi_present {
        key.get_dword("PrevAllowMultipleTSSessions")?
    } else {
        None
    };
    // Legacy installs (pre-H5 regression fix) did not record this flag; treat
    // missing as `false` so we do NOT wipe the existing AddIns subtree on
    // upgrade from those builds.
    let addins_created_by_us = key.get_dword("AddInsCreatedByUs")?.unwrap_or(0) != 0;
    match (original, dir) {
        (Some(o), Some(d)) => Ok(Some(UninstallState {
            original_service_dll: o,
            install_dir: d,
            prev_fdeny,
            prev_fdeny_present: prev_present,
            prev_allow_multi,
            prev_allow_multi_present,
            addins_created_by_us,
        })),
        _ => Ok(None),
    }
}

/// Remove the installer metadata subtree.
pub fn clear_uninstall_state() -> Result<()> {
    delete_tree_local_machine(keys::INSTALLER_STATE)
}

/// Canonical path of the Winlogon key that owns `AllowMultipleTSSessions`.
///
/// Kept colocated with the restore helper below so every writer of this value
/// agrees on the same subkey.
const WINLOGON_KEY: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

/// Value name of the Winlogon multi-session knob restored by
/// [`restore_allow_multi_ts_sessions`].
const ALLOW_MULTI_VALUE: &str = "AllowMultipleTSSessions";

/// Restore the Winlogon `AllowMultipleTSSessions` DWORD to its pre-install
/// state (C1).
///
/// * `Some(v)` — the value was present before install; write `v` back.
/// * `None` — the value was absent before install; delete the value we
///   set to `1` during install so Windows falls back to its documented
///   default.
///
/// Best-effort: if the Winlogon key cannot be opened for write (unusual on a
/// healthy Windows install) the restore is a no-op — there is nothing useful
/// uninstall can do beyond logging, and the caller already logs.
pub fn restore_allow_multi_ts_sessions(value: Option<u32>) -> Result<()> {
    let key = match RegKey::open_local_machine(WINLOGON_KEY, KEY_WRITE) {
        Ok(k) => k,
        Err(_) => return Ok(()),
    };
    match value {
        Some(v) => key.set_dword(ALLOW_MULTI_VALUE, v),
        None => key.delete_value(ALLOW_MULTI_VALUE),
    }
}

pub struct UninstallState {
    pub original_service_dll: String,
    pub install_dir: String,
    /// Value of `fDenyTSConnections` observed before install (`None` if absent).
    pub prev_fdeny: Option<u32>,
    /// Whether a "present" flag was explicitly recorded. On legacy installs
    /// (pre-H4) this will be `false` and callers should fall back to "delete".
    pub prev_fdeny_present: bool,
    /// Value of `AllowMultipleTSSessions` under `HKLM\...\Winlogon` observed
    /// before install (`None` if the value was absent). C1.
    pub prev_allow_multi: Option<u32>,
    /// Whether the Winlogon `AllowMultipleTSSessions` presence flag was
    /// explicitly recorded. Legacy installs (pre-C1) report `false`.
    pub prev_allow_multi_present: bool,
    /// `true` iff the `AddIns` parent key was absent at install time and we
    /// created it (along with the three child subkeys). Only then is uninstall
    /// allowed to remove those subkeys — otherwise the system's pre-existing
    /// AddIns configuration must be preserved (H5).
    pub addins_created_by_us: bool,
}

/// Validate that a recorded `OriginalServiceDll` value is safe to write back.
///
/// Rules (H1):
///   * Must be absolute (after environment-variable expansion).
///   * Must sit under `%SystemRoot%\System32\` OR under the install directory
///     we previously recorded (if provided) — nothing else is a legitimate
///     pre-install value for TermService.
///   * Must not contain `..`, UNC prefixes (`\\`), or NT device namespaces
///     (`\\?\`, `\\.\`).
pub fn validate_service_dll_path(value: &str, known_install_dir: Option<&Path>) -> Result<()> {
    // Lexical checks on the *unexpanded* value.
    if value.is_empty() {
        bail!("OriginalServiceDll is empty");
    }
    if value.contains("..") {
        bail!("OriginalServiceDll contains '..' — refusing");
    }
    if value.starts_with("\\\\") {
        bail!("OriginalServiceDll is UNC / device namespace — refusing");
    }

    // Expand environment variables for absolute-path comparison.
    let expanded = expand_env(value)?;
    let expanded_path = PathBuf::from(&expanded);

    // Must be absolute with a drive letter (not e.g. "termsrv.dll").
    // Accept either drive-root or any fully-qualified path.
    let has_drive = expanded.chars().nth(1).map(|c| c == ':').unwrap_or(false)
        && expanded.chars().nth(2) == Some('\\');
    if !has_drive {
        bail!("OriginalServiceDll is not an absolute DOS path: {expanded}");
    }

    // Re-check UNC / device namespace on the expanded form too.
    if expanded.starts_with("\\\\") {
        bail!("OriginalServiceDll expanded to UNC / device namespace: {expanded}");
    }
    if expanded.contains("..") {
        bail!("OriginalServiceDll expanded contains '..': {expanded}");
    }

    // Must be under System32 or the recorded install dir.
    let system32 = system32_dir()?;
    let under_system32 = path_is_under(&expanded_path, &system32);
    let under_install = known_install_dir
        .map(|d| path_is_under(&expanded_path, d))
        .unwrap_or(false);
    if !(under_system32 || under_install) {
        bail!(
            "OriginalServiceDll {} is not under System32 ({}){}",
            expanded_path.display(),
            system32.display(),
            known_install_dir
                .map(|d| format!(" or install dir {}", d.display()))
                .unwrap_or_default()
        );
    }
    Ok(())
}

/// Case-insensitive ASCII-folded path prefix check.
fn path_is_under(child: &Path, parent: &Path) -> bool {
    let c = child.to_string_lossy().to_ascii_lowercase();
    let p = parent.to_string_lossy().to_ascii_lowercase();
    // Normalise trailing separator on parent.
    let p_trim = p.trim_end_matches('\\').trim_end_matches('/');
    let mut needle = String::with_capacity(p_trim.len() + 1);
    needle.push_str(p_trim);
    needle.push('\\');
    c.starts_with(&needle)
}

/// Return `%SystemRoot%\System32` as a `PathBuf`.
fn system32_dir() -> Result<PathBuf> {
    let root = std::env::var_os("SystemRoot").ok_or_else(|| anyhow!("%SystemRoot% is not set"))?;
    Ok(PathBuf::from(root).join("System32"))
}

/// Expand `%VAR%` sequences in `s` via `ExpandEnvironmentStringsW`.
fn expand_env(s: &str) -> Result<String> {
    use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
    let wide = to_wide(s);
    // SAFETY: Probe with None destination to discover required length.
    let needed = unsafe { ExpandEnvironmentStringsW(PCWSTR(wide.as_ptr()), None) };
    if needed == 0 {
        bail!("ExpandEnvironmentStringsW size probe returned 0");
    }
    let mut buf = vec![0u16; needed as usize];
    // SAFETY: `buf` has `needed` u16 slots of writable storage.
    let wrote = unsafe { ExpandEnvironmentStringsW(PCWSTR(wide.as_ptr()), Some(&mut buf)) };
    if wrote == 0 {
        bail!("ExpandEnvironmentStringsW failed");
    }
    // `wrote` includes the trailing NUL.
    let len = wrote as usize;
    let take = if len > 0 { len - 1 } else { 0 };
    Ok(String::from_utf16_lossy(&buf[..take]))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert!(validate_service_dll_path("", None).is_err());
    }

    #[test]
    fn rejects_dot_dot() {
        assert!(validate_service_dll_path("C:\\Windows\\..\\evil.dll", None).is_err());
    }

    #[test]
    fn rejects_unc() {
        assert!(validate_service_dll_path("\\\\attacker\\share\\evil.dll", None).is_err());
    }

    #[test]
    fn rejects_device_namespace() {
        assert!(validate_service_dll_path("\\\\?\\C:\\evil.dll", None).is_err());
    }

    #[test]
    fn rejects_relative() {
        assert!(validate_service_dll_path("termsrv.dll", None).is_err());
    }

    #[test]
    fn path_is_under_basic() {
        assert!(path_is_under(
            Path::new("C:\\Windows\\System32\\termsrv.dll"),
            Path::new("C:\\Windows\\System32")
        ));
        assert!(!path_is_under(
            Path::new("C:\\WindowsEvil\\termsrv.dll"),
            Path::new("C:\\Windows")
        ));
        assert!(path_is_under(
            Path::new("C:\\Program Files\\RDP Wrapper\\termwrap.dll"),
            Path::new("C:\\Program Files\\RDP Wrapper")
        ));
    }
}
