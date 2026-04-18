//! Detect whether an `RDP-Tcp` listener is currently registered with
//! Terminal Services by calling `WinStationEnumerateW`.
//!
//! The `winsta.dll` exports are only semi-public — they are undocumented on
//! MSDN but stable across Windows 7..11 and used by `qwinsta.exe`.
//! We dynamic-load the DLL so the build does not depend on an import library
//! that may not ship in every Windows SDK.

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::c_void;
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{FreeLibrary, FARPROC, HANDLE, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

use crate::registry::to_wide;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerState {
    Listening,
    NotListening,
    Unavailable,
}

impl ListenerState {
    pub fn label(self) -> &'static str {
        match self {
            ListenerState::Listening => "Listening",
            ListenerState::NotListening => "Not listening",
            ListenerState::Unavailable => "Unavailable",
        }
    }
}

/// Winsta's `SERVER_HANDLE` for the local server.
const SERVER_CURRENT: HANDLE = HANDLE(std::ptr::null_mut::<c_void>());

/// `WinStationEnumerateW(SERVER_HANDLE, SESSIONIDW**, DWORD*)`.
type WinStationEnumerateW = unsafe extern "system" fn(
    server: HANDLE,
    entries: *mut *mut SessionIdW,
    count: *mut u32,
) -> i32;
/// `WinStationFreeMemory(PVOID)`.
type WinStationFreeMemory = unsafe extern "system" fn(p: *mut c_void) -> i32;

/// `SESSIONIDW` as documented in old MSDN / `winsta.h`.
#[repr(C)]
#[derive(Clone, Copy)]
struct SessionIdW {
    size_of_struct: u32,
    session_id: u32,
    /// WINSTATIONNAME — WCHAR[32].
    winstation_name: [u16; 32],
    state: u32,
}

/// Returns `ListenerState::Listening` iff Terminal Services has at least one
/// enumerated session whose station name starts with "RDP-Tcp".
pub fn rdp_tcp_state() -> ListenerState {
    match rdp_tcp_state_inner() {
        Ok(s) => s,
        Err(_) => ListenerState::Unavailable,
    }
}

fn rdp_tcp_state_inner() -> Result<ListenerState> {
    let module = LoadedModule::load("winsta.dll")?;
    let enum_fn: WinStationEnumerateW =
        // SAFETY: The resolved pointer implements the documented export's
        // ABI (stable in winsta.dll since Windows 2000).
        unsafe { core::mem::transmute(module.proc(b"WinStationEnumerateW\0")?) };
    let free_fn: WinStationFreeMemory =
        // SAFETY: Same export ABI as above.
        unsafe { core::mem::transmute(module.proc(b"WinStationFreeMemory\0")?) };

    let mut entries: *mut SessionIdW = core::ptr::null_mut();
    let mut count: u32 = 0;
    // SAFETY: Both out-params are valid writable locals. `SERVER_CURRENT` (NULL)
    // requests the local server per the documented convention.
    let ok = unsafe { enum_fn(SERVER_CURRENT, &mut entries, &mut count) };
    if ok == 0 {
        bail!("WinStationEnumerateW returned 0");
    }
    // RAII release of the caller-owned list.
    let _guard = FreeListGuard {
        ptr: entries as *mut c_void,
        free: free_fn,
    };

    if entries.is_null() || count == 0 {
        return Ok(ListenerState::NotListening);
    }

    // SAFETY: `entries` points to `count` contiguous SessionIdW structures
    // allocated by winsta; it is valid until `_guard` drops below.
    let slice = unsafe { core::slice::from_raw_parts(entries, count as usize) };

    for entry in slice {
        // Trim trailing NULs.
        let nul = entry
            .winstation_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.winstation_name.len());
        let name = String::from_utf16_lossy(&entry.winstation_name[..nul]);
        if name.eq_ignore_ascii_case("RDP-Tcp") || name.to_ascii_lowercase().starts_with("rdp-tcp#")
        {
            return Ok(ListenerState::Listening);
        }
    }
    Ok(ListenerState::NotListening)
}

struct FreeListGuard {
    ptr: *mut c_void,
    free: WinStationFreeMemory,
}
impl Drop for FreeListGuard {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: `self.ptr` was returned by WinStationEnumerateW above and
            // is not used after this free.
            unsafe {
                let _ = (self.free)(self.ptr);
            }
        }
    }
}

struct LoadedModule(HMODULE);
impl LoadedModule {
    fn load(name: &str) -> Result<Self> {
        let w = to_wide(name);
        // SAFETY: `w` is NUL-terminated UTF-16. Search path constrained to
        // System32 via `LOAD_LIBRARY_SEARCH_SYSTEM32` so a spoofed
        // `winsta.dll` next to the GUI binary cannot be loaded instead of
        // the authentic system copy.
        let h = unsafe { LoadLibraryExW(PCWSTR(w.as_ptr()), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }
            .with_context(|| format!("LoadLibraryExW({name}, SEARCH_SYSTEM32)"))?;
        if h.is_invalid() {
            bail!("LoadLibraryExW({name}, SEARCH_SYSTEM32) returned NULL");
        }
        Ok(Self(h))
    }

    fn proc(&self, name: &[u8]) -> Result<unsafe extern "system" fn() -> isize> {
        debug_assert!(name.last() == Some(&0));
        // SAFETY: `self.0` is a valid HMODULE and `name` is a NUL-terminated
        // ASCII byte slice owned by the caller.
        let p: FARPROC = unsafe { GetProcAddress(self.0, PCSTR(name.as_ptr())) };
        p.ok_or_else(|| {
            anyhow!(
                "GetProcAddress failed for {:?}",
                String::from_utf8_lossy(name)
            )
        })
    }
}
impl Drop for LoadedModule {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: Module was obtained from LoadLibraryExW and not used after.
            unsafe {
                let _ = FreeLibrary(self.0);
            }
        }
    }
}
