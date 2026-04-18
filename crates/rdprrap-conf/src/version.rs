//! Read the `FileVersion` resource out of a PE image.
//!
//! `version.dll` is dynamic-loaded so we don't have to pin a further feature
//! on the workspace `windows` crate. These APIs are stable since Windows 2000
//! and are present on every supported platform.

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::c_void;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{FreeLibrary, FARPROC, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

use crate::registry::to_wide;

type GetFileVersionInfoSizeW =
    unsafe extern "system" fn(lptstrfilename: PCWSTR, lpdwhandle: *mut u32) -> u32;
type GetFileVersionInfoW = unsafe extern "system" fn(
    lptstrfilename: PCWSTR,
    dwhandle: u32,
    dwlen: u32,
    lpdata: *mut c_void,
) -> i32;
type VerQueryValueW = unsafe extern "system" fn(
    pblock: *const c_void,
    lpsubblock: PCWSTR,
    lplpbuffer: *mut *mut c_void,
    pulen: *mut u32,
) -> i32;

struct LoadedModule(HMODULE);
impl LoadedModule {
    fn load(name: &str) -> Result<Self> {
        let w = to_wide(name);
        // SAFETY: `w` is NUL-terminated UTF-16. Search path constrained to
        // System32 via `LOAD_LIBRARY_SEARCH_SYSTEM32` so a planted
        // `version.dll` adjacent to the GUI binary cannot hijack the load.
        // Returns a refcounted HMODULE we release on drop.
        let h = unsafe { LoadLibraryExW(PCWSTR(w.as_ptr()), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }
            .with_context(|| format!("LoadLibraryExW({name}, SEARCH_SYSTEM32)"))?;
        if h.is_invalid() {
            bail!("LoadLibraryExW({name}, SEARCH_SYSTEM32) returned NULL");
        }
        Ok(Self(h))
    }

    fn proc(&self, name: &[u8]) -> Result<unsafe extern "system" fn() -> isize> {
        // Ensure NUL-terminated.
        debug_assert!(name.last() == Some(&0));
        let pcstr = windows::core::PCSTR(name.as_ptr());
        // SAFETY: `self.0` is a valid HMODULE and `pcstr` points to a
        // NUL-terminated ASCII byte slice owned by the caller.
        let p: FARPROC = unsafe { GetProcAddress(self.0, pcstr) };
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
            // SAFETY: `self.0` is an HMODULE obtained from LoadLibraryExW and
            // not used after this call.
            unsafe {
                let _ = FreeLibrary(self.0);
            }
        }
    }
}

/// Return the `FileVersion` string (e.g. "10.0.19041.1").
///
/// `None` is returned if the file has no version resource, `Err` for any I/O
/// failure. Callers commonly display `None` / `Err` as literal "N/A".
pub fn file_version(path: &str) -> Result<Option<String>> {
    let module = LoadedModule::load("version.dll")?;
    let get_size: GetFileVersionInfoSizeW =
        // SAFETY: The address returned by GetProcAddress for this documented
        // export has the declared signature.
        unsafe { core::mem::transmute(module.proc(b"GetFileVersionInfoSizeW\0")?) };
    let get_info: GetFileVersionInfoW =
        // SAFETY: See above — matches the documented signature of the export.
        unsafe { core::mem::transmute(module.proc(b"GetFileVersionInfoW\0")?) };
    let ver_query: VerQueryValueW =
        // SAFETY: Same justification as the two sibling exports above.
        unsafe { core::mem::transmute(module.proc(b"VerQueryValueW\0")?) };

    let wpath = to_wide(path);
    let mut dummy_handle: u32 = 0;
    // SAFETY: `wpath` is NUL-terminated; `dummy_handle` is a writable local.
    let size = unsafe { get_size(PCWSTR(wpath.as_ptr()), &mut dummy_handle) };
    if size == 0 {
        return Ok(None);
    }

    let mut buf = vec![0u8; size as usize];
    // SAFETY: `buf` has `size` writable bytes; `wpath` is NUL-terminated UTF-16.
    let ok = unsafe {
        get_info(
            PCWSTR(wpath.as_ptr()),
            0,
            size,
            buf.as_mut_ptr() as *mut c_void,
        )
    };
    if ok == 0 {
        return Ok(None);
    }

    // Query the root \VS_FIXEDFILEINFO structure to extract MAJOR.MINOR.BUILD.REVISION.
    let root = to_wide("\\");
    let mut block_ptr: *mut c_void = core::ptr::null_mut();
    let mut block_len: u32 = 0;
    // SAFETY: `buf` lives for the entire call; `block_ptr`/`block_len` are
    // writable locals. The returned pointer aliases into `buf` and stays valid
    // while `buf` is alive.
    let ok = unsafe {
        ver_query(
            buf.as_ptr() as *const c_void,
            PCWSTR(root.as_ptr()),
            &mut block_ptr,
            &mut block_len,
        )
    };
    if ok == 0
        || block_ptr.is_null()
        || (block_len as usize) < core::mem::size_of::<FixedFileInfo>()
    {
        return Ok(None);
    }

    // SAFETY: `block_ptr` points to at least `sizeof(FixedFileInfo)` bytes
    // inside `buf`. Reading a `#[repr(C)]` POD struct is defined.
    let ffi: FixedFileInfo =
        unsafe { core::ptr::read_unaligned(block_ptr as *const FixedFileInfo) };

    let major = (ffi.file_version_ms >> 16) & 0xFFFF;
    let minor = ffi.file_version_ms & 0xFFFF;
    let build = (ffi.file_version_ls >> 16) & 0xFFFF;
    let revision = ffi.file_version_ls & 0xFFFF;
    Ok(Some(format!("{major}.{minor}.{build}.{revision}")))
}

/// `VS_FIXEDFILEINFO` (subset — only the fields we read).
#[repr(C)]
#[derive(Clone, Copy)]
struct FixedFileInfo {
    signature: u32,
    struct_version: u32,
    file_version_ms: u32,
    file_version_ls: u32,
    product_version_ms: u32,
    product_version_ls: u32,
    file_flags_mask: u32,
    file_flags: u32,
    file_os: u32,
    file_type: u32,
    file_subtype: u32,
    file_date_ms: u32,
    file_date_ls: u32,
}

/// Extract only the `major.minor` prefix of a version string, e.g. "10.0".
/// Returns `None` if parsing fails.
pub fn major_minor(version: &str) -> Option<(u32, u32)> {
    let mut it = version.split('.');
    let major = it.next()?.parse::<u32>().ok()?;
    let minor = it.next()?.parse::<u32>().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_major_minor() {
        assert_eq!(major_minor("10.0.19041.1"), Some((10, 0)));
        assert_eq!(major_minor("6.3.9600.17415"), Some((6, 3)));
        assert_eq!(major_minor("garbage"), None);
        assert_eq!(major_minor(""), None);
    }
}
