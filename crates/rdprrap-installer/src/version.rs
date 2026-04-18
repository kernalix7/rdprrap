//! Read the fixed VS_FIXEDFILEINFO block out of a PE image.
//!
//! Used by the install flow to perform a CheckTermsrvVersion preflight
//! (upstream `RDPWInst.dpr`'s CheckTermsrvVersion): warn when `termsrv.dll`
//! reports a major.minor outside the set of versions upstream rdpwrap is
//! known to patch — currently 6.1 (Win7), 6.2 (Win8), 6.3 (Win8.1) and
//! 10.0 (Win10/Win11). We only emit a warning; we never block install
//! because modern wrappers patch by pattern, not by hard-coded offsets.
//!
//! `version.dll` is dynamic-loaded via `GetProcAddress` — matching the
//! pattern already used in `rdprrap-conf`'s `version.rs` — so we don't have
//! to pin a further feature flag on the workspace `windows` crate.

use std::ffi::c_void;

use anyhow::{anyhow, bail, Context, Result};
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{FreeLibrary, FARPROC, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

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
        // SAFETY: `w` is NUL-terminated UTF-16. `LoadLibraryExW` is used with
        // `LOAD_LIBRARY_SEARCH_SYSTEM32` so the search path is constrained to
        // %WINDIR%\System32 — defeating DLL-search-order hijacking via a
        // planted `version.dll` next to the installer binary. Returns a
        // ref-counted HMODULE released via `FreeLibrary` on drop.
        let h = unsafe { LoadLibraryExW(PCWSTR(w.as_ptr()), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }
            .with_context(|| format!("LoadLibraryExW({name}, SEARCH_SYSTEM32)"))?;
        if h.is_invalid() {
            bail!("LoadLibraryExW({name}, SEARCH_SYSTEM32) returned NULL");
        }
        Ok(Self(h))
    }

    fn proc(&self, name: &[u8]) -> Result<unsafe extern "system" fn() -> isize> {
        debug_assert!(name.last() == Some(&0));
        let pcstr = PCSTR(name.as_ptr());
        // SAFETY: `self.0` is a valid HMODULE; `pcstr` is NUL-terminated.
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
            // SAFETY: `self.0` is an HMODULE obtained from `LoadLibraryExW`
            // and is not used after this call.
            unsafe {
                let _ = FreeLibrary(self.0);
            }
        }
    }
}

/// 4-tuple form of the `VS_FIXEDFILEINFO::dwFileVersionMS/LS` decomposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileVersionTuple {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
}

impl FileVersionTuple {
    pub fn as_tuple(&self) -> (u16, u16, u16, u16) {
        (self.major, self.minor, self.build, self.revision)
    }

    /// Major.minor pair — the discriminator used by CheckTermsrvVersion.
    pub fn major_minor(&self) -> (u16, u16) {
        (self.major, self.minor)
    }
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

/// Read the `VS_FIXEDFILEINFO` from `path` and return it as a 4-tuple.
///
/// `None` is returned if the file has no version resource.
pub fn read_fixed_file_version(path: &str) -> Result<Option<FileVersionTuple>> {
    let module = LoadedModule::load("version.dll")?;
    // SAFETY: The addresses returned by GetProcAddress for these documented
    // exports have the declared signatures.
    let get_size: GetFileVersionInfoSizeW =
        unsafe { core::mem::transmute(module.proc(b"GetFileVersionInfoSizeW\0")?) };
    let get_info: GetFileVersionInfoW =
        unsafe { core::mem::transmute(module.proc(b"GetFileVersionInfoW\0")?) };
    let ver_query: VerQueryValueW =
        unsafe { core::mem::transmute(module.proc(b"VerQueryValueW\0")?) };

    let wpath = to_wide(path);
    let mut dummy_handle: u32 = 0;
    // SAFETY: `wpath` is NUL-terminated UTF-16; `dummy_handle` is writable.
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

    // `VerQueryValueW("\")` returns a pointer aliased into `buf` — which
    // remains owned here until function exit.
    let root = to_wide("\\");
    let mut block_ptr: *mut c_void = core::ptr::null_mut();
    let mut block_len: u32 = 0;
    // SAFETY: `buf` is live for the call; `block_ptr`/`block_len` are writable locals.
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
    // inside `buf`; reading a `#[repr(C)]` POD via `read_unaligned` is defined.
    let ffi: FixedFileInfo =
        unsafe { core::ptr::read_unaligned(block_ptr as *const FixedFileInfo) };

    Ok(Some(FileVersionTuple {
        major: ((ffi.file_version_ms >> 16) & 0xFFFF) as u16,
        minor: (ffi.file_version_ms & 0xFFFF) as u16,
        build: ((ffi.file_version_ls >> 16) & 0xFFFF) as u16,
        revision: (ffi.file_version_ls & 0xFFFF) as u16,
    }))
}

/// The known-good major.minor pairs for `termsrv.dll` — Windows 7 through
/// Windows 11. An OS reporting something outside this set is *probably*
/// still patchable (we detect everything by pattern now, not by hard-coded
/// offsets), but unusual enough to warn the operator about.
pub const KNOWN_TERMSRV_MAJOR_MINOR: &[(u16, u16)] = &[(6, 1), (6, 2), (6, 3), (10, 0)];

/// Return `true` if `(major, minor)` is one of the upstream-supported
/// `termsrv.dll` major.minor pairs.
pub fn is_known_termsrv_version(major: u16, minor: u16) -> bool {
    KNOWN_TERMSRV_MAJOR_MINOR.contains(&(major, minor))
}

fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_versions_match() {
        assert!(is_known_termsrv_version(6, 1));
        assert!(is_known_termsrv_version(6, 2));
        assert!(is_known_termsrv_version(6, 3));
        assert!(is_known_termsrv_version(10, 0));
    }

    #[test]
    fn unknown_versions_reject() {
        assert!(!is_known_termsrv_version(5, 1));
        assert!(!is_known_termsrv_version(11, 0));
        assert!(!is_known_termsrv_version(0, 0));
    }

    #[test]
    fn tuple_accessors() {
        let v = FileVersionTuple {
            major: 10,
            minor: 0,
            build: 19041,
            revision: 1,
        };
        assert_eq!(v.as_tuple(), (10, 0, 19041, 1));
        assert_eq!(v.major_minor(), (10, 0));
    }
}
