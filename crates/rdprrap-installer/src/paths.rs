//! Canonical install paths for the rdprrap wrapper DLLs.
//!
//! We resolve `%ProgramFiles%` at runtime via `SHGetKnownFolderPath` rather
//! than trusting the environment variable, which can be redirected under
//! WOW64 / 32-bit processes and shimming layers.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use windows::core::PWSTR;
use windows::Win32::Foundation::HLOCAL;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath, KF_FLAG_DEFAULT};

// Install-contract string constants are defined once in `crate::contract`
// (non-gated so they can drive the `plan` subcommand on Linux too). We
// re-export the relevant names here to preserve the existing `paths::...`
// call sites without duplicating the source of truth.
pub use crate::contract::{INSTALL_SUBDIR, SERVICE_DLL_NAME, WRAPPER_DLLS};

/// Return `%ProgramFiles%\RDP Wrapper\`.
pub fn install_dir() -> Result<PathBuf> {
    Ok(program_files()?.join(INSTALL_SUBDIR))
}

/// Return the absolute path where the TermService ServiceDll should point.
#[allow(dead_code)]
pub fn service_dll_path() -> Result<PathBuf> {
    Ok(install_dir()?.join(SERVICE_DLL_NAME))
}

/// RAII guard for memory allocated by a COM API that requires `CoTaskMemFree`.
///
/// Holds the raw pointer returned by APIs like `SHGetKnownFolderPath`. The
/// pointer is freed on `Drop` — including on panic / early return — which
/// eliminates the leak window that existed when `CoTaskMemFree` was called
/// manually at the end of the `unsafe` block.
struct CoTaskMem(*mut core::ffi::c_void);

impl CoTaskMem {
    /// Wrap a raw COM-allocated pointer.
    ///
    /// # Safety
    /// `ptr` must either be null OR a pointer whose ownership has been
    /// transferred to us and is valid to pass to `CoTaskMemFree` exactly once.
    unsafe fn from_raw(ptr: *mut core::ffi::c_void) -> Self {
        Self(ptr)
    }
}

impl Drop for CoTaskMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Constructor contract guarantees the pointer is either
            // null (skipped above) or a valid COM allocation handed to us
            // exactly once. `CoTaskMemFree` tolerates `None` but we only
            // reach here when non-null.
            unsafe {
                CoTaskMemFree(Some(self.0 as *const core::ffi::c_void));
            }
        }
    }
}

/// Resolve `%ProgramFiles%` via `SHGetKnownFolderPath(FOLDERID_ProgramFiles)`.
pub fn program_files() -> Result<PathBuf> {
    // SAFETY: `SHGetKnownFolderPath` writes a pointer to a COM-allocated,
    // wide-char, NUL-terminated string into its return value. We immediately
    // transfer ownership to the `CoTaskMem` RAII guard so the allocation is
    // released even if `read_wide_to_pathbuf` panics.
    let pwstr: PWSTR = unsafe {
        SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, None)
            .context("SHGetKnownFolderPath(FOLDERID_ProgramFiles) failed")?
    };

    if pwstr.is_null() {
        return Err(anyhow!("SHGetKnownFolderPath returned NULL"));
    }

    // SAFETY: `pwstr.0` was just returned from `SHGetKnownFolderPath` with a
    // success status, so ownership is ours to free via `CoTaskMemFree`.
    let _guard = unsafe { CoTaskMem::from_raw(pwstr.0 as *mut core::ffi::c_void) };

    // SAFETY: `pwstr` is a valid NUL-terminated UTF-16 buffer owned by the
    // COM allocator; it lives until `_guard` drops at function exit.
    let path = unsafe { read_wide_to_pathbuf(pwstr) };
    if path.as_os_str().is_empty() {
        return Err(anyhow!(
            "SHGetKnownFolderPath returned a path exceeding MAX_WIDE_LEN"
        ));
    }
    Ok(path)
}

/// Copy a raw NUL-terminated wide pointer into an owned `PathBuf`.
///
/// Caps the scan at `MAX_WIDE_LEN` u16 code units as a defensive bound — a
/// well-behaved Shell API will always terminate long before that. If the cap
/// is hit we return an empty `PathBuf` (caller treats it as failure).
///
/// # Safety
/// - `ptr.0` must point to a valid NUL-terminated UTF-16 sequence, OR the
///   sequence must be at least `MAX_WIDE_LEN` u16 code units long.
/// - The underlying memory must remain live for the duration of the call.
unsafe fn read_wide_to_pathbuf(ptr: PWSTR) -> PathBuf {
    use std::os::windows::ffi::OsStringExt;

    /// Windows `MAX_PATH` is 260, extended-length paths cap at 32767. We
    /// pick a generous upper bound that still prevents unbounded reads.
    const MAX_WIDE_LEN: usize = 32768;

    // SAFETY: Caller guarantees a valid NUL-terminated UTF-16 string.
    let mut len = 0usize;
    while len < MAX_WIDE_LEN && unsafe { *ptr.0.add(len) } != 0 {
        len += 1;
    }
    if len >= MAX_WIDE_LEN {
        // Pathological input — refuse rather than risk reading past the buffer.
        return PathBuf::new();
    }
    // SAFETY: `ptr.0` is valid for `len` u16 reads (caller guarantee) and
    // `len < MAX_WIDE_LEN` so no overflow.
    let slice = unsafe { std::slice::from_raw_parts(ptr.0, len) };
    PathBuf::from(std::ffi::OsString::from_wide(slice))
}

/// Helper — suppress unused-import warning when only HLOCAL is referenced.
#[allow(dead_code)]
const _HLOCAL_IMPORT_USED: Option<HLOCAL> = None;

/// Check whether a path is under a writeable, existing directory.
/// Used for friendlier diagnostics before doing actual I/O.
#[allow(dead_code)]
pub fn parent_is_dir(path: &Path) -> bool {
    path.parent().map(Path::is_dir).unwrap_or(false)
}
