//! Install-directory ACL hardening (H3).
//!
//! After the install directory is populated we grant **read + execute** to
//! the two non-admin principals that legitimately need to load the wrapper
//! DLLs at runtime:
//!
//!   * `NT AUTHORITY\SYSTEM` (S-1-5-18) — TermService runs under SYSTEM and
//!     must be able to read/map `termwrap.dll`.
//!   * `NT AUTHORITY\LocalService` (S-1-5-19) — some network-only Windows
//!     SKUs host the UMS helpers under LocalService.
//!
//! We deliberately do **not** grant Write / Delete / WriteDAC to either
//! principal. We also do not touch the existing inherited ACL from
//! `%ProgramFiles%` (Administrators + TrustedInstaller retain full control)
//! — we merely *add* the two ACEs so that a future SKU where TermService
//! drops privileges to LocalService can still load the DLL.
//!
//! Rather than pull in the `Win32_Security_Authorization` typed bindings
//! (whose struct layouts can drift between windows-rs minor versions) we
//! dynamic-load `advapi32!SetEntriesInAclW` + `SetNamedSecurityInfoW` via
//! `GetProcAddress` and construct `EXPLICIT_ACCESS_W` ourselves with
//! `#[repr(C)]` mirrors of the documented struct layout.  This mirrors the
//! pattern already used in `version.rs` and keeps the crate feature set
//! minimal.

use std::ffi::c_void;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{FreeLibrary, LocalFree, FARPROC, HLOCAL, HMODULE};
use windows::Win32::Security::{
    CreateWellKnownSid, WinLocalServiceSid, WinLocalSystemSid, PSID, WELL_KNOWN_SID_TYPE,
};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

/// Access mask — `GENERIC_READ | GENERIC_EXECUTE` resolved for file objects.
///
/// Using raw bits (0x8000_0000 | 0x2000_0000) keeps us out of the
/// `Win32_Storage_FileSystem` feature requirement for `FILE_GENERIC_READ`.
const GENERIC_READ_EXECUTE: u32 = 0x8000_0000 | 0x2000_0000;

/// `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE` — applies to this directory
/// and to all descendant files + subdirectories.
const OI_CI: u32 = 0x0000_0003;

/// `SET_ACCESS` value from the Windows SDK `ACCESS_MODE` enum (entry #2).
/// Replace existing ACE(s) for the trustee with the new one.
const SET_ACCESS_MODE: u32 = 2;

/// `TRUSTEE_IS_SID` entry from the `TRUSTEE_FORM` enum.
const TRUSTEE_FORM_SID: u32 = 0;

/// `TRUSTEE_IS_WELL_KNOWN_GROUP` entry from the `TRUSTEE_TYPE` enum.
const TRUSTEE_TYPE_WELL_KNOWN: u32 = 5;

/// `NO_MULTIPLE_TRUSTEE` — no multi-trustee aggregation.
const NO_MULTIPLE_TRUSTEE_OP: u32 = 0;

/// `SE_FILE_OBJECT` from the `SE_OBJECT_TYPE` enum — object named by path.
const SE_FILE_OBJECT_VAL: u32 = 1;

/// `DACL_SECURITY_INFORMATION` — we only rewrite the DACL.
const DACL_SECURITY_INFORMATION_VAL: u32 = 0x0000_0004;

/// `TRUSTEE_W` as laid out in `authz.h`. `ptstrName` double-duties as a
/// `PSID` when `TrusteeForm == TRUSTEE_IS_SID`.
#[repr(C)]
#[allow(non_snake_case)]
struct TrusteeW {
    pMultipleTrustee: *mut c_void,
    MultipleTrusteeOperation: u32,
    TrusteeForm: u32,
    TrusteeType: u32,
    ptstrName: *mut u16,
}

/// `EXPLICIT_ACCESS_W` as laid out in `accctrl.h`.
#[repr(C)]
#[allow(non_snake_case)]
struct ExplicitAccessW {
    grfAccessPermissions: u32,
    grfAccessMode: u32,
    grfInheritance: u32,
    Trustee: TrusteeW,
}

/// `SetEntriesInAclW` signature.
#[allow(non_snake_case)]
type SetEntriesInAclW = unsafe extern "system" fn(
    cCountOfExplicitEntries: u32,
    pListOfExplicitEntries: *const ExplicitAccessW,
    OldAcl: *const c_void,
    NewAcl: *mut *mut c_void,
) -> u32;

/// `SetNamedSecurityInfoW` signature. Only DACL is supplied.
#[allow(non_snake_case)]
type SetNamedSecurityInfoW = unsafe extern "system" fn(
    pObjectName: PCWSTR,
    ObjectType: u32,
    SecurityInfo: u32,
    psidOwner: *mut c_void,
    psidGroup: *mut c_void,
    pDacl: *const c_void,
    pSacl: *const c_void,
) -> u32;

struct LoadedModule(HMODULE);
impl LoadedModule {
    fn load(name: &str) -> Result<Self> {
        let w = to_wide(name);
        // SAFETY: `w` is NUL-terminated UTF-16. We explicitly constrain the
        // search path to %WINDIR%\System32 via LOAD_LIBRARY_SEARCH_SYSTEM32 so
        // a maliciously-planted `advapi32.dll` alongside the installer cannot
        // win the DLL search race (defence against classic DLL hijacking).
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
            // SAFETY: `self.0` from `LoadLibraryExW`, not used after this call.
            unsafe {
                let _ = FreeLibrary(self.0);
            }
        }
    }
}

/// Owned SID buffer created by `CreateWellKnownSid`. Freed automatically.
///
/// The underlying storage is a `Box<[u8]>` (not a `Vec<u8>`) so the address
/// returned by [`WellKnownSid::as_ptr`] is *frozen* for the lifetime of the
/// struct: boxed slices have no `push` / `reserve` / `insert` API that could
/// reallocate the backing buffer and invalidate the pointer we stash inside
/// the `TRUSTEE_W.ptstrName` field that `SetEntriesInAclW` dereferences. This
/// is load-bearing — `EXPLICIT_ACCESS_W` borrows that pointer by-value but
/// the SID bytes have to stay at the same address until `SetEntriesInAclW`
/// returns.
struct WellKnownSid {
    bytes: Box<[u8]>,
}

impl WellKnownSid {
    fn new(ty: WELL_KNOWN_SID_TYPE) -> Result<Self> {
        // Probe the required size first (len=0 is documented to fail with
        // ERROR_INSUFFICIENT_BUFFER and write the needed size into `size`).
        let mut size: u32 = 0;
        // SAFETY: `size` is writable; `None` SID buffer requests a size probe.
        let _ = unsafe { CreateWellKnownSid(ty, None, PSID(core::ptr::null_mut()), &mut size) };
        if size == 0 {
            bail!("CreateWellKnownSid size probe returned 0 for {ty:?}");
        }
        let mut bytes = vec![0u8; size as usize];
        let mut size2 = size;
        // SAFETY: `bytes` has `size` writable bytes; the PSID we pass aliases
        // the head of that buffer.
        unsafe {
            CreateWellKnownSid(
                ty,
                None,
                PSID(bytes.as_mut_ptr() as *mut c_void),
                &mut size2,
            )
        }
        .with_context(|| format!("CreateWellKnownSid({ty:?})"))?;
        // Freeze post-construction: `into_boxed_slice` drops any extra
        // capacity and hands back a buffer that cannot be grown or shrunk,
        // so `as_ptr()` below is address-stable.
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
        })
    }

    fn as_ptr(&self) -> *mut c_void {
        // `Box<[u8]>::as_ptr` still exists (via deref to `[u8]`), returns a
        // pointer that remains valid for the entire lifetime of `self`.
        self.bytes.as_ptr() as *mut c_void
    }
}

/// Grant `SYSTEM` and `LocalService` **read + execute** on `dir`.
///
/// Never removes existing ACEs. If `advapi32.dll` fails to load (extremely
/// unlikely on Windows) or `SetEntriesInAclW` / `SetNamedSecurityInfoW`
/// returns non-zero, we propagate the failure — the operator needs to know
/// because on some hardened SKUs the wrapper DLL would otherwise be
/// unreadable by the service account.
pub fn grant_install_dir_acl(dir: &Path) -> Result<()> {
    let advapi = LoadedModule::load("advapi32.dll")?;
    // SAFETY: The addresses returned by `GetProcAddress` for these documented
    // exports have the declared signatures.
    let set_entries: SetEntriesInAclW =
        unsafe { core::mem::transmute(advapi.proc(b"SetEntriesInAclW\0")?) };
    let set_named: SetNamedSecurityInfoW =
        unsafe { core::mem::transmute(advapi.proc(b"SetNamedSecurityInfoW\0")?) };

    let sys_sid =
        WellKnownSid::new(WinLocalSystemSid).context("create SID for LocalSystem (S-1-5-18)")?;
    let local_svc_sid =
        WellKnownSid::new(WinLocalServiceSid).context("create SID for LocalService (S-1-5-19)")?;

    let entries: [ExplicitAccessW; 2] = [
        ExplicitAccessW {
            grfAccessPermissions: GENERIC_READ_EXECUTE,
            grfAccessMode: SET_ACCESS_MODE,
            grfInheritance: OI_CI,
            Trustee: TrusteeW {
                pMultipleTrustee: core::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE_OP,
                TrusteeForm: TRUSTEE_FORM_SID,
                TrusteeType: TRUSTEE_TYPE_WELL_KNOWN,
                ptstrName: sys_sid.as_ptr() as *mut u16,
            },
        },
        ExplicitAccessW {
            grfAccessPermissions: GENERIC_READ_EXECUTE,
            grfAccessMode: SET_ACCESS_MODE,
            grfInheritance: OI_CI,
            Trustee: TrusteeW {
                pMultipleTrustee: core::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE_OP,
                TrusteeForm: TRUSTEE_FORM_SID,
                TrusteeType: TRUSTEE_TYPE_WELL_KNOWN,
                ptstrName: local_svc_sid.as_ptr() as *mut u16,
            },
        },
    ];

    let mut new_acl: *mut c_void = core::ptr::null_mut();
    // SAFETY: `entries` has 2 valid elements; we pass NULL old-ACL to request
    // a brand-new ACL containing exactly our two ACEs. The returned pointer
    // is `LocalAlloc`-ed and must be released with `LocalFree`.
    let rc = unsafe {
        set_entries(
            entries.len() as u32,
            entries.as_ptr(),
            core::ptr::null(),
            &mut new_acl,
        )
    };
    if rc != 0 {
        bail!("SetEntriesInAclW returned Win32 error 0x{rc:08x}");
    }
    if new_acl.is_null() {
        bail!("SetEntriesInAclW returned a NULL ACL with success status");
    }
    let _new_acl_guard = LocalPtr(new_acl);

    // Attach the new DACL on the directory. Only DACL info is modified;
    // owner + group are left untouched (NULL).
    let wpath = to_wide_path(dir)?;
    // SAFETY: `wpath` is NUL-terminated UTF-16; `new_acl` is a valid ACL
    // pointer returned by `SetEntriesInAclW`.
    let rc = unsafe {
        set_named(
            PCWSTR(wpath.as_ptr()),
            SE_FILE_OBJECT_VAL,
            DACL_SECURITY_INFORMATION_VAL,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            new_acl,
            core::ptr::null(),
        )
    };
    if rc != 0 {
        bail!(
            "SetNamedSecurityInfoW({}) returned 0x{:08x}",
            dir.display(),
            rc
        );
    }
    Ok(())
}

/// RAII guard that `LocalFree`s a pointer returned by Win32.
struct LocalPtr(*mut c_void);
impl Drop for LocalPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was returned by `SetEntriesInAclW`, which
            // documents that the caller must release it via `LocalFree`.
            unsafe {
                let _ = LocalFree(HLOCAL(self.0));
            }
        }
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

fn to_wide_path(p: &Path) -> Result<Vec<u16>> {
    let s = p
        .to_str()
        .ok_or_else(|| anyhow!("install dir path is not valid UTF-8: {}", p.display()))?;
    Ok(to_wide(s))
}
