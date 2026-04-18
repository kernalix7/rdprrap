#[cfg(windows)]
mod patches;
#[cfg(windows)]
mod thread;

#[cfg(windows)]
use std::sync::OnceLock;
#[cfg(windows)]
use windows::core::{w, PCSTR};
#[cfg(windows)]
use windows::Win32::Foundation::{BOOL, FALSE, HMODULE, TRUE};
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::LOAD_LIBRARY_SEARCH_SYSTEM32;
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW};
#[cfg(windows)]
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

#[cfg(windows)]
type ServiceMainFn = unsafe extern "system" fn(u32, *mut *mut u16);
#[cfg(windows)]
type SvchostPushFn = unsafe extern "system" fn(*mut std::ffi::c_void);

// NOTE: HMODULE wraps `*mut c_void` and thus is not automatically `Send + Sync`,
// which `OnceLock<T>` requires. Store as `usize` and reconstruct the HMODULE on
// read. Module handles are process-wide identifiers in Windows, so round-tripping
// through `usize` preserves their meaning.
#[cfg(windows)]
static ORIGINAL_MODULE: OnceLock<usize> = OnceLock::new();
#[cfg(windows)]
static SERVICE_MAIN: OnceLock<ServiceMainFn> = OnceLock::new();
#[cfg(windows)]
static SVCHOST_PUSH: OnceLock<SvchostPushFn> = OnceLock::new();

/// Exported: ServiceMain — forwarded to the original termsrv.dll
///
/// # Safety
/// Called by the Windows Service Control Manager with valid `argc`/`argv`
/// matching the standard Unicode service entry-point contract.
#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn ServiceMain(argc: u32, argv: *mut *mut u16) {
    if let Some(func) = SERVICE_MAIN.get() {
        // SAFETY: forwarding call with same arguments to original function
        unsafe { func(argc, argv) };
    }
}

/// Exported: SvchostPushServiceGlobals — forwarded to the original termsrv.dll
///
/// # Safety
/// Called by svchost.exe with a valid pointer to the shared-service globals
/// structure. The pointer is simply forwarded to the original termsrv.dll.
#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SvchostPushServiceGlobals(data: *mut std::ffi::c_void) {
    if let Some(func) = SVCHOST_PUSH.get() {
        // SAFETY: forwarding call with same arguments to original function
        unsafe { func(data) };
    }
}

/// DllMain entry point
///
/// # Safety
/// Called by the Windows loader under the loader lock with standard DllMain
/// arguments. Must only perform loader-safe work during PROCESS_ATTACH/DETACH.
#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _instance: HMODULE,
    reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => unsafe { dll_attach() },
        DLL_PROCESS_DETACH => unsafe { dll_detach() },
        _ => TRUE,
    }
}

#[cfg(windows)]
unsafe fn dll_attach() -> BOOL {
    // SAFETY: Loading termsrv.dll from the system directory only
    let hmod = unsafe { LoadLibraryExW(w!("termsrv.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32) };

    let hmod = match hmod {
        Ok(h) => h,
        Err(_) => return FALSE,
    };

    // SAFETY: GetProcAddress on a validly loaded module
    let service_main = unsafe { GetProcAddress(hmod, PCSTR(c"ServiceMain".as_ptr() as *const u8)) };
    let svchost_push = unsafe {
        GetProcAddress(
            hmod,
            PCSTR(c"SvchostPushServiceGlobals".as_ptr() as *const u8),
        )
    };

    if let Some(f) = service_main {
        // SAFETY: GetProcAddress returned a non-null pointer to the original
        // termsrv.dll export, whose ABI matches ServiceMainFn (verified by the
        // termsrv.dll contract).
        let _ = SERVICE_MAIN.set(unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, ServiceMainFn>(f)
        });
    }
    if let Some(f) = svchost_push {
        // SAFETY: same reasoning as above — matches SvchostPushFn ABI.
        let _ = SVCHOST_PUSH.set(unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, SvchostPushFn>(f)
        });
    }

    let _ = ORIGINAL_MODULE.set(hmod.0 as usize);

    // Suspend all other threads, apply patches, resume
    unsafe {
        thread::set_threads_state(false);
        patches::apply_patches(hmod);
        thread::set_threads_state(true);
    }

    TRUE
}

#[cfg(windows)]
unsafe fn dll_detach() -> BOOL {
    if let Some(&raw) = ORIGINAL_MODULE.get() {
        // SAFETY: reconstructing the HMODULE we stored as usize, and freeing the
        // library we loaded in dll_attach. The handle is only used inside this
        // detach path and is valid as long as the module is loaded.
        let hmod = HMODULE(raw as *mut std::ffi::c_void);
        unsafe {
            windows::Win32::Foundation::FreeLibrary(hmod).ok();
        }
    }
    TRUE
}

// Non-Windows stub so the crate compiles on Linux for development
#[cfg(not(windows))]
pub fn _placeholder() {}
