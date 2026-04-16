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

#[cfg(windows)]
static ORIGINAL_MODULE: OnceLock<HMODULE> = OnceLock::new();
#[cfg(windows)]
static SERVICE_MAIN: OnceLock<ServiceMainFn> = OnceLock::new();
#[cfg(windows)]
static SVCHOST_PUSH: OnceLock<SvchostPushFn> = OnceLock::new();

/// Exported: ServiceMain — forwarded to the original termsrv.dll
#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn ServiceMain(argc: u32, argv: *mut *mut u16) {
    if let Some(func) = SERVICE_MAIN.get() {
        // SAFETY: forwarding call with same arguments to original function
        unsafe { func(argc, argv) };
    }
}

/// Exported: SvchostPushServiceGlobals — forwarded to the original termsrv.dll
#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SvchostPushServiceGlobals(data: *mut std::ffi::c_void) {
    if let Some(func) = SVCHOST_PUSH.get() {
        // SAFETY: forwarding call with same arguments to original function
        unsafe { func(data) };
    }
}

/// DllMain entry point
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
    let service_main = unsafe { GetProcAddress(hmod, PCSTR(b"ServiceMain\0".as_ptr())) };
    let svchost_push =
        unsafe { GetProcAddress(hmod, PCSTR(b"SvchostPushServiceGlobals\0".as_ptr())) };

    if let Some(f) = service_main {
        let _ = SERVICE_MAIN.set(unsafe { std::mem::transmute(f) });
    }
    if let Some(f) = svchost_push {
        let _ = SVCHOST_PUSH.set(unsafe { std::mem::transmute(f) });
    }

    let _ = ORIGINAL_MODULE.set(hmod);

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
    if let Some(&hmod) = ORIGINAL_MODULE.get() {
        // SAFETY: freeing the library we loaded
        unsafe {
            windows::Win32::System::LibraryLoader::FreeLibrary(hmod).ok();
        }
    }
    TRUE
}

// Non-Windows stub so the crate compiles on Linux for development
#[cfg(not(windows))]
pub fn _placeholder() {}
