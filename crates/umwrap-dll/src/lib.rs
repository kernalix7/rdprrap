#[cfg(windows)]
mod patches;
#[cfg(windows)]
mod thread;

#[cfg(windows)]
use std::sync::OnceLock;
#[cfg(windows)]
use windows::core::w;
#[cfg(windows)]
use windows::Win32::Foundation::{BOOL, FALSE, HMODULE, TRUE};
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::LoadLibraryExW;
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::LOAD_LIBRARY_SEARCH_SYSTEM32;
#[cfg(windows)]
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

#[cfg(windows)]
static ORIGINAL_MODULE: OnceLock<HMODULE> = OnceLock::new();

// umrdp.dll is a device redirection DLL (not a service DLL),
// so it does not export ServiceMain or SvchostPushServiceGlobals.
// The wrapper only needs DllMain to load the original and apply patches.

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
    // SAFETY: Loading umrdp.dll from system directory
    let hmod = unsafe { LoadLibraryExW(w!("umrdp.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32) };

    let hmod = match hmod {
        Ok(h) => h,
        Err(_) => return FALSE,
    };

    let _ = ORIGINAL_MODULE.set(hmod);

    // Suspend threads, apply patches, resume
    // SAFETY: We are in DLL_PROCESS_ATTACH; suspending other threads is safe here
    thread::set_threads_state(false);
    patches::apply_patches(hmod);
    thread::set_threads_state(true);

    TRUE
}

#[cfg(windows)]
unsafe fn dll_detach() -> BOOL {
    if let Some(&hmod) = ORIGINAL_MODULE.get() {
        unsafe {
            windows::Win32::System::LibraryLoader::FreeLibrary(hmod).ok();
        }
    }
    TRUE
}

#[cfg(not(windows))]
pub fn _placeholder() {}
