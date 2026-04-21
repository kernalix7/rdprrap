#[cfg(windows)]
mod patches;
#[cfg(windows)]
mod thread;

// The x86 function-body walker is pure-Rust / host-safe and is exercised by
// unit tests on any host. `patches.rs` pulls it in only on Windows x86.
#[cfg(any(all(windows, target_arch = "x86"), test))]
mod x86_walk;

#[cfg(windows)]
use core::ffi::c_void;
#[cfg(windows)]
use std::sync::OnceLock;
#[cfg(windows)]
use windows::core::{w, PCSTR};
#[cfg(windows)]
use windows::Win32::Foundation::{FreeLibrary, BOOL, FALSE, HMODULE, TRUE};
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::LOAD_LIBRARY_SEARCH_SYSTEM32;
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW};
#[cfg(windows)]
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

// rdpendp.dll export types
#[cfg(windows)]
type GetTSAudioEndpointFn = unsafe extern "system" fn(u32, *mut *mut std::ffi::c_void) -> i32;
#[cfg(windows)]
type DllGetClassObjectFn = unsafe extern "system" fn(
    *const windows::core::GUID,
    *const windows::core::GUID,
    *mut *mut std::ffi::c_void,
) -> i32;
#[cfg(windows)]
type DllCanUnloadNowFn = unsafe extern "system" fn() -> i32;

// NOTE: HMODULE wraps `*mut c_void` and thus is not automatically `Send + Sync`,
// which `OnceLock<T>` requires. Store as `usize` and reconstruct the HMODULE on
// read. Module handles are process-wide identifiers in Windows, so round-tripping
// through `usize` preserves their meaning.
#[cfg(windows)]
static ORIGINAL_MODULE: OnceLock<usize> = OnceLock::new();
#[cfg(windows)]
static GET_TS_AUDIO: OnceLock<GetTSAudioEndpointFn> = OnceLock::new();
#[cfg(windows)]
static DLL_GET_CLASS_OBJECT: OnceLock<DllGetClassObjectFn> = OnceLock::new();
#[cfg(windows)]
static DLL_CAN_UNLOAD_NOW: OnceLock<DllCanUnloadNowFn> = OnceLock::new();

/// Exported: GetTSAudioEndpointEnumeratorForSession — forwarded to rdpendp.dll
///
/// # Safety
/// Called by the OS audio subsystem with a valid session id and output pointer;
/// the arguments are simply forwarded to the original rdpendp.dll export.
#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetTSAudioEndpointEnumeratorForSession(
    session_id: u32,
    enumerator: *mut *mut std::ffi::c_void,
) -> i32 {
    if let Some(func) = GET_TS_AUDIO.get() {
        // SAFETY: forwarding call with same arguments to original function
        unsafe { func(session_id, enumerator) }
    } else {
        -1 // E_FAIL
    }
}

/// Exported: DllGetClassObject — forwarded to rdpendp.dll
///
/// # Safety
/// Called by COM with valid CLSID/IID pointers and an output pointer. All
/// arguments are forwarded to the original rdpendp.dll export unchanged.
#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const windows::core::GUID,
    riid: *const windows::core::GUID,
    ppv: *mut *mut std::ffi::c_void,
) -> i32 {
    if let Some(func) = DLL_GET_CLASS_OBJECT.get() {
        // SAFETY: forwarding call with same arguments to original function
        unsafe { func(rclsid, riid, ppv) }
    } else {
        0x80040111_u32 as i32 // CLASS_E_CLASSNOTAVAILABLE
    }
}

/// Exported: DllCanUnloadNow — forwarded to rdpendp.dll
///
/// # Safety
/// Called by COM to query whether the DLL can be unloaded. The call is
/// forwarded to the original rdpendp.dll export.
#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllCanUnloadNow() -> i32 {
    if let Some(func) = DLL_CAN_UNLOAD_NOW.get() {
        // SAFETY: forwarding call with same arguments to original function
        unsafe { func() }
    } else {
        1 // S_FALSE
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
    let hmod = unsafe { LoadLibraryExW(w!("rdpendp.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32) };

    let hmod = match hmod {
        Ok(h) => h,
        Err(_) => return FALSE,
    };

    // SAFETY: GetProcAddress on a validly loaded module
    let get_ts = unsafe {
        GetProcAddress(
            hmod,
            PCSTR(c"GetTSAudioEndpointEnumeratorForSession".as_ptr() as *const u8),
        )
    };
    // SAFETY: GetProcAddress on a validly loaded module
    let get_class =
        unsafe { GetProcAddress(hmod, PCSTR(c"DllGetClassObject".as_ptr() as *const u8)) };
    // SAFETY: GetProcAddress on a validly loaded module
    let can_unload =
        unsafe { GetProcAddress(hmod, PCSTR(c"DllCanUnloadNow".as_ptr() as *const u8)) };

    if let Some(f) = get_ts {
        // SAFETY: FARPROC from GetProcAddress matches GetTSAudioEndpointFn signature
        let _ = GET_TS_AUDIO.set(unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, GetTSAudioEndpointFn>(f)
        });
    }
    if let Some(f) = get_class {
        // SAFETY: FARPROC from GetProcAddress matches DllGetClassObjectFn signature
        let _ = DLL_GET_CLASS_OBJECT.set(unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, DllGetClassObjectFn>(f)
        });
    }
    if let Some(f) = can_unload {
        // SAFETY: FARPROC from GetProcAddress matches DllCanUnloadNowFn signature
        let _ = DLL_CAN_UNLOAD_NOW.set(unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, DllCanUnloadNowFn>(f)
        });
    }

    let _ = ORIGINAL_MODULE.set(hmod.0 as usize);

    // Suspend threads, apply patches, resume
    thread::set_threads_state(false);
    patches::apply_patches(hmod);
    thread::set_threads_state(true);

    TRUE
}

#[cfg(windows)]
unsafe fn dll_detach() -> BOOL {
    if let Some(&raw) = ORIGINAL_MODULE.get() {
        // SAFETY: reconstructing the HMODULE we stored as usize, and freeing the
        // library we loaded in dll_attach. The handle is only used inside this
        // detach path and is valid as long as the module is loaded.
        let hmod = HMODULE(raw as *mut c_void);
        unsafe {
            FreeLibrary(hmod).ok();
        }
    }
    TRUE
}

#[cfg(not(windows))]
pub fn _placeholder() {}
