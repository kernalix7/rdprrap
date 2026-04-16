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

#[cfg(windows)]
static ORIGINAL_MODULE: OnceLock<HMODULE> = OnceLock::new();
#[cfg(windows)]
static GET_TS_AUDIO: OnceLock<GetTSAudioEndpointFn> = OnceLock::new();
#[cfg(windows)]
static DLL_GET_CLASS_OBJECT: OnceLock<DllGetClassObjectFn> = OnceLock::new();
#[cfg(windows)]
static DLL_CAN_UNLOAD_NOW: OnceLock<DllCanUnloadNowFn> = OnceLock::new();

#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetTSAudioEndpointEnumeratorForSession(
    session_id: u32,
    enumerator: *mut *mut std::ffi::c_void,
) -> i32 {
    if let Some(func) = GET_TS_AUDIO.get() {
        unsafe { func(session_id, enumerator) }
    } else {
        -1 // E_FAIL
    }
}

#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const windows::core::GUID,
    riid: *const windows::core::GUID,
    ppv: *mut *mut std::ffi::c_void,
) -> i32 {
    if let Some(func) = DLL_GET_CLASS_OBJECT.get() {
        unsafe { func(rclsid, riid, ppv) }
    } else {
        0x80040111_u32 as i32 // CLASS_E_CLASSNOTAVAILABLE
    }
}

#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllCanUnloadNow() -> i32 {
    if let Some(func) = DLL_CAN_UNLOAD_NOW.get() {
        unsafe { func() }
    } else {
        1 // S_FALSE
    }
}

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

    let get_ts = unsafe {
        GetProcAddress(
            hmod,
            PCSTR(b"GetTSAudioEndpointEnumeratorForSession\0".as_ptr()),
        )
    };
    let get_class = unsafe { GetProcAddress(hmod, PCSTR(b"DllGetClassObject\0".as_ptr())) };
    let can_unload = unsafe { GetProcAddress(hmod, PCSTR(b"DllCanUnloadNow\0".as_ptr())) };

    if let Some(f) = get_ts {
        // SAFETY: FARPROC from GetProcAddress matches GetTSAudioEndpointFn signature
        let _ = GET_TS_AUDIO.set(unsafe { std::mem::transmute(f) });
    }
    if let Some(f) = get_class {
        // SAFETY: FARPROC from GetProcAddress matches DllGetClassObjectFn signature
        let _ = DLL_GET_CLASS_OBJECT.set(unsafe { std::mem::transmute(f) });
    }
    if let Some(f) = can_unload {
        // SAFETY: FARPROC from GetProcAddress matches DllCanUnloadNowFn signature
        let _ = DLL_CAN_UNLOAD_NOW.set(unsafe { std::mem::transmute(f) });
    }

    let _ = ORIGINAL_MODULE.set(hmod);

    // Suspend threads, apply patches, resume
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
