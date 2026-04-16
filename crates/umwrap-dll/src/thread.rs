use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread,
    THREAD_SUSPEND_RESUME,
};

/// Suspend or resume all threads in the current process except the calling thread.
///
/// This is critical for safe in-memory patching: we must ensure no thread is
/// executing the code we're about to modify.
///
/// # Safety
/// - Must be called from a context where suspending/resuming threads is safe
/// - Caller must ensure patches are applied between suspend and resume calls
pub unsafe fn set_threads_state(resume: bool) {
    let current_thread = unsafe { GetCurrentThreadId() };
    let current_process = unsafe { GetCurrentProcessId() };

    // SAFETY: Creating a snapshot of all threads in the system
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    let snapshot = match snapshot {
        Ok(h) => h,
        Err(_) => return,
    };

    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    // SAFETY: entry is properly initialized with dwSize
    if unsafe { Thread32First(snapshot, &mut entry) }.is_err() {
        unsafe { CloseHandle(snapshot).ok() };
        return;
    }

    loop {
        if entry.th32ThreadID != current_thread && entry.th32OwnerProcessID == current_process {
            // SAFETY: Opening a thread in our own process
            if let Ok(thread) =
                unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) }
            {
                if resume {
                    // SAFETY: Resuming a thread we previously suspended
                    unsafe { ResumeThread(thread) };
                } else {
                    // SAFETY: Suspending a thread in our own process
                    unsafe { SuspendThread(thread) };
                }
                unsafe { CloseHandle(thread).ok() };
            }
        }

        // SAFETY: Iterating to next thread entry
        if unsafe { Thread32Next(snapshot, &mut entry) }.is_err() {
            break;
        }
    }

    unsafe { CloseHandle(snapshot).ok() };
}
