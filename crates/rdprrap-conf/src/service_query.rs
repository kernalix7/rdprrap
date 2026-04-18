//! Thin wrapper around `QueryServiceStatusEx` for the TermService host.

use anyhow::{Context, Result};
use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_CONTINUE_PENDING, SERVICE_PAUSED,
    SERVICE_PAUSE_PENDING, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS_PROCESS, SERVICE_STOPPED, SERVICE_STOP_PENDING,
};

use crate::registry::to_wide;

const TERMSERVICE: &str = "TermService";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Unknown,
    Unavailable,
}

impl ServiceState {
    pub fn label(self) -> &'static str {
        match self {
            ServiceState::Stopped => "Stopped",
            ServiceState::StartPending => "Start pending",
            ServiceState::StopPending => "Stop pending",
            ServiceState::Running => "Running",
            ServiceState::ContinuePending => "Continue pending",
            ServiceState::PausePending => "Pause pending",
            ServiceState::Paused => "Paused",
            ServiceState::Unknown => "Unknown",
            ServiceState::Unavailable => "Unavailable",
        }
    }
}

/// Query the current state of `TermService`. Never panics; errors collapse to
/// `ServiceState::Unavailable` so the UI polling loop remains robust.
pub fn query_termservice() -> ServiceState {
    query_termservice_inner().unwrap_or(ServiceState::Unavailable)
}

fn query_termservice_inner() -> Result<ServiceState> {
    let scm = ScmHandle::open(SC_MANAGER_CONNECT)?;
    let svc = ServiceHandle::open(&scm, TERMSERVICE, SERVICE_QUERY_STATUS)?;

    let mut info = SERVICE_STATUS_PROCESS::default();
    let mut bytes_needed: u32 = 0;
    let size = core::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32;
    // SAFETY: `info` is a locally-owned struct exactly `size` bytes wide; the
    // Win32 API writes into it. `bytes_needed` is a writable local.
    unsafe {
        QueryServiceStatusEx(
            svc.0,
            SC_STATUS_PROCESS_INFO,
            Some(core::slice::from_raw_parts_mut(
                &mut info as *mut _ as *mut u8,
                size as usize,
            )),
            &mut bytes_needed,
        )
    }
    .context("QueryServiceStatusEx(TermService)")?;

    Ok(match info.dwCurrentState {
        s if s == SERVICE_RUNNING => ServiceState::Running,
        s if s == SERVICE_STOPPED => ServiceState::Stopped,
        s if s == SERVICE_START_PENDING => ServiceState::StartPending,
        s if s == SERVICE_STOP_PENDING => ServiceState::StopPending,
        s if s == SERVICE_CONTINUE_PENDING => ServiceState::ContinuePending,
        s if s == SERVICE_PAUSE_PENDING => ServiceState::PausePending,
        s if s == SERVICE_PAUSED => ServiceState::Paused,
        _ => ServiceState::Unknown,
    })
}

struct ScmHandle(SC_HANDLE);
impl ScmHandle {
    fn open(access: u32) -> Result<Self> {
        // SAFETY: Both PCWSTR arguments are null as required for the local
        // machine / default database; `access` is a documented mask.
        let h = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access) }
            .context("OpenSCManagerW failed")?;
        Ok(Self(h))
    }
}
impl Drop for ScmHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: Owned handle, not used after drop.
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

struct ServiceHandle(SC_HANDLE);
impl ServiceHandle {
    fn open(scm: &ScmHandle, name: &str, access: u32) -> Result<Self> {
        let wname = to_wide(name);
        // SAFETY: `scm.0` valid; `wname` is NUL-terminated UTF-16.
        let h = unsafe { OpenServiceW(scm.0, PCWSTR(wname.as_ptr()), access) }
            .with_context(|| format!("OpenServiceW({name})"))?;
        Ok(Self(h))
    }
}
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: Owned handle, not used after drop.
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}
