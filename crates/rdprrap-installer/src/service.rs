//! Minimal SCM helpers — stop / start the TermService shared host so the
//! wrapper ServiceDll is picked up.
//!
//! Also exposes cohort-aware restart (H1) and a lightweight dependency probe
//! (H4) that mirror the CheckTermsrvDependencies / restart logic in the
//! upstream Delphi `RDPWInst.dpr`.
//!
//! The cohort implementation deliberately scopes itself to a curated list of
//! well-known siblings (`UmRdpService`, `SessionEnv`) rather than enumerating
//! every netsvcs service via `EnumServicesStatusExW`. Upstream rdpwrap's
//! original restart logic was scoped to precisely this set and a broader
//! enumeration would (a) require a further Cargo feature on `windows-rs` for
//! the enumerate APIs and (b) risk bouncing unrelated critical services (for
//! example `DHCP`, `EventLog`, `LSM`) that also live on the netsvcs host.
//! If a future operator asks for the full walk we can add it behind a flag.

use anyhow::{anyhow, Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{GetLastError, ERROR_ACCESS_DENIED, ERROR_SERVICE_NOT_ACTIVE};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
    QueryServiceStatus, StartServiceW, QUERY_SERVICE_CONFIGW, SC_HANDLE, SC_MANAGER_CONNECT,
    SERVICE_CONTROL_STOP, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_START, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED, SERVICE_STOP_PENDING,
};

/// Service name used by the Windows Terminal Services host.
pub const TERMSERVICE: &str = "TermService";

/// svchost group that TermService lives in on every supported Windows release.
///
/// The original upstream cohort restart logic walked HKLM\..\Svchost\<group>
/// for sibling services; we use the ImagePath substring `-k netsvcs` as an
/// equivalent, feature-gate-free check.
pub const NETSVCS_GROUP: &str = "netsvcs";
/// Substring we look for inside `QueryServiceConfigW().lpBinaryPathName` to
/// identify a service that shares the same svchost host as TermService.
pub const NETSVCS_IMAGEPATH_MARKER: &str = "-k netsvcs";

/// Service names we know belong to the TermService cohort and which we will
/// unconditionally leave alone even if their ImagePath happens to match the
/// netsvcs marker (these are either TermService itself, its published
/// dependencies, or services that must stay up during our SCM transaction).
///
/// `UmRdpService` is the per-session USB / mass-storage redirection side-car
/// (the `umwrap.dll` wrapper target). `SessionEnv` is TermService's session-
/// environment broker. Restarting either out from under a signed-in user
/// severs their redirected devices before the TermService restart has a
/// chance to re-establish them — so we stop *them* first (if running) and
/// restart them alongside TermService in `restart_termservice_with_cohort`.
pub const KNOWN_COHORT_SIBLINGS: &[&str] = &["UmRdpService", "SessionEnv"];

/// Stop TermService (best-effort — returns Ok even if already stopped).
pub fn stop_termservice() -> Result<()> {
    let scm = ScmHandle::open(SC_MANAGER_CONNECT)?;
    let svc = ServiceHandle::open(&scm, TERMSERVICE, SERVICE_STOP | SERVICE_QUERY_STATUS)?;

    let mut status = SERVICE_STATUS::default();
    // SAFETY: `svc.0` is a valid handle; `status` is a writable local.
    let rc = unsafe { QueryServiceStatus(svc.0, &mut status) };
    rc.context("QueryServiceStatus(TermService)")?;

    if status.dwCurrentState == SERVICE_STOPPED {
        return Ok(());
    }

    let mut status_ctl = SERVICE_STATUS::default();
    // SAFETY: `svc.0` is valid; `status_ctl` is a writable local.
    let rc = unsafe { ControlService(svc.0, SERVICE_CONTROL_STOP, &mut status_ctl) };
    // M2: distinguish real failures from benign "already stopped" or a brief
    // "still pending" transient. We propagate ACCESS_DENIED so the caller
    // knows elevation / ACL config is wrong; we log+continue on anything else
    // because the polling loop below will still catch a successful stop.
    if let Err(e) = rc {
        // SAFETY: `GetLastError` has no preconditions.
        let err = unsafe { GetLastError() };
        if err == ERROR_SERVICE_NOT_ACTIVE {
            return Ok(());
        }
        if err == ERROR_ACCESS_DENIED {
            return Err(anyhow!(
                "ControlService(TermService, STOP) denied (0x{:08x}) — \
                 installer needs SERVICE_STOP access. {e}",
                err.0
            ));
        }
        eprintln!(
            "rdprrap-installer: ControlService(STOP) returned 0x{:08x} ({e}); \
             polling for stop anyway",
            err.0
        );
    }

    // Poll for up to ~15 seconds for SERVICE_STOPPED.
    for _ in 0..30 {
        // SAFETY: `svc.0` is valid; `status` is a writable local.
        let _ = unsafe { QueryServiceStatus(svc.0, &mut status) };
        if status.dwCurrentState == SERVICE_STOPPED {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    if status.dwCurrentState == SERVICE_STOP_PENDING {
        Err(anyhow!("TermService stop did not complete within 15s"))
    } else {
        Err(anyhow!(
            "TermService stop failed — current state = {:?}",
            status.dwCurrentState
        ))
    }
}

/// Start TermService.
pub fn start_termservice() -> Result<()> {
    let scm = ScmHandle::open(SC_MANAGER_CONNECT)?;
    let svc = ServiceHandle::open(&scm, TERMSERVICE, SERVICE_START | SERVICE_QUERY_STATUS)?;
    // SAFETY: `svc.0` is a valid service handle; we pass no argv.
    let rc = unsafe { StartServiceW(svc.0, None) };
    rc.context("StartServiceW(TermService)")
}

struct ScmHandle(SC_HANDLE);

impl ScmHandle {
    fn open(access: u32) -> Result<Self> {
        // SAFETY: Both PCWSTR params are null per the "local machine / default
        // database" contract. `access` is a documented mask.
        let h = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access) }
            .context("OpenSCManagerW failed")?;
        Ok(Self(h))
    }
}

impl Drop for ScmHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` is owned and not used after drop.
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
            // SAFETY: `self.0` is owned and not used after drop.
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

/// Convert a NUL-terminated UTF-16 pointer to an owned `String`.
///
/// Returns the empty string for NULL; stops at the first NUL or after
/// `cap` u16 code units (defensive).
///
/// # Safety
/// `p` must either be NULL or point to a NUL-terminated UTF-16 sequence,
/// OR a sequence at least `cap` u16 code units long. The memory must remain
/// live for the duration of this call.
unsafe fn wide_ptr_to_string(p: *const u16, cap: usize) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while len < cap {
        // SAFETY: caller guarantees either NUL-termination before `cap` or
        // validity out to `cap` u16s. `read_unaligned` is defence-in-depth
        // against callers passing an odd-aligned pointer (for example when
        // the multi-string sits at an offset that does not meet u16 alignment
        // inside a byte buffer).
        let v = unsafe { core::ptr::read_unaligned(p.add(len)) };
        if v == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: `p..p+len` is readable per above.
    let slice = unsafe { core::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(slice)
}

/// Return the subset of `KNOWN_COHORT_SIBLINGS` whose current ImagePath on
/// the local SCM contains the `-k <group_name>` marker — i.e. the subset
/// that actually shares one svchost instance with TermService on this host.
///
/// Any sibling whose SCM config cannot be read (because the service does not
/// exist on this SKU, or because it lives under a different svchost group
/// such as `termsvcs` on Windows 10 1803+) is silently skipped.
///
/// Returns an empty Vec (not Err) if the SCM probe fails for any reason —
/// callers treat an empty list as "no cohort siblings detected, restart
/// TermService alone".
pub fn enumerate_cohort_services(group_name: &str) -> Result<Vec<String>> {
    let scm = match ScmHandle::open(SC_MANAGER_CONNECT) {
        Ok(s) => s,
        Err(_) => return Ok(Vec::new()),
    };
    let marker = format!("-k {group_name}").to_ascii_lowercase();
    let mut result = Vec::new();
    for name in KNOWN_COHORT_SIBLINGS {
        let image_path = match query_service_image_path(&scm, name) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if image_path.to_ascii_lowercase().contains(&marker) {
            result.push((*name).to_string());
        }
    }
    Ok(result)
}

/// Read the `lpBinaryPathName` (ImagePath) of a service via `QueryServiceConfigW`.
fn query_service_image_path(scm: &ScmHandle, name: &str) -> Result<String> {
    let svc = ServiceHandle::open(scm, name, SERVICE_QUERY_CONFIG)?;

    // Size-probe call with a null buffer.
    let mut needed: u32 = 0;
    // SAFETY: `svc.0` is a valid handle; `needed` is a writable out-param.
    let _ = unsafe { QueryServiceConfigW(svc.0, None, 0, &mut needed) };
    if needed == 0 {
        return Ok(String::new());
    }
    let mut buf = vec![0u8; needed as usize];
    let mut needed2: u32 = 0;
    let lpcfg = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
    // SAFETY: `buf` has `needed` writable bytes; `lpcfg` aliases its head.
    let rc = unsafe { QueryServiceConfigW(svc.0, Some(lpcfg), needed, &mut needed2) };
    if rc.is_err() {
        return Ok(String::new());
    }
    // SAFETY: `lpcfg` points to a valid struct inside `buf`; its
    // `lpBinaryPathName` is a NUL-terminated UTF-16 pointer into `buf`.
    let cfg = unsafe { core::ptr::read_unaligned(lpcfg) };
    // SAFETY: `cfg.lpBinaryPathName` points into `buf` and remains valid
    // while `buf` is alive.
    let path = unsafe { wide_ptr_to_string(cfg.lpBinaryPathName.as_ptr(), 4096) };
    Ok(path)
}

/// Read the `DependOnService` multi-string out of `QueryServiceConfigW` for
/// `name`. Each NUL-separated entry is returned as a single `String`; the
/// final empty-string terminator is stripped.
pub fn query_service_dependencies(name: &str) -> Result<Vec<String>> {
    let scm = ScmHandle::open(SC_MANAGER_CONNECT)?;
    let svc = ServiceHandle::open(&scm, name, SERVICE_QUERY_CONFIG)?;

    let mut needed: u32 = 0;
    // SAFETY: `svc.0` is valid; `needed` is writable.
    let _ = unsafe { QueryServiceConfigW(svc.0, None, 0, &mut needed) };
    if needed == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; needed as usize];
    let mut needed2: u32 = 0;
    let lpcfg = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
    // SAFETY: `buf` has `needed` writable bytes; `lpcfg` aliases head.
    let rc = unsafe { QueryServiceConfigW(svc.0, Some(lpcfg), needed, &mut needed2) };
    rc.with_context(|| format!("QueryServiceConfigW({name})"))?;
    // The dependency multi-string lives inside `buf`, so its total wide-char
    // footprint cannot exceed `needed / 2` u16 code units. This is the ONLY
    // hard upper bound we validate every cursor advance against below — the
    // old soft `DEPENDS_CAP_U16 = 16 * 1024` ceiling has been removed because
    // it was a guess that happened to be larger than any realistic SCM reply
    // but smaller than a maliciously-crafted one; the real buffer length
    // returned by `QueryServiceConfigW` is the authoritative bound.
    let buf_u16_cap = (needed as usize) / 2;
    // SAFETY: `lpcfg` points to a valid struct inside `buf`.
    let cfg = unsafe { core::ptr::read_unaligned(lpcfg) };
    if cfg.lpDependencies.is_null() {
        return Ok(Vec::new());
    }
    // `lpDependencies` is a double-NUL-terminated sequence of NUL-terminated
    // wide strings. Walk it carefully with an upper bound.
    let mut out = Vec::new();
    let mut cursor = cfg.lpDependencies.as_ptr();
    let mut total: usize = 0;
    loop {
        if cursor.is_null() || total >= buf_u16_cap {
            break;
        }
        // SAFETY: cursor points inside `buf` per QueryServiceConfigW contract,
        // and `total < buf_u16_cap` was just verified so the one-u16 read is
        // in-bounds. `read_unaligned` guards against unaligned multi-string
        // placement inside the byte buffer.
        let first = unsafe { core::ptr::read_unaligned(cursor) };
        if first == 0 {
            break; // double-NUL terminator
        }
        // Cap passed to `wide_ptr_to_string` is bounded by the remaining
        // in-buffer u16 budget so a missing NUL terminator can never read past
        // the end of `buf`.
        let remaining = buf_u16_cap - total;
        // SAFETY: see above; consume one NUL-terminated chunk up to a cap.
        let s = unsafe { wide_ptr_to_string(cursor, remaining.min(1024)) };
        let len = s.encode_utf16().count();
        if s.is_empty() {
            break;
        }
        // Advance past the chunk + NUL only if doing so stays inside the
        // original buffer. Without this hard-bound check a malformed or
        // maliciously-constructed SCM response could otherwise let `cursor`
        // walk past `buf` on the next iteration.
        if total + len + 1 > buf_u16_cap {
            break;
        }
        out.push(s);
        // Advance past the chunk + NUL.
        // SAFETY: `cursor + (len + 1)` is bounded by `buf_u16_cap` per the
        // check immediately above, so the resulting pointer stays within
        // `buf` — which backs the entire multi-string per
        // `QueryServiceConfigW`'s contract.
        cursor = unsafe { cursor.add(len + 1) };
        total += len + 1;
    }
    Ok(out)
}

/// Return the list of `TermService` declared dependencies that are NOT
/// currently present on the host SCM. Used by install as a soft preflight
/// (H4 / CheckTermsrvDependencies): a missing dependency will not block the
/// install, but we surface it to the operator because a broken dependency
/// graph prevents TermService from starting.
pub fn check_termsrv_dependencies() -> Result<Vec<String>> {
    let deps = match query_service_dependencies(TERMSERVICE) {
        Ok(d) => d,
        Err(_) => return Ok(Vec::new()),
    };
    if deps.is_empty() {
        return Ok(Vec::new());
    }
    let scm = ScmHandle::open(SC_MANAGER_CONNECT)?;
    let mut missing = Vec::new();
    for dep in deps {
        // Dependency names prefixed by "+" designate a load-order group, not
        // a service; we skip those — the SCM resolves them implicitly and
        // absence is normal.
        if dep.starts_with('+') {
            continue;
        }
        if ServiceHandle::open(&scm, &dep, SERVICE_QUERY_STATUS).is_err() {
            missing.push(dep);
        }
    }
    Ok(missing)
}

/// Stop a named service best-effort — returns `Ok(())` if it is already
/// stopped, if the service does not exist, or if the stop completes within
/// ~15 s. Any other outcome propagates.
fn stop_named_service(name: &str) -> Result<()> {
    let scm = ScmHandle::open(SC_MANAGER_CONNECT)?;
    let svc = match ServiceHandle::open(&scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS) {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };

    let mut status = SERVICE_STATUS::default();
    // SAFETY: `svc.0` is valid; `status` is writable.
    let rc = unsafe { QueryServiceStatus(svc.0, &mut status) };
    if rc.is_err() {
        return Ok(());
    }
    if status.dwCurrentState == SERVICE_STOPPED {
        return Ok(());
    }

    let mut status_ctl = SERVICE_STATUS::default();
    // SAFETY: `svc.0` is valid; `status_ctl` is writable.
    let rc = unsafe { ControlService(svc.0, SERVICE_CONTROL_STOP, &mut status_ctl) };
    if rc.is_err() {
        // Already stopped / transient — poll below.
        // SAFETY: `GetLastError` has no preconditions.
        let err = unsafe { GetLastError() };
        if err == ERROR_SERVICE_NOT_ACTIVE {
            return Ok(());
        }
    }

    for _ in 0..30 {
        // SAFETY: `svc.0` is valid; `status` is writable.
        let _ = unsafe { QueryServiceStatus(svc.0, &mut status) };
        if status.dwCurrentState == SERVICE_STOPPED {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Ok(())
}

/// Start a named service best-effort — tolerates "already running" / "does not exist".
fn start_named_service(name: &str) -> Result<()> {
    let scm = ScmHandle::open(SC_MANAGER_CONNECT)?;
    let svc = match ServiceHandle::open(&scm, name, SERVICE_START | SERVICE_QUERY_STATUS) {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };
    // SAFETY: `svc.0` is valid; argv passed as None.
    let rc = unsafe { StartServiceW(svc.0, None) };
    let _ = rc;
    // Poll until running (best-effort).
    let mut status = SERVICE_STATUS::default();
    for _ in 0..20 {
        // SAFETY: `svc.0` is valid; `status` is writable.
        let _ = unsafe { QueryServiceStatus(svc.0, &mut status) };
        if status.dwCurrentState == SERVICE_RUNNING {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Ok(())
}

/// Restart TermService along with any cohort services that share its svchost
/// host ("-k netsvcs"). Cohort stops/starts are best-effort — we warn on
/// failure but never block the TermService restart (which is the load-
/// bearing part of the install).
pub fn restart_termservice_with_cohort() -> Result<()> {
    // Enumerate cohort before we stop anything so we have a stable pre-list.
    let cohort = match enumerate_cohort_services(NETSVCS_GROUP) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "rdprrap-installer: cohort enumeration failed ({e}); \
                 restarting TermService alone"
            );
            Vec::new()
        }
    };
    // Include well-known siblings that may not be running right now (and
    // thus not show up in the active enumeration) — they still need a
    // restart if they were stopped mid-transaction.
    let mut merged: Vec<String> = cohort;
    for known in KNOWN_COHORT_SIBLINGS {
        if !merged.iter().any(|s| s.eq_ignore_ascii_case(known)) {
            merged.push((*known).to_string());
        }
    }

    // Stop cohort first (best-effort), then stop + start TermService, then
    // start cohort back up. This mirrors upstream's "shut the whole svchost
    // down, patch, restart it" sequence without relying on
    // TerminateProcess(svchost) which is heavier.
    for name in &merged {
        if let Err(e) = stop_named_service(name) {
            eprintln!("rdprrap-installer: cohort stop of {name} returned {e} (continuing)");
        }
    }

    println!("rdprrap-installer: stopping TermService...");
    match stop_termservice() {
        Ok(()) => println!("rdprrap-installer: TermService stopped"),
        Err(e) => println!(
            "rdprrap-installer: TermService stop returned: {e} (continuing; starting anyway)"
        ),
    }
    println!("rdprrap-installer: starting TermService...");
    start_termservice().context("failed to start TermService")?;
    println!("rdprrap-installer: TermService running");

    for name in &merged {
        if let Err(e) = start_named_service(name) {
            eprintln!("rdprrap-installer: cohort start of {name} returned {e} (continuing)");
        }
    }
    Ok(())
}
