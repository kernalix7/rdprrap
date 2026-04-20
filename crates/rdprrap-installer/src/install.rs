//! High-level install orchestration.
//!
//! Step-by-step:
//!
//! 1. Resolve & create `%ProgramFiles%\RDP Wrapper\` (install dir).
//! 2. Copy the three wrapper DLLs from the source directory (or the directory
//!    of the current executable) into the install directory — refusing to
//!    follow reparse points into attacker-controlled locations (H2).
//! 3. Snapshot the current `ServiceDll` value (and current `fDenyTSConnections`
//!    for accurate later restoration — H4) and persist them under the
//!    rdprrap installer state key so uninstall can restore verbatim.
//! 4. Point `ServiceDll` at the wrapper.
//! 5. Apply the multi-session registry keys + TS AddIns.
//! 6. Open TCP 3389 in the firewall (unless skipped).
//! 7. Restart `TermService` (unless skipped).
//!
//! Steps 4-6 form a transactional unit: if any of them fails we roll back to
//! the previously-recorded `ServiceDll` value (M1).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use windows::Win32::System::Registry::{KEY_READ, KEY_WRITE};

use crate::acl;
use crate::firewall;
use crate::paths;
use crate::registry::{self, keys, RegKey};
use crate::service;
use crate::version;

pub struct Options {
    pub source_dir: Option<PathBuf>,
    pub skip_firewall: bool,
    pub skip_restart: bool,
    /// If set, explicitly write `UserAuthentication=0` under `WinStations\RDP-Tcp`
    /// to disable Network-Level Authentication. Default: do NOT touch the value
    /// (matches upstream `rdpwrap`). See H3.
    pub disable_nla: bool,
    /// Proceed with install even if the preflight detects an existing rdprrap
    /// deployment under the target install dir (C2).
    pub force: bool,
}

/// Key + value under Winlogon used to cap the number of concurrent TS sessions.
/// Matches upstream `RDPWInst.dpr`'s AllowMultipleTSSessions knob (C1): setting
/// this DWORD to 1 tells Winlogon to permit parallel interactive sessions.
/// Path + value name come from `crate::contract` so the install plan and the
/// actual writer cannot drift.
use crate::contract::reg::WINLOGON as WINLOGON_KEY;
use crate::contract::values::ALLOW_MULTIPLE_TS_SESSIONS as ALLOW_MULTI_VALUE;

pub fn run(opts: Options) -> Result<()> {
    let install_dir = paths::install_dir()?;
    let source_dir = resolve_source_dir(opts.source_dir)?;

    println!("rdprrap-installer: installing to {}", install_dir.display());
    println!("rdprrap-installer: source dir    {}", source_dir.display());

    // C2: CheckInstall preflight — if our own wrapper DLL is already the
    // ServiceDll, refuse to reinstall unless --force was supplied.
    if !opts.force && check_already_installed(&install_dir)? {
        bail!(
            "rdprrap is already installed at {}. Use --force to reinstall, \
             or uninstall first.",
            install_dir.display()
        );
    }

    // H2: CheckTermsrvVersion — soft-warn when the host's termsrv.dll version
    // is outside the set upstream is known to patch. We still proceed because
    // rdprrap patches by pattern, not by hard-coded offsets.
    preflight_termsrv_version();

    // Step 1: ensure install dir exists. We create it ourselves if it is
    // missing so we know it inherits the parent's ACL (ProgramFiles ACL —
    // TrustedInstaller/SYSTEM/Admins full, Users read-only).
    let created_install_dir = !install_dir.exists();
    fs::create_dir_all(&install_dir)
        .with_context(|| format!("create_dir_all({})", install_dir.display()))?;

    // Security gate (H2): confirm the install dir is either freshly created
    // by us OR an existing directory whose parent is %ProgramFiles% (which is
    // not world-writable on a healthy Windows install).
    validate_install_dir(&install_dir, created_install_dir)?;

    // Step 2: copy DLLs. Refuse to follow reparse points on the destination.
    copy_wrapper_dlls(&source_dir, &install_dir)?;

    // H3: grant SYSTEM + LocalService read/execute on the install dir so the
    // wrapper DLL is loadable from every service account upstream rdpwrap
    // supports. Soft-fail: if the ACL write is rejected (for example on a
    // hardened SKU where only TrustedInstaller can modify ProgramFiles ACLs)
    // we log-and-continue so the install still completes.
    if let Err(e) = acl::grant_install_dir_acl(&install_dir) {
        eprintln!(
            "rdprrap-installer: WARNING: could not grant SYSTEM/LocalService \
             read+execute on {}: {e}. TermService may be unable to load the \
             wrapper. Re-run as an elevated admin or fix the ACL manually.",
            install_dir.display()
        );
    }

    // Step 3: snapshot original ServiceDll + fDenyTSConnections + AllowMulti +
    // AddIns presence, then save state.
    let original = registry::get_service_dll()?
        .unwrap_or_else(|| "%SystemRoot%\\System32\\termsrv.dll".to_string());

    // M3: validate the captured pre-install ServiceDll *before* we bake it
    // into the rollback closure. If the value we read from the registry was
    // already tampered with by an attacker-with-write-to-HKLM (e.g. pointing
    // at a UNC path, at a System32-shadow outside `%SystemRoot%\System32`,
    // or at a world-writable install dir) a failed install would otherwise
    // roll back to *that* malicious ServiceDll and load it as SYSTEM on the
    // next TermService start. Refusing up front forces the operator to
    // manually review + correct the registry before re-running install.
    //
    // Signature matches the `uninstall.rs` call site so the same validation
    // policy governs both the install-time rollback and the uninstall
    // restore paths.
    registry::validate_service_dll_path(&original, Some(&install_dir)).with_context(|| {
        format!(
            "refusing to proceed — pre-install ServiceDll value '{original}' \
                 failed validation and cannot be used as a safe rollback target"
        )
    })?;

    let prev_fdeny = read_fdeny_ts_connections()?;
    // C1: snapshot AllowMultipleTSSessions so uninstall can restore verbatim.
    let prev_allow_multi = read_allow_multi_ts_sessions()?;
    // H5: mirror upstream `RDPWInst.dpr`'s `if not Reg.KeyExists('AddIns')`
    // guard — if the Terminal Server AddIns parent key already exists, its
    // contents are not ours to modify. We record this decision so uninstall
    // knows whether it is also allowed to remove the subkeys.
    let addins_parent_existed = registry::key_exists_local_machine(keys::ADDINS_PARENT)?;
    let addins_created_by_us = !addins_parent_existed;
    registry::save_uninstall_state(
        &original,
        &install_dir,
        prev_fdeny,
        prev_allow_multi,
        addins_created_by_us,
    )?;

    // --- Begin transactional section: if any of steps 4/5/6 fails we must
    //     restore the ServiceDll to `original` so that TermService boots with
    //     the vanilla Microsoft DLL on next restart (M1).

    // Step 4: write new ServiceDll.
    let new_dll = install_dir.join(paths::SERVICE_DLL_NAME);
    registry::set_service_dll(&new_dll).context("failed to rewrite ServiceDll")?;
    println!("rdprrap-installer: ServiceDll -> {}", new_dll.display());

    let rollback = |stage: &str, e: anyhow::Error| -> anyhow::Error {
        eprintln!("rdprrap-installer: rolling back ServiceDll after {stage} failure: {e}");
        match set_service_dll_str(&original) {
            Ok(()) => eprintln!("rdprrap-installer: ServiceDll reverted to {original}"),
            Err(e2) => eprintln!("rdprrap-installer: ROLLBACK FAILED: {e2}"),
        }
        e
    };

    // Step 5: apply policy keys.
    if let Err(e) = apply_policy_keys(opts.disable_nla, addins_created_by_us) {
        return Err(rollback("policy-keys", e));
    }

    // Step 6: firewall.
    if !opts.skip_firewall {
        if let Err(e) = firewall::add_rule() {
            return Err(rollback("firewall", e));
        }
        println!("rdprrap-installer: firewall rules added (TCP+UDP 3389)");
    }

    // Step 7: restart TermService (with cohort — H1). We invoke the cohort-
    // aware variant so svchost siblings that share the `-k netsvcs` host
    // (UmRdpService, SessionEnv, …) are bounced alongside TermService. A
    // cohort failure is logged but never aborts the install — the TermService
    // restart inside `restart_termservice_with_cohort` is the load-bearing
    // part, and its own failure is surfaced via `Result`.
    if !opts.skip_restart {
        println!(
            "rdprrap-installer: restarting TermService with cohort (ImagePath \
             marker '{}')...",
            service::NETSVCS_IMAGEPATH_MARKER
        );
        if let Err(e) = service::restart_termservice_with_cohort() {
            // The cohort helper only returns Err when the TermService start
            // itself failed; cohort stop/start failures are already
            // swallowed-with-warnings inside the helper. Fall back to the
            // non-cohort restart so the operator still has a chance of
            // picking up the wrapper without a reboot.
            eprintln!(
                "rdprrap-installer: WARNING: cohort-aware restart failed: {e}. \
                 Falling back to a plain TermService restart."
            );
            restart_termservice()?;
        }
    } else {
        println!("rdprrap-installer: skipping TermService restart (requested)");
    }

    // H4: soft preflight — warn (but never block) if TermService's declared
    // dependencies are not all present on the host SCM. A broken dependency
    // graph prevents TermService from starting, so surfacing it here gives
    // the operator a concrete clue if the upcoming restart misbehaves.
    if let Ok(missing) = service::check_termsrv_dependencies() {
        if !missing.is_empty() {
            eprintln!(
                "rdprrap-installer: WARNING: TermService dependencies may be \
                 missing on this host: {missing:?}. This will not block the \
                 install, but TermService may fail to start until the missing \
                 services are restored."
            );
        }
    }

    println!("rdprrap-installer: install complete");
    Ok(())
}

pub fn status() -> Result<()> {
    println!("rdprrap-installer status");
    println!("-----------------------");
    match paths::install_dir() {
        Ok(p) => println!("install dir : {} (exists={})", p.display(), p.exists()),
        Err(e) => println!("install dir : <error: {e}>"),
    }
    match registry::get_service_dll() {
        Ok(Some(v)) => println!("ServiceDll  : {v}"),
        Ok(None) => println!("ServiceDll  : <absent>"),
        Err(e) => println!("ServiceDll  : <error: {e}>"),
    }
    match registry::load_uninstall_state() {
        Ok(Some(state)) => {
            println!(
                "saved state : OriginalServiceDll = {}",
                state.original_service_dll
            );
            println!("              InstallDir         = {}", state.install_dir);
            if state.prev_fdeny_present {
                println!("              PrevDenyTS         = {:?}", state.prev_fdeny);
            }
            println!(
                "              AddInsCreatedByUs  = {}",
                state.addins_created_by_us
            );
        }
        Ok(None) => println!("saved state : <not installed by rdprrap-installer>"),
        Err(e) => println!("saved state : <error: {e}>"),
    }
    Ok(())
}

fn resolve_source_dir(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        if !p.is_dir() {
            bail!("--source directory does not exist: {}", p.display());
        }
        // H2: reject a source directory whose canonical form lies under a
        // world-writable ancestor. Cheapest practical check: refuse paths
        // inside %TEMP% / %TMP% / %PUBLIC%. Anything else requires the
        // admin to have explicitly chosen it.
        reject_world_writable_source(&p)?;
        return Ok(p);
    }
    // Default: directory of the installer executable.
    let exe = std::env::current_exe().context("std::env::current_exe")?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("current_exe has no parent directory"))?;
    Ok(dir.to_path_buf())
}

/// Refuse to copy DLLs out of locations that are typically world-writable
/// (TEMP / Public) unless the operator overrides — at time of writing this is
/// a hard refusal.
fn reject_world_writable_source(p: &Path) -> Result<()> {
    let canonical = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    let lc = canonical.to_string_lossy().to_ascii_lowercase();
    for forbidden_var in ["TEMP", "TMP", "PUBLIC"] {
        if let Some(val) = std::env::var_os(forbidden_var) {
            let val_lc = val.to_string_lossy().to_ascii_lowercase();
            if !val_lc.is_empty() && lc.starts_with(&val_lc) {
                bail!(
                    "--source {} is under %{}% (world-writable); refusing",
                    canonical.display(),
                    forbidden_var
                );
            }
        }
    }
    Ok(())
}

fn validate_install_dir(dir: &Path, created_by_us: bool) -> Result<()> {
    if created_by_us {
        // We just made it — parent is %ProgramFiles%, inherits a safe ACL.
        return Ok(());
    }
    // Pre-existing directory: refuse to write if it's a reparse point to an
    // attacker-controlled target.
    if is_reparse_point(dir)? {
        bail!(
            "install dir {} is a reparse point; refusing to follow it",
            dir.display()
        );
    }
    Ok(())
}

fn copy_wrapper_dlls(source: &Path, target: &Path) -> Result<()> {
    let mut missing = Vec::new();
    for (built_name, canonical_name) in paths::WRAPPER_DLLS {
        let src = source.join(built_name);
        let src_use = if src.exists() {
            src
        } else {
            // Allow the canonical name to already exist in the source dir
            // (e.g. distributed release archive).
            let alt = source.join(canonical_name);
            if !alt.exists() {
                missing.push(built_name.to_string());
                continue;
            }
            alt
        };
        let dst = target.join(canonical_name);

        // H2 / M1: if `dst` already exists, make sure it is a plain file. A
        // reparse point with the same name was planted by an attacker to
        // redirect our SYSTEM-privileged copy into e.g. System32. We delete
        // reparse points before writing so the replacement is a real file we
        // own. `FILE_FLAG_OPEN_REPARSE_POINT` on the attribute query below
        // means `is_reparse_point` examines the literal name, not its target.
        if dst.exists() && is_reparse_point(&dst)? {
            eprintln!(
                "rdprrap-installer: {} was a reparse point — removing before copy",
                dst.display()
            );
            fs::remove_file(&dst)
                .with_context(|| format!("remove reparse point {}", dst.display()))?;
        }

        // Race-safe write: open `dst` with `CREATE_NEW` + exclusive share so
        // that any attacker who re-planted a reparse point (or any other file)
        // between the `remove_file` above and this open call causes an
        // explicit `ERROR_FILE_EXISTS` failure rather than a silently-
        // followed redirection to an attacker-controlled target.
        // `FILE_FLAG_OPEN_REPARSE_POINT` makes the open literal so a race-
        // planted reparse point fails the `CREATE_NEW` check instead of being
        // silently traversed. We then write the source bytes straight into
        // the handle — no second `open` on the path — so there is no further
        // window in which the file can be swapped under us.
        write_file_race_safe(&src_use, &dst)
            .with_context(|| format!("copy {} -> {}", src_use.display(), dst.display()))?;
        println!("rdprrap-installer: copied {}", dst.display());
    }
    if !missing.is_empty() {
        bail!(
            "missing DLL(s) in source directory {}: {}",
            source.display(),
            missing.join(", ")
        );
    }
    Ok(())
}

/// Race-safe equivalent of `std::fs::copy` for install-time DLL placement.
///
/// Reads `src` into memory, then opens `dst` with `CreateFileW(CREATE_NEW,
/// GENERIC_WRITE, share=0, FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL)`
/// and writes the content in one pass. If `dst` has been re-created between
/// the caller's `remove_file` and this call — whether as a reparse point, a
/// hardlink, or any other file type — the `CREATE_NEW` open fails and the
/// install is aborted rather than silently writing through a planted
/// redirection.
fn write_file_race_safe(src: &Path, dst: &Path) -> Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, WriteFile, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_MODE,
    };

    let bytes = fs::read(src).with_context(|| format!("read source DLL {}", src.display()))?;

    let dst_str = dst
        .to_str()
        .ok_or_else(|| anyhow!("destination path is not valid UTF-8: {}", dst.display()))?;
    let mut wdst: Vec<u16> = dst_str.encode_utf16().collect();
    wdst.push(0);

    // GENERIC_WRITE = 0x40000000.
    const GENERIC_WRITE: u32 = 0x4000_0000;
    // Combine FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT.
    let flags = FILE_FLAGS_AND_ATTRIBUTES(FILE_ATTRIBUTE_NORMAL.0 | FILE_FLAG_OPEN_REPARSE_POINT.0);

    // SAFETY: `wdst` is NUL-terminated UTF-16 and lives through the call.
    // `CREATE_NEW` with `FILE_SHARE_MODE(0)` fails with `ERROR_FILE_EXISTS`
    // (or `ERROR_SHARING_VIOLATION`) if any other handle or reparse point
    // occupies the name — that is exactly the race we want to close. The
    // returned HANDLE is released below via `CloseHandle`.
    let handle: HANDLE = unsafe {
        CreateFileW(
            PCWSTR(wdst.as_ptr()),
            GENERIC_WRITE,
            FILE_SHARE_MODE(0),
            None,
            CREATE_NEW,
            flags,
            HANDLE::default(),
        )
    }
    .with_context(|| format!("CreateFileW(CREATE_NEW, {})", dst.display()))?;

    // RAII close so every exit path (including the error path below) still
    // releases the handle.
    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: `self.0` was returned by a successful `CreateFileW`
                // above and is not used after this call.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }
    let guard = HandleGuard(handle);

    // Write the source bytes in one or more passes. WriteFile on a synchronous
    // handle can return a short count on very large buffers; we loop until
    // the whole payload is on disk.
    let mut written: usize = 0;
    while written < bytes.len() {
        let chunk = &bytes[written..];
        // Clamp to a u32 for the Win32 API.
        let chunk_len: u32 = chunk.len().min(u32::MAX as usize) as u32;
        let mut this_pass: u32 = 0;
        // SAFETY: `guard.0` is a valid write handle; `chunk` is a live borrow
        // into `bytes`; `this_pass` is a writable local out-param.
        unsafe {
            WriteFile(
                guard.0,
                Some(&chunk[..chunk_len as usize]),
                Some(&mut this_pass),
                None,
            )
        }
        .with_context(|| format!("WriteFile({})", dst.display()))?;
        if this_pass == 0 {
            bail!(
                "WriteFile({}) returned zero bytes written with success status",
                dst.display()
            );
        }
        written += this_pass as usize;
    }

    // `guard` drops here → CloseHandle runs.
    drop(guard);
    Ok(())
}

/// Check whether `p` is a reparse point by calling `GetFileAttributesW`.
/// Returns `Ok(false)` for "file does not exist".
fn is_reparse_point(p: &Path) -> Result<bool> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{GetLastError, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
    use windows::Win32::Storage::FileSystem::{
        GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    };

    let s = p
        .to_str()
        .ok_or_else(|| anyhow!("path is not valid UTF-8: {}", p.display()))?;
    let mut w: Vec<u16> = s.encode_utf16().collect();
    w.push(0);
    // SAFETY: `w` is NUL-terminated UTF-16 living for the duration of the call.
    let attrs = unsafe { GetFileAttributesW(PCWSTR(w.as_ptr())) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        // SAFETY: `GetLastError` has no preconditions.
        let err = unsafe { GetLastError() };
        if err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND {
            return Ok(false);
        }
        return Err(anyhow!(
            "GetFileAttributesW({}) failed: 0x{:08x}",
            p.display(),
            err.0
        ));
    }
    Ok((attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0)
}

/// Read `fDenyTSConnections` under `HKLM\SYSTEM\...\Terminal Server` so we can
/// restore it verbatim later (H4). Absent → `None`.
fn read_fdeny_ts_connections() -> Result<Option<u32>> {
    let key = match RegKey::open_local_machine(keys::TERMINAL_SERVER, KEY_READ) {
        Ok(k) => k,
        Err(_) => return Ok(None),
    };
    key.get_dword(crate::contract::values::FDENY_TS_CONNECTIONS)
}

/// Read `AllowMultipleTSSessions` under `HKLM\...\Winlogon` so uninstall can
/// restore it verbatim (C1). Absent → `None`.
fn read_allow_multi_ts_sessions() -> Result<Option<u32>> {
    let key = match RegKey::open_local_machine(WINLOGON_KEY, KEY_READ) {
        Ok(k) => k,
        Err(_) => return Ok(None),
    };
    key.get_dword(ALLOW_MULTI_VALUE)
}

/// C2 CheckInstall preflight: return `true` iff the current `ServiceDll`
/// registry value points at a DLL inside `install_dir`. That is the signal the
/// wrapper is already live — re-running install without `--force` would
/// overwrite our own state key with a wrapped `OriginalServiceDll` value and
/// leave the host with no path back to the vanilla `termsrv.dll`.
fn check_already_installed(install_dir: &Path) -> Result<bool> {
    let current = match registry::get_service_dll()? {
        Some(v) => v,
        None => return Ok(false),
    };
    // Compare case-insensitively (Windows paths). Anchor on the wrapper file
    // name too so a pure substring match against a different directory that
    // happens to contain the install-dir prefix does not false-positive.
    let dll_path = install_dir.join(paths::SERVICE_DLL_NAME);
    let needle = dll_path.to_string_lossy().to_ascii_lowercase();
    let haystack = current.to_ascii_lowercase();
    Ok(haystack.contains(&needle))
}

/// H2 CheckTermsrvVersion soft preflight: look at `%SystemRoot%\System32\
/// termsrv.dll`, read its `VS_FIXEDFILEINFO` and warn when the major.minor
/// pair is outside the set upstream `rdpwrap` is known to patch. We always
/// proceed — the wrapper patches by pattern, not by hard-coded offsets, so an
/// unknown version is usually fine.
fn preflight_termsrv_version() {
    let termsrv = match std::env::var_os("SystemRoot") {
        Some(root) => PathBuf::from(root).join("System32").join("termsrv.dll"),
        None => {
            eprintln!("rdprrap-installer: CheckTermsrvVersion: %SystemRoot% is unset — skipping");
            return;
        }
    };
    let path_str = match termsrv.to_str() {
        Some(s) => s,
        None => {
            eprintln!(
                "rdprrap-installer: CheckTermsrvVersion: termsrv.dll path is not UTF-8 — skipping"
            );
            return;
        }
    };
    match version::read_fixed_file_version(path_str) {
        Ok(Some(v)) => {
            let (major, minor) = v.major_minor();
            // Use the 4-tuple accessor for the full-version formatting so a
            // single authoritative decomposition of `VS_FIXEDFILEINFO` feeds
            // both log lines (avoids drift between the "known" and "unknown"
            // branches).
            let (mj, mn, bd, rv) = v.as_tuple();
            if version::is_known_termsrv_version(major, minor) {
                println!(
                    "rdprrap-installer: termsrv.dll version {}.{}.{}.{} (known)",
                    mj, mn, bd, rv
                );
            } else {
                eprintln!(
                    "rdprrap-installer: WARNING: termsrv.dll reports unknown major.minor \
                     {}.{} (full {}.{}.{}.{}). rdprrap patches by pattern so this is \
                     usually fine — proceeding.",
                    major, minor, mj, mn, bd, rv
                );
            }
        }
        Ok(None) => {
            eprintln!(
                "rdprrap-installer: CheckTermsrvVersion: termsrv.dll has no version \
                 resource — proceeding without a version check."
            );
        }
        Err(e) => {
            eprintln!(
                "rdprrap-installer: CheckTermsrvVersion: could not read termsrv.dll \
                 version ({e}) — proceeding without a version check."
            );
        }
    }
}

fn set_service_dll_str(value: &str) -> Result<()> {
    let key = RegKey::open_local_machine(keys::TERMSERVICE_PARAMETERS, KEY_WRITE)?;
    key.set_string(registry::VALUE_SERVICE_DLL, value, /*expand=*/ true)
}

fn apply_policy_keys(disable_nla: bool, create_addins: bool) -> Result<()> {
    use crate::contract::values as v;

    // Terminal Server root: fDenyTSConnections=0
    {
        let key = RegKey::open_local_machine(keys::TERMINAL_SERVER, KEY_WRITE)?;
        key.set_dword(v::FDENY_TS_CONNECTIONS, v::FDENY_TS_CONNECTIONS_DATA)?;
    }
    // WinStations\RDP-Tcp: EnableConcurrentSessions=1
    {
        let key = RegKey::open_local_machine(keys::WINSTATIONS_RDP_TCP, KEY_WRITE)?;
        key.set_dword(
            v::ENABLE_CONCURRENT_SESSIONS,
            v::ENABLE_CONCURRENT_SESSIONS_DATA,
        )?;

        // H3: historically we unconditionally wrote `UserAuthentication=0`
        // to disable NLA. That silently weakens authentication on every host
        // and does not match upstream rdpwrap behaviour. We now only touch
        // this value when the operator opts in via `--disable-nla`.
        if disable_nla {
            eprintln!(
                "rdprrap-installer: WARNING: --disable-nla set — writing \
                 UserAuthentication=0 under WinStations\\RDP-Tcp. This \
                 weakens RDP authentication. Omit the flag to keep the \
                 current NLA setting."
            );
            key.set_dword(v::USER_AUTHENTICATION, v::USER_AUTHENTICATION_DISABLED)?;
        }
    }
    // Licensing Core: AllowMultipleTSSessions=1
    {
        // This key may not pre-exist on all SKUs; create_local_machine is safe.
        let key = RegKey::create_local_machine(keys::LICENSING_CORE, KEY_WRITE)?;
        key.set_dword(
            v::ALLOW_MULTIPLE_TS_SESSIONS,
            v::ALLOW_MULTIPLE_TS_SESSIONS_DATA,
        )?;
    }
    // TS AddIns (Clip Redirector / DND Redirector / Dynamic VC).
    //
    // H5: mirror upstream `RDPWInst.dpr` lines 982..1022 verbatim. The entire
    // block is guarded by `if not Reg.KeyExists('AddIns')` — if the parent
    // key already exists we leave the system's configuration alone.
    //
    // Per the Delphi source the three subkeys hold:
    //   * Clip Redirector : Name="RDPClip" (REG_SZ),      Type=3 (REG_DWORD)
    //   * DND Redirector  : Name="RDPDND"  (REG_SZ),      Type=3 (REG_DWORD)
    //   * Dynamic VC      :                                Type=0xFFFFFFFF (= -1 signed, REG_DWORD)
    //
    // No `DLL` value is written by upstream on any of the three. Earlier
    // rdprrap releases wrote `Name`/`Type=3`/`DLL=...` values that did not
    // exist in stock `rdpwrap`, which could regress redirection on hosts that
    // had different AddIn DLLs registered. This revision restores parity.
    if !create_addins {
        eprintln!(
            "rdprrap-installer: AddIns key already exists — leaving the \
             existing Terminal Server AddIns configuration untouched (H5)"
        );
        return Ok(());
    }

    // Clip Redirector
    {
        let key = RegKey::create_local_machine(keys::ADDINS_CLIP, KEY_WRITE)?;
        key.set_string(
            v::ADDIN_NAME,
            v::ADDIN_CLIP_NAME_DATA,
            /*expand=*/ false,
        )?;
        key.set_dword(v::ADDIN_TYPE, v::ADDIN_TYPE_STANDARD)?;
    }
    // DND Redirector
    {
        let key = RegKey::create_local_machine(keys::ADDINS_DND, KEY_WRITE)?;
        key.set_string(
            v::ADDIN_NAME,
            v::ADDIN_DND_NAME_DATA,
            /*expand=*/ false,
        )?;
        key.set_dword(v::ADDIN_TYPE, v::ADDIN_TYPE_STANDARD)?;
    }
    // Dynamic VC — only `Type = 0xFFFFFFFF` (unsigned representation of the
    // signed -1 written by `RDPWInst.dpr`).
    {
        let key = RegKey::create_local_machine(keys::ADDINS_DVC, KEY_WRITE)?;
        key.set_dword(v::ADDIN_TYPE, v::ADDIN_TYPE_DYNAMIC_VC)?;
    }
    Ok(())
}

fn restart_termservice() -> Result<()> {
    println!("rdprrap-installer: stopping TermService...");
    match service::stop_termservice() {
        Ok(()) => println!("rdprrap-installer: TermService stopped"),
        Err(e) => {
            println!(
                "rdprrap-installer: TermService stop returned: {e} (continuing; starting anyway)"
            );
        }
    }
    println!("rdprrap-installer: starting TermService...");
    service::start_termservice().context("failed to start TermService")?;
    println!("rdprrap-installer: TermService running");
    Ok(())
}

// Keep KEY_READ referenced so `use` above doesn't produce unused-import warnings
// on paths that don't read the registry (currently none — this is defensive).
#[allow(dead_code)]
const _KEEP_KEY_READ: windows::Win32::System::Registry::REG_SAM_FLAGS = KEY_READ;
