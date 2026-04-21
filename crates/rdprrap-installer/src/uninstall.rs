//! High-level uninstall orchestration — inverse of `install::run`.
//!
//! We prefer to restore the original `ServiceDll` value we captured at install
//! time. Without that saved value we fall back to the Microsoft-documented
//! default: `%SystemRoot%\System32\termsrv.dll`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use windows::Win32::System::Registry::KEY_WRITE;

use crate::firewall;
use crate::paths;
use crate::registry::{self, keys, RegKey};
use crate::service;

/// Default `ServiceDll` expression as shipped by Microsoft.
const DEFAULT_SERVICE_DLL: &str = "%SystemRoot%\\System32\\termsrv.dll";

pub struct Options {
    pub skip_firewall: bool,
    pub skip_restart: bool,
}

pub fn run(opts: Options) -> Result<()> {
    println!("rdprrap-installer: uninstalling");

    // Step 1: load + validate + restore ServiceDll.
    let saved = registry::load_uninstall_state()?;
    let (restore_value, install_dir, prev_fdeny, prev_fdeny_present, addins_created_by_us) =
        match &saved {
            Some(state) => {
                // H1: validate the saved value *before* writing it. If a
                // low-privileged administrator has tampered with it we refuse
                // to restore (leaving the wrapper ServiceDll in place is far
                // safer than loading an attacker-chosen DLL as SYSTEM).
                let install_dir = PathBuf::from(&state.install_dir);
                if let Err(e) = registry::validate_service_dll_path(
                    &state.original_service_dll,
                    Some(&install_dir),
                ) {
                    bail!(
                        "refusing to restore saved ServiceDll '{}': {}. \
                         Aborting uninstall to avoid loading an attacker-controlled DLL. \
                         Remove HKLM\\SOFTWARE\\rdprrap\\Installer manually and re-run.",
                        state.original_service_dll,
                        e
                    );
                }
                (
                    state.original_service_dll.clone(),
                    Some(install_dir),
                    state.prev_fdeny,
                    state.prev_fdeny_present,
                    state.addins_created_by_us,
                )
            }
            None => {
                println!("rdprrap-installer: no saved state — using default ServiceDll");
                (DEFAULT_SERVICE_DLL.to_string(), None, None, false, false)
            }
        };

    restore_service_dll(&restore_value)?;
    println!("rdprrap-installer: ServiceDll restored to {restore_value}");

    // Step 2: revert policy keys (best-effort — we only revert values we set).
    revert_policy_keys(prev_fdeny, prev_fdeny_present, addins_created_by_us)?;

    // Step 3: firewall cleanup.
    if !opts.skip_firewall {
        let _ = firewall::remove_rule();
        println!("rdprrap-installer: firewall rules removed (TCP+UDP 3389)");
    }

    // Step 4: restart TermService so it picks up the original DLL.
    if !opts.skip_restart {
        println!("rdprrap-installer: restarting TermService...");
        if let Err(e) = service::stop_termservice() {
            eprintln!("rdprrap-installer: TermService stop: {e} (continuing)");
        }
        service::start_termservice().context("failed to start TermService")?;
        println!("rdprrap-installer: TermService running");
    } else {
        println!("rdprrap-installer: skipping TermService restart (requested)");
    }

    // Step 5: remove the installer state subtree.
    registry::clear_uninstall_state()?;

    // Step 6: clean up the install directory.
    let dir = install_dir.unwrap_or(paths::install_dir()?);
    if dir.exists() {
        remove_install_dir(&dir);
    }

    println!("rdprrap-installer: uninstall complete");
    Ok(())
}

fn restore_service_dll(value: &str) -> Result<()> {
    let key = RegKey::open_local_machine(keys::TERMSERVICE_PARAMETERS, KEY_WRITE)?;
    key.set_string(registry::VALUE_SERVICE_DLL, value, /*expand=*/ true)
}

fn revert_policy_keys(
    prev_fdeny: Option<u32>,
    prev_fdeny_present: bool,
    addins_created_by_us: bool,
) -> Result<()> {
    // H4: restore fDenyTSConnections to whatever we observed pre-install.
    //
    //   * If we recorded an explicit prior value, write it back.
    //   * If we recorded "value was absent", delete the value (so Windows
    //     falls back to its documented default of 1 = deny).
    //   * If we have no record at all (legacy install from before H4), leave
    //     the value alone — the user can flip RDP on/off in System Properties.
    use crate::contract::values as v;

    if prev_fdeny_present {
        if let Ok(key) = RegKey::open_local_machine(keys::TERMINAL_SERVER, KEY_WRITE) {
            match prev_fdeny {
                Some(vv) => {
                    let _ = key.set_dword(v::FDENY_TS_CONNECTIONS, vv);
                }
                None => {
                    let _ = key.delete_value(v::FDENY_TS_CONNECTIONS);
                }
            }
        }
    }

    // Revert EnableConcurrentSessions back to 0 on RDP-Tcp.
    if let Ok(key) = RegKey::open_local_machine(keys::WINSTATIONS_RDP_TCP, KEY_WRITE) {
        let _ = key.set_dword(v::ENABLE_CONCURRENT_SESSIONS, 0);
    }

    // AllowMultipleTSSessions — we created the subkey, so remove the value.
    if let Ok(key) = RegKey::open_local_machine(keys::LICENSING_CORE, KEY_WRITE) {
        let _ = key.delete_value(v::ALLOW_MULTIPLE_TS_SESSIONS);
    }

    // TS AddIns (H5): only tear down the subtree if WE created the AddIns
    // parent key during install. If the parent existed pre-install its
    // contents are not ours to touch — we'd break the system's original
    // virtual-channel configuration.
    if addins_created_by_us {
        // Delete in reverse-create order so `AddIns` itself is last.
        for subkey in [
            keys::ADDINS_DVC,
            keys::ADDINS_DND,
            keys::ADDINS_CLIP,
            keys::ADDINS_PARENT,
        ] {
            if let Err(e) = registry::delete_tree_local_machine(subkey) {
                eprintln!("rdprrap-installer: failed to delete {subkey}: {e} (continuing)");
            }
        }
    } else {
        println!(
            "rdprrap-installer: AddIns key pre-existed at install time — \
             leaving Terminal Server AddIns configuration intact"
        );
    }

    Ok(())
}

fn remove_install_dir(dir: &Path) {
    match fs::remove_dir_all(dir) {
        Ok(()) => println!("rdprrap-installer: removed {}", dir.display()),
        Err(e) => println!(
            "rdprrap-installer: could not remove {} ({e}) — remove manually if needed",
            dir.display()
        ),
    }
}
