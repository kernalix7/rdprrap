//! rdprrap-installer — CLI installer/uninstaller for the rdprrap wrapper DLLs.
//!
//! Replicates the high-level flow of the original Delphi `RDPWInst.exe`:
//!
//! 1. Copies `termwrap.dll`, `umwrap.dll`, `endpwrap.dll` to `%ProgramFiles%\RDP Wrapper\`.
//! 2. Rewrites `HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters\ServiceDll`
//!    to point at the wrapper (backing up the original value for later restore).
//! 3. Applies the canonical RDP policy registry keys (multi-session enable, TS AddIns).
//! 4. Adds a firewall rule opening TCP 3389.
//! 5. Restarts the shared `TermService` host so the wrapper is loaded.
//!
//! Uninstall (`-u`) reverses every step and restores the saved original ServiceDll.
//!
//! All Windows-specific operations are gated behind `#[cfg(windows)]`. On non-Windows
//! hosts the binary still compiles (useful for CI/lint on Linux) but refuses to run
//! install/uninstall actions.

use anyhow::{bail, Result};
use clap::Parser;

#[cfg(windows)]
mod acl;
mod cli;
mod contract;
#[cfg(windows)]
mod elevation;
#[cfg(windows)]
mod firewall;
#[cfg(windows)]
mod install;
#[cfg(windows)]
mod paths;
mod plan;
#[cfg(windows)]
mod registry;
#[cfg(windows)]
mod service;
#[cfg(windows)]
mod uninstall;
#[cfg(windows)]
mod version;

fn main() -> Result<()> {
    let args = cli::Args::parse();

    #[cfg(windows)]
    {
        run_windows(args)
    }
    #[cfg(not(windows))]
    {
        run_non_windows(args)
    }
}

#[cfg(windows)]
fn run_windows(args: cli::Args) -> Result<()> {
    let command = args.command();

    // `plan` is read-only and does no I/O — skip the elevation gate so it
    // can be run from any shell for documentation/diagnostics.
    if matches!(command, cli::Command::Plan) {
        return plan::print();
    }

    // Elevation is required for every action that touches the registry,
    // SCM or Windows Firewall — bail fast with a clear message otherwise.
    if !elevation::is_elevated()? {
        bail!(
            "Administrator privileges required. Re-run this binary from an elevated \
             command prompt (Run as administrator)."
        );
    }

    match command {
        cli::Command::Install {
            source_dir,
            skip_firewall,
            skip_restart,
            disable_nla,
            force,
        } => install::run(install::Options {
            source_dir,
            skip_firewall,
            skip_restart,
            disable_nla,
            force,
        }),
        cli::Command::Uninstall {
            skip_firewall,
            skip_restart,
        } => uninstall::run(uninstall::Options {
            skip_firewall,
            skip_restart,
        }),
        cli::Command::Status => install::status(),
        cli::Command::Plan => plan::print(),
    }
}

#[cfg(not(windows))]
fn run_non_windows(args: cli::Args) -> Result<()> {
    // Allow the `--help`, `status` and `plan` codepaths to succeed on Linux
    // for CI. `plan` is especially useful here — it emits the install
    // contract as a stable manifest that the snapshot test pins.
    match args.command() {
        cli::Command::Status => {
            eprintln!(
                "rdprrap-installer: status command is a no-op on non-Windows hosts \
                 (built for CI/lint only)."
            );
            Ok(())
        }
        cli::Command::Plan => plan::print(),
        _ => bail!(
            "rdprrap-installer must be run on Windows. Build with --target \
             x86_64-pc-windows-msvc or i686-pc-windows-msvc and run on the target host."
        ),
    }
}
