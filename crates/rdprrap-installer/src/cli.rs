//! Command-line argument parsing for `rdprrap-installer`.
//!
//! The original `RDPWInst.exe` uses flag-style arguments (`-i`, `-u`, `-r`).
//! We keep backwards-compatible flag aliases while exposing a clap-derived
//! subcommand layout that is easier to extend.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "rdprrap-installer",
    version,
    about = "Install / uninstall the rdprrap wrapper DLLs",
    long_about = "Installs the rdprrap wrapper DLLs into %ProgramFiles%\\RDP Wrapper, \
                  configures the TermService ServiceDll, enables multi-session RDP \
                  registry keys and opens the firewall. Use `uninstall` to revert."
)]
pub struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Legacy alias for `install`.
    #[arg(short = 'i', long = "install", conflicts_with_all = ["uninstall", "status"], action = clap::ArgAction::SetTrue)]
    install: bool,

    /// Legacy alias for `uninstall`.
    #[arg(short = 'u', long = "uninstall", conflicts_with_all = ["install", "status"], action = clap::ArgAction::SetTrue)]
    uninstall: bool,

    /// Legacy alias for `status`.
    #[arg(long = "status", conflicts_with_all = ["install", "uninstall"], action = clap::ArgAction::SetTrue)]
    status: bool,

    /// Directory holding the built wrapper DLLs (install only).
    #[arg(long = "source", value_name = "DIR")]
    source: Option<PathBuf>,

    /// Skip firewall rule changes.
    #[arg(long = "skip-firewall", action = clap::ArgAction::SetTrue)]
    skip_firewall: bool,

    /// Skip restarting TermService.
    #[arg(long = "skip-restart", action = clap::ArgAction::SetTrue)]
    skip_restart: bool,

    /// Disable Network-Level Authentication (writes `UserAuthentication=0`
    /// under `WinStations\RDP-Tcp`). Off by default — only supply this flag
    /// if you explicitly want to weaken RDP authentication for legacy client
    /// compatibility.
    #[arg(long = "disable-nla", action = clap::ArgAction::SetTrue)]
    disable_nla: bool,

    /// Proceed with install even if a previous rdprrap deployment is detected
    /// under the target install dir (C2 CheckInstall). Without this flag the
    /// installer refuses to run a second time to avoid clobbering state.
    #[arg(long = "force", action = clap::ArgAction::SetTrue)]
    force: bool,
}

#[derive(Debug, Subcommand, Clone)]
pub enum Command {
    /// Install the wrapper DLLs and wire up the registry/service/firewall.
    Install {
        /// Directory containing the built wrapper DLLs to copy.
        #[arg(long = "source", value_name = "DIR")]
        source_dir: Option<PathBuf>,

        /// Do not add firewall rules.
        #[arg(long = "skip-firewall")]
        skip_firewall: bool,

        /// Do not restart TermService after install.
        #[arg(long = "skip-restart")]
        skip_restart: bool,

        /// Explicitly disable Network-Level Authentication. Off by default.
        #[arg(long = "disable-nla")]
        disable_nla: bool,

        /// Reinstall over an existing rdprrap deployment without aborting.
        #[arg(long = "force")]
        force: bool,
    },
    /// Revert all install actions and restore the original ServiceDll.
    Uninstall {
        /// Do not remove firewall rules.
        #[arg(long = "skip-firewall")]
        skip_firewall: bool,

        /// Do not restart TermService after uninstall.
        #[arg(long = "skip-restart")]
        skip_restart: bool,
    },
    /// Print the current install state (paths, ServiceDll value, firewall).
    Status,
    /// Print a platform-independent description of the install contract
    /// (paths, DLLs, registry keys, firewall rules). Does no I/O and
    /// requires no elevation — useful for diagnostics and CI snapshots.
    Plan,
}

impl Args {
    /// Resolve legacy flags into a canonical [`Command`].
    pub fn command(self) -> Command {
        if let Some(cmd) = self.command {
            return cmd;
        }
        if self.uninstall {
            return Command::Uninstall {
                skip_firewall: self.skip_firewall,
                skip_restart: self.skip_restart,
            };
        }
        if self.status {
            return Command::Status;
        }
        // Default to install when invoked with no subcommand (matches RDPWInst behaviour
        // when called with `-i` or no arg — we require an explicit action for safety).
        Command::Install {
            source_dir: self.source,
            skip_firewall: self.skip_firewall,
            skip_restart: self.skip_restart,
            disable_nla: self.disable_nla,
            force: self.force,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_install() {
        let args = Args::parse_from(["rdprrap-installer"]);
        assert!(matches!(args.command(), Command::Install { .. }));
    }

    #[test]
    fn legacy_uninstall_flag() {
        let args = Args::parse_from(["rdprrap-installer", "-u"]);
        assert!(matches!(args.command(), Command::Uninstall { .. }));
    }

    #[test]
    fn explicit_status_subcommand() {
        let args = Args::parse_from(["rdprrap-installer", "status"]);
        assert!(matches!(args.command(), Command::Status));
    }

    #[test]
    fn install_source_flag() {
        let args = Args::parse_from(["rdprrap-installer", "install", "--source", "/tmp/x"]);
        match args.command() {
            Command::Install { source_dir, .. } => {
                assert_eq!(
                    source_dir
                        .as_deref()
                        .map(|p| p.to_string_lossy().to_string()),
                    Some("/tmp/x".to_string())
                );
            }
            _ => panic!("expected install"),
        }
    }

    #[test]
    fn disable_nla_defaults_off() {
        let args = Args::parse_from(["rdprrap-installer", "install"]);
        match args.command() {
            Command::Install { disable_nla, .. } => assert!(!disable_nla),
            _ => panic!("expected install"),
        }
    }

    #[test]
    fn disable_nla_opt_in() {
        let args = Args::parse_from(["rdprrap-installer", "install", "--disable-nla"]);
        match args.command() {
            Command::Install { disable_nla, .. } => assert!(disable_nla),
            _ => panic!("expected install"),
        }
    }
}
