//! Platform-independent install-contract manifest.
//!
//! The `plan` subcommand prints a deterministic, human-readable description
//! of everything the installer would touch on a Windows host. It is pure
//! formatting over the static constants in [`crate::contract`] — no I/O, no
//! registry access, no COM — so it runs on Linux CI and feeds a snapshot test
//! that fails when the install contract drifts unintentionally.

use std::io::{self, Write};

use crate::contract::{self, firewall, reg};

/// Write the full install manifest to `out`. Deterministic across hosts.
pub fn write_manifest<W: Write>(out: &mut W) -> io::Result<()> {
    writeln!(out, "rdprrap-installer plan")?;
    writeln!(out, "======================")?;
    writeln!(out)?;

    writeln!(out, "Install directory")?;
    writeln!(
        out,
        "  %ProgramFiles%\\{subdir}\\",
        subdir = contract::INSTALL_SUBDIR
    )?;
    writeln!(out)?;

    writeln!(out, "Wrapper DLLs (built_name -> installed_name)")?;
    for (built, canonical) in contract::WRAPPER_DLLS {
        writeln!(out, "  {built} -> {canonical}")?;
    }
    writeln!(out)?;

    writeln!(out, "ServiceDll registration")?;
    writeln!(
        out,
        "  HKLM\\{key}\\{value} = %ProgramFiles%\\{subdir}\\{dll} (REG_EXPAND_SZ)",
        key = reg::TERMSERVICE_PARAMETERS,
        value = contract::VALUE_SERVICE_DLL,
        subdir = contract::INSTALL_SUBDIR,
        dll = contract::SERVICE_DLL_NAME,
    )?;
    writeln!(out)?;

    writeln!(out, "Registry keys touched (all under HKLM)")?;
    for key in [
        reg::TERMSERVICE_PARAMETERS,
        reg::TERMINAL_SERVER,
        reg::WINSTATIONS_RDP_TCP,
        reg::LICENSING_CORE,
        reg::ADDINS_PARENT,
        reg::ADDINS_CLIP,
        reg::ADDINS_DND,
        reg::ADDINS_DVC,
        reg::WINLOGON,
        reg::INSTALLER_STATE,
    ] {
        writeln!(out, "  {key}")?;
    }
    writeln!(out)?;

    writeln!(out, "Firewall rules (inbound, profile=any)")?;
    writeln!(
        out,
        "  {name} tcp/{port}",
        name = firewall::RULE_TCP,
        port = firewall::RDP_PORT
    )?;
    writeln!(
        out,
        "  {name} udp/{port}",
        name = firewall::RULE_UDP,
        port = firewall::RDP_PORT
    )?;
    writeln!(out)?;

    writeln!(out, "Uninstall behavior")?;
    writeln!(
        out,
        "  Restore original ServiceDll from installer-state key"
    )?;
    writeln!(out, "  Remove wrapper DLLs + install directory")?;
    writeln!(out, "  Remove firewall rules")?;
    writeln!(out, "  Restart TermService")?;

    Ok(())
}

/// Print the manifest to stdout.
pub fn print() -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    write_manifest(&mut lock)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_deterministic() {
        let mut a = Vec::new();
        let mut b = Vec::new();
        write_manifest(&mut a).unwrap();
        write_manifest(&mut b).unwrap();
        assert_eq!(a, b, "plan output must be byte-for-byte deterministic");
    }

    #[test]
    fn manifest_mentions_core_elements() {
        let mut buf = Vec::new();
        write_manifest(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("RDP Wrapper"));
        assert!(text.contains("termwrap.dll"));
        assert!(text.contains("ServiceDll"));
        assert!(text.contains("rdprrap-RDP-TCP"));
        assert!(text.contains("rdprrap-RDP-UDP"));
        assert!(text.contains("3389"));
    }

    // Snapshot test: pins the full install-contract manifest. Any drift in
    // DLL names, registry key paths, firewall rule names or the ServiceDll
    // value requires an explicit `cargo insta accept` — unintended changes
    // break CI on Linux before they ever reach a Windows host.
    #[test]
    fn manifest_snapshot() {
        let mut buf = Vec::new();
        write_manifest(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        insta::assert_snapshot!(text);
    }
}
