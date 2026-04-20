//! Windows Firewall rule management for the RDP port (TCP + UDP 3389).
//!
//! The original `RDPWInst.exe` shells out to `netsh advfirewall` rather than
//! driving `INetFwPolicy2` directly; we do the same here. `netsh` is shipped
//! with every supported Windows SKU and avoids pulling COM into the install
//! dependency graph.
//!
//! Upstream `RDPWInst.dpr` adds **two** rules — one for TCP/3389 and one for
//! UDP/3389 — because modern RDP clients negotiate UDP side channels for
//! better bandwidth/latency. Our earlier revision only opened TCP, which
//! silently regressed multi-monitor and high-latency sessions.
//!
//! Security note: we invoke `netsh.exe` by its absolute path inside
//! `%SystemRoot%\System32` rather than letting `CreateProcess` resolve it
//! via `PATH`. Because the installer runs elevated this prevents a
//! PATH-shadowing attack by any writable directory that happens to appear
//! earlier in the search path.
//!
//! Rule-name rationale: Windows ships a built-in rule called simply
//! `Remote Desktop` (and localized equivalents). Reusing that name from
//! `netsh` is ambiguous on localized SKUs and would risk deleting the
//! built-in entry during uninstall. We therefore use distinct, rdprrap-owned
//! names — `rdprrap-RDP-TCP` and `rdprrap-RDP-UDP` — so our rules are
//! addressable by exact string and never collide with the stock ones.

use std::ffi::OsString;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, Result};

// Rule names and RDP port come from the non-gated `crate::contract::firewall`
// module so the install-plan snapshot and the actual `netsh` calls cannot
// diverge. Exposed through this module so existing call sites
// (`firewall::RULE_TCP`, etc.) continue to resolve unchanged.
pub use crate::contract::firewall::{RDP_PORT, RULE_TCP, RULE_UDP};

/// All rdprrap-owned firewall rule names, in the order we add them.
pub const RULES: &[&str] = &[RULE_TCP, RULE_UDP];

/// Protocol-specific rule definitions. Each tuple is
/// `(rule_name, netsh_protocol_token)`.
///
/// `netsh advfirewall firewall` accepts `protocol=tcp` and `protocol=udp`
/// case-insensitively; we use lowercase to match the `rdpwrap` Delphi source.
const RULES_WITH_PROTO: &[(&str, &str)] = &[(RULE_TCP, "tcp"), (RULE_UDP, "udp")];

/// CREATE_NO_WINDOW — suppress console window flash when running netsh.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Resolve the absolute path to `netsh.exe` under `%SystemRoot%\System32`.
///
/// Falls back to the bare name `netsh.exe` if `%SystemRoot%` is unset — this
/// should never happen on a sane Windows host, but failing hard there would
/// be worse than letting Windows do a normal search.
fn netsh_path() -> PathBuf {
    let sysroot = std::env::var_os("SystemRoot").unwrap_or_else(|| OsString::from("C:\\Windows"));
    PathBuf::from(sysroot).join("System32").join("netsh.exe")
}

/// Add an inbound allow rule for TCP 3389 *and* UDP 3389. Idempotent per rule
/// (removes any prior rule with the same name first to avoid duplicates).
///
/// Partial failure is tolerated: if one protocol fails we still try the other,
/// and return the first error collected so the caller can decide whether to
/// roll back the installer transaction.
pub fn add_rule() -> Result<()> {
    let mut first_err: Option<anyhow::Error> = None;

    for (name, proto) in RULES_WITH_PROTO {
        // Best-effort delete first — ignore error.
        let _ = remove_single_rule(name);

        let status = Command::new(netsh_path())
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={name}"),
                "dir=in",
                "action=allow",
                &format!("protocol={proto}"),
                &format!("localport={RDP_PORT}"),
                "profile=any",
                "enable=yes",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .map_err(|e| anyhow!("failed to spawn netsh for rule {name}: {e}"));

        match status {
            Ok(s) if s.success() => {}
            Ok(s) => {
                let err = anyhow!(
                    "netsh advfirewall add rule {name} ({proto}/{RDP_PORT}) failed (exit {:?})",
                    s.code()
                );
                eprintln!("rdprrap-installer: {err}");
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
            Err(e) => {
                eprintln!("rdprrap-installer: {e}");
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }

    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Remove both rdprrap firewall rules. Tolerates "rule not found" on either.
/// Always returns `Ok(())` because failure to delete a rule that does not
/// exist, or a transient `netsh` spawn failure, should not block uninstall.
pub fn remove_rule() -> Result<()> {
    for name in RULES {
        let _ = remove_single_rule(name);
    }
    Ok(())
}

fn remove_single_rule(name: &str) -> Result<()> {
    let status = Command::new(netsh_path())
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={name}"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|e| anyhow!("failed to spawn netsh for delete {name}: {e}"))?;
    // netsh exits non-zero when the rule is absent — we swallow that here and
    // let the caller treat it as success.
    let _ = status;
    Ok(())
}
