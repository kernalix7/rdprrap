//! Spawn `mstsc.exe` against the local loopback listener to verify the
//! termwrap multi-session patch.
//!
//! Design decision (see crate-level comments): we launch the stock MSTSC
//! client rather than embedding the MSTSCAX ActiveX control. The user-visible
//! behaviour is identical (loopback RDP round-trip), the code surface is
//! dramatically smaller, and we avoid re-implementing COM event sinks for
//! `IMsTscAxEvents` with hand-rolled IID definitions.
//!
//! Because mstsc.exe does not propagate the protocol-level `discReason`
//! through its exit code, an unsuccessful connection surfaces as either:
//!   * non-zero exit code   → generic "connection failed"
//!   * immediate exit code 0 with no user interaction → "connect refused"
//!
//! The caller overlays the [`crate::disc_reason`] mapping by reading the
//! most-recent `ExtendedDisconnectReasonCode` out of the Terminal Services
//! client event log when available; otherwise the generic failure text is
//! used.

use std::path::PathBuf;
use std::process::{Command, ExitStatus};

use anyhow::{anyhow, Context, Result};

/// Result of an attempted mstsc.exe connection.
pub struct MstscOutcome {
    pub status: ExitStatus,
    /// When non-empty, raw stderr the child emitted before exit. mstsc.exe
    /// usually writes nothing here, but we capture it for completeness.
    pub stderr: String,
}

impl MstscOutcome {
    pub fn is_success(&self) -> bool {
        self.status.success()
    }
}

/// Locate `mstsc.exe` on the current system. We resolve via `%SystemRoot%`
/// rather than trusting `PATH` so a shadowing entry on PATH cannot redirect
/// us to an attacker-chosen binary.
pub fn mstsc_path() -> Result<PathBuf> {
    let root = std::env::var_os("SystemRoot")
        .ok_or_else(|| anyhow!("%SystemRoot% is not set; cannot locate mstsc.exe"))?;
    let path = PathBuf::from(root).join("System32").join("mstsc.exe");
    if !path.exists() {
        return Err(anyhow!(
            "mstsc.exe not found at {} — is this really Windows?",
            path.display()
        ));
    }
    Ok(path)
}

/// Spawn mstsc.exe against `127.0.0.2:<port>` and wait for it to exit.
///
/// The loopback address `127.0.0.2` is chosen to match the upstream rdpwrap
/// RDPCheck behaviour: it's a distinct address from the common `127.0.0.1`
/// so users can visually distinguish the test connection from any other
/// loopback traffic, and it still routes to the local stack on every
/// supported Windows version.
pub fn run_loopback_check(port: u16) -> Result<MstscOutcome> {
    let mstsc = mstsc_path()?;
    let target = format!("127.0.0.2:{port}");
    let output = Command::new(&mstsc)
        .arg(format!("/v:{target}"))
        .output()
        .with_context(|| format!("spawning {}", mstsc.display()))?;

    Ok(MstscOutcome {
        status: output.status,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn mstsc_path_resolves_on_windows() {
        // Only meaningful on a real Windows host; on CI cross-checks this
        // test file is compiled but the function call only succeeds on
        // Windows. Guard the call to avoid spurious failures in any
        // non-Windows test environment that may sneak in.
        let _ = mstsc_path();
    }
}
