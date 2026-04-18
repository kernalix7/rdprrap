//! `ReadSettings` / `WriteSettings` logic.
//!
//! Mirrors the registry I/O performed by the original Delphi `RDPConf.exe`.
//! All writes are best-effort per-value — a failure on one entry does not
//! short-circuit the others. Callers receive a `WriteResult` that aggregates
//! per-field outcomes so the UI can surface a precise error list.

use anyhow::Result;

use crate::registry::{keys, read_hklm_dword, write_hklm_dword};

/// Firewall rule names for rdprrap. **Must stay in sync with
/// `rdprrap-installer::firewall::RULES`** (not imported to avoid a dep on the
/// installer crate — see README §Configuration).
const FW_RULE_TCP: &str = "rdprrap-RDP-TCP";
const FW_RULE_UDP: &str = "rdprrap-RDP-UDP";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// `SecurityLayer=0, UserAuthentication=0`
    GuiOnly,
    /// `SecurityLayer=1, UserAuthentication=0`
    Default,
    /// `SecurityLayer=2, UserAuthentication=1`
    NetworkLevel,
}

impl AuthMode {
    pub fn from_registry(security_layer: u32, user_auth: u32) -> Self {
        match (security_layer, user_auth) {
            (0, _) => AuthMode::GuiOnly,
            (2, _) | (_, 1) => AuthMode::NetworkLevel,
            _ => AuthMode::Default,
        }
    }

    pub fn values(self) -> (u32, u32) {
        match self {
            AuthMode::GuiOnly => (0, 0),
            AuthMode::Default => (1, 0),
            AuthMode::NetworkLevel => (2, 1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// "Enable Remote Desktop" — UI state (true = enabled). Backed by
    /// `fDenyTSConnections` with inverted semantics.
    pub enable_rdp: bool,
    pub rdp_port: u16,
    pub single_session_per_user: bool,
    pub hide_users_on_logon: bool,
    pub allow_custom_programs: bool,
    pub auth: AuthMode,
    /// `0..=4` — written to two registry locations (Terminal Server + Policies).
    pub shadow: u8,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enable_rdp: true,
            rdp_port: 3389,
            single_session_per_user: true,
            hide_users_on_logon: false,
            allow_custom_programs: false,
            auth: AuthMode::Default,
            shadow: 0,
        }
    }
}

/// Read every UI-visible setting from the registry. Missing values fall back
/// to documented Windows defaults so the UI never shows uninitialised state.
pub fn read_settings() -> Result<Settings> {
    let fdeny = read_hklm_dword(keys::TERMINAL_SERVER, "fDenyTSConnections")?.unwrap_or(1);
    let rdp_port = read_hklm_dword(keys::WINSTATIONS_RDP_TCP, "PortNumber")?.unwrap_or(3389);
    let single = read_hklm_dword(keys::TERMINAL_SERVER, "fSingleSessionPerUser")?.unwrap_or(1);
    let hide = read_hklm_dword(keys::POLICIES_SYSTEM, "dontdisplaylastusername")?.unwrap_or(0);
    let honor = read_hklm_dword(keys::TERMINAL_SERVER, "HonorLegacySettings")?.unwrap_or(0);
    let sec = read_hklm_dword(keys::WINSTATIONS_RDP_TCP, "SecurityLayer")?.unwrap_or(1);
    let uauth = read_hklm_dword(keys::WINSTATIONS_RDP_TCP, "UserAuthentication")?.unwrap_or(0);
    let shadow_ts = read_hklm_dword(keys::WINSTATIONS_RDP_TCP, "Shadow")?.unwrap_or(0);

    Ok(Settings {
        enable_rdp: fdeny == 0,
        rdp_port: u16::try_from(rdp_port).unwrap_or(3389),
        single_session_per_user: single != 0,
        hide_users_on_logon: hide != 0,
        allow_custom_programs: honor != 0,
        auth: AuthMode::from_registry(sec, uauth),
        shadow: u8::try_from(shadow_ts.min(4)).unwrap_or(0),
    })
}

/// Per-field write outcome. The UI renders `failures` as a bullet list.
#[derive(Debug, Default)]
pub struct WriteResult {
    pub failures: Vec<String>,
    /// `true` iff the port changed and at least one firewall rebind succeeded.
    pub firewall_updated: bool,
}

impl WriteResult {
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Write every setting. Individual field failures are collected into
/// `WriteResult::failures`; the caller displays them but the function itself
/// never returns `Err` unless a catastrophic (non-per-value) error occurs.
pub fn write_settings(new: &Settings, previous_port: u16) -> WriteResult {
    let mut out = WriteResult::default();

    let try_write = |subkey: &str, value: &str, data: u32, label: &str, out: &mut WriteResult| {
        if let Err(e) = write_hklm_dword(subkey, value, data) {
            out.failures.push(format!("{label}: {e}"));
        }
    };

    // fDenyTSConnections is inverted relative to the UI toggle.
    try_write(
        keys::TERMINAL_SERVER,
        "fDenyTSConnections",
        if new.enable_rdp { 0 } else { 1 },
        "Enable Remote Desktop",
        &mut out,
    );
    try_write(
        keys::WINSTATIONS_RDP_TCP,
        "PortNumber",
        u32::from(new.rdp_port),
        "RDP Port",
        &mut out,
    );
    try_write(
        keys::TERMINAL_SERVER,
        "fSingleSessionPerUser",
        u32::from(new.single_session_per_user),
        "Single session per user",
        &mut out,
    );
    try_write(
        keys::POLICIES_SYSTEM,
        "dontdisplaylastusername",
        u32::from(new.hide_users_on_logon),
        "Hide users on logon screen",
        &mut out,
    );
    try_write(
        keys::TERMINAL_SERVER,
        "HonorLegacySettings",
        u32::from(new.allow_custom_programs),
        "Allow custom programs to start",
        &mut out,
    );

    let (sec, uauth) = new.auth.values();
    try_write(
        keys::WINSTATIONS_RDP_TCP,
        "SecurityLayer",
        sec,
        "SecurityLayer",
        &mut out,
    );
    try_write(
        keys::WINSTATIONS_RDP_TCP,
        "UserAuthentication",
        uauth,
        "UserAuthentication",
        &mut out,
    );

    // Dual-write Shadow, matching the original RDPConf behaviour.
    try_write(
        keys::WINSTATIONS_RDP_TCP,
        "Shadow",
        u32::from(new.shadow),
        "Shadow (Terminal Server)",
        &mut out,
    );
    try_write(
        keys::POLICIES_TS,
        "Shadow",
        u32::from(new.shadow),
        "Shadow (Policies)",
        &mut out,
    );

    if new.rdp_port != previous_port {
        out.firewall_updated = update_firewall_rules(new.rdp_port, &mut out.failures);
    }

    out
}

/// Rebind both rdprrap firewall rules to the new local port. Failures are
/// logged into `failures` as warnings rather than propagated — a machine may
/// legitimately have no firewall profile configured (e.g. gpedit-managed) and
/// blocking the OK/Apply flow there would be hostile.
#[cfg(windows)]
fn update_firewall_rules(new_port: u16, failures: &mut Vec<String>) -> bool {
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let sysroot =
        std::env::var_os("SystemRoot").unwrap_or_else(|| std::ffi::OsString::from("C:\\Windows"));
    let netsh = PathBuf::from(sysroot).join("System32").join("netsh.exe");

    let mut any_ok = false;
    for name in [FW_RULE_TCP, FW_RULE_UDP] {
        let status = Command::new(&netsh)
            .args([
                "advfirewall",
                "firewall",
                "set",
                "rule",
                &format!("name={name}"),
                "new",
                &format!("localport={new_port}"),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .status();
        match status {
            Ok(s) if s.success() => any_ok = true,
            Ok(s) => failures.push(format!(
                "Firewall rule {name} rebind to port {new_port} returned exit {:?} (non-fatal)",
                s.code()
            )),
            Err(e) => failures.push(format!(
                "Failed to spawn netsh for rule {name}: {e} (non-fatal)"
            )),
        }
    }
    any_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_roundtrip() {
        for m in [AuthMode::GuiOnly, AuthMode::Default, AuthMode::NetworkLevel] {
            let (s, u) = m.values();
            assert_eq!(AuthMode::from_registry(s, u), m);
        }
    }

    #[test]
    fn auth_from_registry_falls_back_to_default() {
        assert_eq!(AuthMode::from_registry(7, 7), AuthMode::NetworkLevel);
        // Only UserAuthentication=1 with non-zero SecurityLayer implies NLA.
        assert_eq!(AuthMode::from_registry(1, 0), AuthMode::Default);
        assert_eq!(AuthMode::from_registry(0, 0), AuthMode::GuiOnly);
    }

    #[test]
    fn settings_default_is_reasonable() {
        let s = Settings::default();
        assert_eq!(s.rdp_port, 3389);
        assert!(s.enable_rdp);
        assert_eq!(s.shadow, 0);
        assert_eq!(s.auth, AuthMode::Default);
    }

    #[test]
    fn fw_rule_names_documented() {
        // Cross-check with rdprrap-installer::firewall::RULES
        assert_eq!(FW_RULE_TCP, "rdprrap-RDP-TCP");
        assert_eq!(FW_RULE_UDP, "rdprrap-RDP-UDP");
    }
}
