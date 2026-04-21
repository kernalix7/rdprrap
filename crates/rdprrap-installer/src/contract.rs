//! Static install contract — platform-independent string constants.
//!
//! The real I/O lives in the Windows-gated modules ([`crate::paths`],
//! [`crate::registry`], [`crate::firewall`]), but those all boil down to
//! writing a fixed set of registry keys, copying a fixed set of DLL names,
//! and creating a fixed pair of firewall rules. We centralise the string
//! constants here so:
//!
//! 1. The [`crate::plan`] subcommand can emit a stable manifest of the
//!    install contract on any host, including Linux CI.
//! 2. Snapshot tests can fail on unintended changes to the contract — the
//!    kind of silent drift that would leave a user with a broken uninstall.
//! 3. The Windows modules re-export from here so there is a single source
//!    of truth for the key names and rule names.

/// Subdirectory name under `%ProgramFiles%` for the installed wrapper DLLs.
pub const INSTALL_SUBDIR: &str = "RDP Wrapper";

/// File names of the three wrapper DLLs produced by the cdylib crates.
///
/// `(built_name, canonical_name)` — the first component is the raw file
/// name cargo emits for the cdylib target (`crate-` becomes `crate_`),
/// the second is the short name the installer renames to on copy.
pub const WRAPPER_DLLS: &[(&str, &str)] = &[
    ("termwrap_dll.dll", "termwrap.dll"),
    ("umwrap_dll.dll", "umwrap.dll"),
    ("endpwrap_dll.dll", "endpwrap.dll"),
];

/// The wrapper DLL that must be registered as the TermService `ServiceDll`.
pub const SERVICE_DLL_NAME: &str = "termwrap.dll";

/// Value name of the TermService `ServiceDll` REG_EXPAND_SZ entry.
pub const VALUE_SERVICE_DLL: &str = "ServiceDll";

/// Registry paths touched by the installer. All are under `HKLM\`.
pub mod reg {
    pub const TERMSERVICE_PARAMETERS: &str =
        "SYSTEM\\CurrentControlSet\\Services\\TermService\\Parameters";
    pub const TERMINAL_SERVER: &str = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server";
    pub const WINSTATIONS_RDP_TCP: &str =
        "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp";
    pub const LICENSING_CORE: &str =
        "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Licensing Core";
    pub const ADDINS_PARENT: &str = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\AddIns";
    pub const ADDINS_CLIP: &str =
        "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\AddIns\\Clip Redirector";
    pub const ADDINS_DND: &str =
        "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\AddIns\\DND Redirector";
    pub const ADDINS_DVC: &str =
        "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\AddIns\\Dynamic VC";

    /// Private state key the installer uses to persist uninstall metadata.
    pub const INSTALLER_STATE: &str = "SOFTWARE\\rdprrap\\Installer";
}

/// Firewall rule names opened for RDP traffic (TCP+UDP port 3389).
pub mod firewall {
    pub const RULE_TCP: &str = "rdprrap-RDP-TCP";
    pub const RULE_UDP: &str = "rdprrap-RDP-UDP";
    pub const RDP_PORT: u16 = 3389;
}

/// Registry value names + DWORD payloads the installer writes. Pulled out of
/// the writers so the `plan` manifest can describe the install contract down
/// to the value level — not just which keys are touched — and so the insta
/// snapshot fails on silent numerical drift (e.g. if `EnableConcurrentSessions`
/// ever changed from `1` to `2`).
pub mod values {
    // ── HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server ──
    pub const FDENY_TS_CONNECTIONS: &str = "fDenyTSConnections";
    pub const FDENY_TS_CONNECTIONS_DATA: u32 = 0;

    // ── HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp ──
    pub const ENABLE_CONCURRENT_SESSIONS: &str = "EnableConcurrentSessions";
    pub const ENABLE_CONCURRENT_SESSIONS_DATA: u32 = 1;
    /// Only written when the operator passes `--disable-nla`. NLA stays
    /// enabled by default (matches upstream rdpwrap behaviour post-H3).
    pub const USER_AUTHENTICATION: &str = "UserAuthentication";
    pub const USER_AUTHENTICATION_DISABLED: u32 = 0;

    // ── HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Licensing Core ──
    pub const ALLOW_MULTIPLE_TS_SESSIONS: &str = "AllowMultipleTSSessions";
    pub const ALLOW_MULTIPLE_TS_SESSIONS_DATA: u32 = 1;

    // ── HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\* ──
    pub const ADDIN_NAME: &str = "Name";
    pub const ADDIN_TYPE: &str = "Type";
    pub const ADDIN_CLIP_NAME_DATA: &str = "RDPClip";
    pub const ADDIN_DND_NAME_DATA: &str = "RDPDND";
    /// `Type=3` matches the REG_DWORD constant written by upstream
    /// `RDPWInst.dpr` for Clip and DND Redirector entries.
    pub const ADDIN_TYPE_STANDARD: u32 = 3;
    /// `Type=0xFFFFFFFF` is `-1i32 as u32` — the sentinel the Delphi source
    /// writes for the Dynamic VC AddIn (unsigned-wrapped signed int).
    pub const ADDIN_TYPE_DYNAMIC_VC: u32 = 0xFFFF_FFFF;
}
