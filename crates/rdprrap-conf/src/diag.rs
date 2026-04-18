//! Real-time diagnostics — assembled once per timer tick.
//!
//! Every accessor here is read-only and tolerates I/O / permission failure by
//! collapsing to a safe "unknown" state, so the UI polling thread never panics.

use crate::listener::{self, ListenerState};
use crate::registry::{keys, RegKey};
use crate::service_query::{self, ServiceState};
use crate::version;

use windows::Win32::System::Registry::KEY_READ;

/// Wrapper DLL fingerprint deduced from `ServiceDll`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperState {
    Installed,
    InstalledRdpWrap,
    NotInstalled,
    ThirdParty,
    Unknown,
}

impl WrapperState {
    pub fn label(self) -> &'static str {
        match self {
            WrapperState::Installed => "Installed",
            WrapperState::InstalledRdpWrap => "Installed (original rdpwrap)",
            WrapperState::NotInstalled => "Not installed",
            WrapperState::ThirdParty => "3rd-party library detected",
            WrapperState::Unknown => "Unknown",
        }
    }

    /// Suggested foreground colour — returned as a native-windows-gui
    /// friendly `(r, g, b)` tuple.
    pub fn color(self) -> (u8, u8, u8) {
        match self {
            WrapperState::Installed => (0, 128, 0),
            WrapperState::InstalledRdpWrap => (0, 128, 0),
            WrapperState::NotInstalled => (128, 128, 128),
            WrapperState::ThirdParty => (200, 0, 0),
            WrapperState::Unknown => (128, 128, 128),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportLevel {
    Fully,
    Partially,
    Unknown,
}

impl SupportLevel {
    pub fn label(self) -> &'static str {
        match self {
            SupportLevel::Fully => "fully supported",
            SupportLevel::Partially => "partially supported",
            SupportLevel::Unknown => "unknown",
        }
    }

    pub fn color(self) -> (u8, u8, u8) {
        match self {
            SupportLevel::Fully => (0, 128, 0),
            SupportLevel::Partially => (192, 128, 0),
            SupportLevel::Unknown => (128, 128, 128),
        }
    }
}

/// Aggregate diagnostics snapshot refreshed on each timer tick.
#[derive(Debug, Clone)]
pub struct Diagnostics {
    pub wrapper: WrapperState,
    pub wrapper_version: Option<String>,
    pub service: ServiceState,
    pub termsrv_version: Option<String>,
    pub listener: ListenerState,
    pub support: SupportLevel,
}

impl Diagnostics {
    pub fn collect() -> Self {
        let service_dll = current_service_dll();
        let (wrapper, wrapper_version) = classify_wrapper(service_dll.as_deref());
        let termsrv_path = system32_path("termsrv.dll");
        let termsrv_version = version::file_version(&termsrv_path).ok().flatten();
        let support = classify_support(termsrv_version.as_deref());

        Self {
            wrapper,
            wrapper_version,
            service: service_query::query_termservice(),
            termsrv_version,
            listener: listener::rdp_tcp_state(),
            support,
        }
    }
}

fn current_service_dll() -> Option<String> {
    let key = RegKey::open_hklm(keys::TERMSERVICE_PARAMETERS, KEY_READ).ok()?;
    key.get_string("ServiceDll").ok().flatten()
}

fn classify_wrapper(service_dll: Option<&str>) -> (WrapperState, Option<String>) {
    let Some(path) = service_dll else {
        return (WrapperState::Unknown, None);
    };
    let lower = path.to_ascii_lowercase();
    // Detection priority (filename first, then directory fallback):
    //   1. rdpwrap.dll filename — original stascorp/rdpwrap (must precede
    //      "rdp wrapper" directory check, since both share that directory)
    //   2. termwrap.dll filename or rdprrap-specific directory — our install
    //   3. stock termsrv.dll
    //   4. anything else is a 3rd-party library
    let state = if lower.contains("rdpwrap.dll") {
        WrapperState::InstalledRdpWrap
    } else if lower.contains("termwrap")
        || lower.contains("rdprrap")
        || lower.contains("rdp wrapper")
    {
        WrapperState::Installed
    } else if lower.ends_with("\\termsrv.dll") || lower.ends_with("/termsrv.dll") {
        WrapperState::NotInstalled
    } else {
        WrapperState::ThirdParty
    };

    // Only attempt to read a file version when the ServiceDll is *not* stock.
    // Reading stock termsrv.dll's version belongs in `termsrv_version`, not here.
    let ver = if state == WrapperState::NotInstalled {
        None
    } else {
        // `path` may contain %SystemRoot% — expand lexically via std env.
        let expanded = expand_env_vars(path);
        version::file_version(&expanded).ok().flatten()
    };
    (state, ver)
}

/// Proxy for support-level detection — see CLAUDE.md §conf for the policy.
///
/// Because rdprrap resolves offsets via runtime pattern matching rather than
/// a versioned INI, we cannot cheaply predict whether a patch will succeed
/// without actually mapping termsrv.dll. A future patcher API
/// (`patcher::termsrv::detect_patterns`) will replace this heuristic; today we
/// match the termsrv major.minor against the set of major Windows lines that
/// shipped terminal services:
///
///  * 6.1 = Windows 7 / Server 2008 R2
///  * 6.2 = Windows 8 / Server 2012
///  * 6.3 = Windows 8.1 / Server 2012 R2
///  * 10.0 = Windows 10 / 11 / Server 2016+
fn classify_support(termsrv_version: Option<&str>) -> SupportLevel {
    let Some(v) = termsrv_version else {
        return SupportLevel::Unknown;
    };
    match version::major_minor(v) {
        Some((10, 0)) | Some((6, 3)) | Some((6, 2)) | Some((6, 1)) => SupportLevel::Fully,
        Some(_) => SupportLevel::Partially,
        None => SupportLevel::Unknown,
    }
}

fn system32_path(dll: &str) -> String {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    format!("{sysroot}\\System32\\{dll}")
}

/// Replace `%VAR%` sequences with the matching environment value. Unknown
/// variables are left verbatim so callers still see useful diagnostics.
fn expand_env_vars(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('%') {
            let name = &after[..end];
            match std::env::var(name) {
                Ok(v) => out.push_str(&v),
                Err(_) => {
                    out.push('%');
                    out.push_str(name);
                    out.push('%');
                }
            }
            rest = &after[end + 1..];
        } else {
            out.push_str(&rest[start..]);
            return out;
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_not_installed() {
        let (s, _) = classify_wrapper(Some("%SystemRoot%\\System32\\termsrv.dll"));
        assert_eq!(s, WrapperState::NotInstalled);
    }

    #[test]
    fn classify_installed_rdprrap() {
        let (s, _) = classify_wrapper(Some("C:\\Program Files\\RDP Wrapper\\termwrap.dll"));
        assert_eq!(s, WrapperState::Installed);
    }

    #[test]
    fn classify_installed_rdpwrap() {
        let (s, _) = classify_wrapper(Some("C:\\Program Files\\RDP Wrapper\\rdpwrap.dll"));
        assert_eq!(s, WrapperState::InstalledRdpWrap);
    }

    #[test]
    fn classify_third_party() {
        let (s, _) = classify_wrapper(Some("C:\\weird\\path\\other.dll"));
        assert_eq!(s, WrapperState::ThirdParty);
    }

    #[test]
    fn classify_unknown_when_missing() {
        let (s, v) = classify_wrapper(None);
        assert_eq!(s, WrapperState::Unknown);
        assert!(v.is_none());
    }

    #[test]
    fn support_known_majors() {
        assert_eq!(classify_support(Some("10.0.19041.1")), SupportLevel::Fully);
        assert_eq!(classify_support(Some("6.3.9600.1")), SupportLevel::Fully);
        assert_eq!(classify_support(Some("6.1.7601.1")), SupportLevel::Fully);
    }

    #[test]
    fn support_unknown_major_is_partial() {
        assert_eq!(classify_support(Some("11.2.0.0")), SupportLevel::Partially);
    }

    #[test]
    fn support_unknown_when_missing() {
        assert_eq!(classify_support(None), SupportLevel::Unknown);
        assert_eq!(classify_support(Some("garbage")), SupportLevel::Unknown);
    }

    #[test]
    fn expand_simple_var() {
        std::env::set_var("__RDPRRAP_TEST_VAR", "BAR");
        assert_eq!(expand_env_vars("foo%__RDPRRAP_TEST_VAR%baz"), "fooBARbaz");
        std::env::remove_var("__RDPRRAP_TEST_VAR");
    }

    #[test]
    fn expand_missing_var_is_verbatim() {
        let out = expand_env_vars("pre%__RDPRRAP_MISSING_VAR%post");
        assert_eq!(out, "pre%__RDPRRAP_MISSING_VAR%post");
    }
}
