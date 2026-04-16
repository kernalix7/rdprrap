use crate::error::PatcherError;
use crate::pe::{LoadedPe, SectionInfo};

/// Search for a byte pattern in a PE section at 4-byte aligned offsets.
/// Returns the RVA of the match.
///
/// This mirrors TermWrap's `pattenMatch` function — scanning .rdata for
/// known strings like "CDefPolicy::Query" to locate function references
/// without PDB symbols.
pub fn find_pattern_in_section(
    pe: &LoadedPe,
    section: &SectionInfo,
    pattern: &[u8],
) -> Result<usize, PatcherError> {
    let section_start = pe.base + section.virtual_address as usize;
    let section_size = section.raw_data_size as usize;

    if pattern.len() > section_size {
        return Err(PatcherError::PatternNotFound(
            String::from_utf8_lossy(pattern).to_string(),
        ));
    }

    // Scan at 4-byte aligned offsets (matches TermWrap behavior)
    for offset in (0..=section_size.saturating_sub(pattern.len())).step_by(4) {
        // SAFETY: section_start + offset is within the loaded PE section
        let candidate = unsafe {
            std::slice::from_raw_parts((section_start + offset) as *const u8, pattern.len())
        };

        if candidate == pattern {
            return Ok(section.virtual_address as usize + offset);
        }
    }

    Err(PatcherError::PatternNotFound(
        String::from_utf8_lossy(pattern).to_string(),
    ))
}

/// Well-known strings in termsrv.dll used to locate functions
pub mod termsrv_strings {
    /// CDefPolicy::Query — used to find the multi-session policy check
    pub const CDEFPOLICY_QUERY: &[u8] = b"CDefPolicy::Query";

    /// CSLQuery::IsTerminalTypeLocalOnly — license type check
    pub const CSLQUERY_IS_LOCAL_ONLY: &[u8] = b"CSLQuery::IsTerminalTypeLocalOnly";

    /// CSLQuery::IsAppServerInstalled
    pub const CSLQUERY_IS_APPSERVER: &[u8] = b"CSLQuery::IsAppServerInstalled\0";

    /// CRemoteConnectionManager::IsAllowNonRDPStack
    pub const IS_ALLOW_NONRDP: &[u8] = b"CRemoteConnectionManager::IsAllowNonRDPStack\0";

    /// CSessionArbitrationHelper::IsSingleSessionPerUserEnabled
    pub const IS_SINGLE_SESSION_ENABLED: &[u8] =
        b"CSessionArbitrationHelper::IsSingleSessionPerUserEnabled";

    /// CEnforcementCore::GetInstanceOfTSLicense (note trailing space — intentional)
    pub const GET_INSTANCE_OF_TSLICENSE: &[u8] = b"CEnforcementCore::GetInstanceOfTSLicense ";

    /// CConnectionEx::GetConnectionProperty
    pub const GET_CONNECTION_PROPERTY: &[u8] = b"CConnectionEx::GetConnectionProperty\0";

    /// CUtils::IsSingleSessionPerUser — alternate location
    pub const IS_SINGLE_SESSION_PER_USER: &[u8] = b"IsSingleSessionPerUser\0";

    /// SL policy wide strings used by CSLQuery::Initialize to find in .rdata
    pub const ALLOW_REMOTE_BYTES: &[u8] =
        b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0R\0e\0m\0o\0t\0e\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0M\0a\0n\0a\0g\0e\0r\0-\0A\0l\0l\0o\0w\0R\0e\0m\0o\0t\0e\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\0\0";
    pub const ALLOW_MULTIPLE_SESSIONS_BYTES: &[u8] =
        b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0R\0e\0m\0o\0t\0e\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0M\0a\0n\0a\0g\0e\0r\0-\0A\0l\0l\0o\0w\0M\0u\0l\0t\0i\0p\0l\0e\0S\0e\0s\0s\0i\0o\0n\0s\0\0\0";
    pub const ALLOW_APPSERVER_BYTES: &[u8] =
        b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0R\0e\0m\0o\0t\0e\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0M\0a\0n\0a\0g\0e\0r\0-\0A\0l\0l\0o\0w\0A\0p\0p\0S\0e\0r\0v\0e\0r\0M\0o\0d\0e\0\0\0";
    pub const ALLOW_MULTIMON_BYTES: &[u8] =
        b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0R\0e\0m\0o\0t\0e\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0M\0a\0n\0a\0g\0e\0r\0-\0A\0l\0l\0o\0w\0M\0u\0l\0t\0i\0m\0o\0n\0\0\0";
}
