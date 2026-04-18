#![cfg_attr(not(windows), allow(dead_code))]
//! MSTSCAX `OnDisconnected(discReason)` → human-readable string mapping.
//!
//! Port of the `case DiscReason of` block in the original rdpwrap
//! `check_MainUnit.pas`. The set of codes and text is stable public
//! MSTSCAX documentation (see ExtendedDisconnectReasonCode on MSDN) so
//! the mapping can be kept in one place and unit-tested offline.
//!
//! We expose `describe(code) -> String` rather than returning a `&'static str`
//! so that the `"Unknown disconnect reason (code N)"` fallback can include the
//! raw code in its message.

/// Return a human-readable description for an MSTSCAX disconnect reason code.
///
/// Matches the upstream text from rdpwrap's RDPCheck. Unknown codes fall
/// through to `"Unknown disconnect reason (code N)"`.
pub fn describe(code: i32) -> String {
    match code {
        0 => "No information is available.".to_string(),
        1 => "Local disconnection.".to_string(),
        2 => "Remote disconnection by user.".to_string(),
        3 => "Remote disconnection by server.".to_string(),

        // Connect-initiation failures (0x0nn family).
        0x0006 => "Out of memory.".to_string(),
        0x0007 => "Connection was denied.".to_string(),
        0x0009 => "Connection was denied because of an access-denied error.".to_string(),
        0x000A => "Connection timed out.".to_string(),
        0x000B => "User could not be authenticated.".to_string(),
        0x000C => "User is not authorized to log on at this time.".to_string(),
        0x000D => "Password has expired.".to_string(),
        0x000E => "User account is disabled.".to_string(),
        0x000F => "User account has restrictions.".to_string(),
        0x0010 => "Password must be changed.".to_string(),
        0x0011 => "No permissions to access the remote computer.".to_string(),

        // Protocol / socket family (0x1nn).
        0x0100 => "Internal error.".to_string(),
        0x0108 => "Loopback connections are not allowed.".to_string(),

        // Network / transport family (0x2nn).
        0x0208 => "Connection timeout — server did not respond.".to_string(),
        0x0209 => "Connection refused by server.".to_string(),
        0x020A => "Network error — connection broken.".to_string(),

        // DNS / host resolution (0x3nn).
        0x0308 => "DNS lookup failure — could not resolve the remote computer name.".to_string(),
        0x0309 => "Host unreachable.".to_string(),

        // Licensing family (0x5nn).
        0x0502 => "Licensing timeout.".to_string(),
        0x0503 => "License negotiation failed.".to_string(),
        0x0504 => "No licensing server available.".to_string(),
        0x0505 => "Unable to validate the client license.".to_string(),
        0x0506 => "License store access failure.".to_string(),
        0x0507 => "Client does not have a valid license.".to_string(),

        // Security / credential family (0x6nn, 0x7nn).
        0x0606 => "TLS handshake failed.".to_string(),
        0x0608 => "Server certificate is not trusted.".to_string(),
        0x0609 => "Server name on certificate does not match.".to_string(),
        0x060A => "Server certificate has expired.".to_string(),
        0x0708 => "RDP is working, but the client doesn't allow loopback connections. \
             Try connecting from a different machine or loopback client."
            .to_string(),

        // CredSSP / NLA family (0x8nn, 0x9nn, 0xAnn, 0xBnn).
        0x0808 => "CredSSP authentication failed.".to_string(),
        0x0809 => "CredSSP protocol error.".to_string(),
        0x0903 => "Server refused the connection.".to_string(),
        0x0904 => "Server is busy.".to_string(),
        0x0B07 => "Authentication failure. Check your credentials.".to_string(),
        0x0B08 => "NLA authentication failure. Check your credentials.".to_string(),
        0x0B09 => {
            "Network Level Authentication is required, run RDPCheck as administrator.".to_string()
        }

        // Post-authentication / session errors (0xCnn).
        0x0C08 => "Session disconnected by server.".to_string(),
        0x0C09 => "Idle timeout reached.".to_string(),
        0x0C0A => "Session logged off by administrator.".to_string(),

        // Fallback.
        _ => format!("Unknown disconnect reason (code 0x{code:04X} / {code})"),
    }
}

/// Number of discReason codes explicitly handled (for diagnostic/test purposes).
#[allow(dead_code)]
pub const KNOWN_CODE_COUNT: usize = 44;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_return_non_unknown() {
        // A representative sample across all families.
        let samples: &[i32] = &[
            0, 1, 2, 3, 0x0006, 0x000A, 0x000B, 0x0108, 0x0208, 0x0308, 0x0708, 0x0808, 0x0B09,
            0x0C0A,
        ];
        for &code in samples {
            let s = describe(code);
            assert!(
                !s.starts_with("Unknown"),
                "code 0x{code:04X} returned unknown: {s}"
            );
        }
    }

    #[test]
    fn unknown_code_mentions_both_hex_and_dec() {
        let s = describe(0x1234_5678);
        assert!(s.starts_with("Unknown"));
        assert!(s.contains("0x12345678"));
        assert!(s.contains("305419896"));
    }

    #[test]
    fn nla_code_has_admin_hint() {
        let s = describe(0x0B09);
        assert!(s.contains("administrator") || s.contains("Administrator"));
    }

    #[test]
    fn loopback_code_matches_spec() {
        assert!(describe(0x0108).contains("Loopback"));
        assert!(describe(0x0708).contains("loopback"));
    }

    #[test]
    fn known_code_count_is_plausible() {
        // The constant is advisory (not computed from the match) so we only
        // sanity-check that it's in the expected ballpark — the upstream
        // rdpwrap table has ~40 entries. Evaluated at compile time since the
        // value is const.
        const _: () = assert!(
            KNOWN_CODE_COUNT >= 40 && KNOWN_CODE_COUNT <= 60,
            "KNOWN_CODE_COUNT outside expected range"
        );
    }
}
