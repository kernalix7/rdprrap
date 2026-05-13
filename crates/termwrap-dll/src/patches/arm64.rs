use patcher::arm64 as arm64_pe;
use patcher::patch::{bytecodes, debug_log, write_patch};
use patcher::pattern::{find_pattern_in_section, termsrv_strings as strings};
use patcher::pe::{LoadedPe, SectionInfo};
use windows::Win32::Foundation::HMODULE;

const DEF_POLICY_ALLOW_OFFSET: u32 = 0x638;
const DEF_POLICY_COMPARE_OFFSET: u32 = 0x63c;
const SL_POLICY_CALL_WINDOW: usize = 96;
const ARM64_NOP: u32 = 0xd503_201f;

/// GUID for IS_PNP_DISABLED: {93D359D5-831F-47B4-90BE-8383AF8F1B0E}
const IS_PNP_DISABLED: [u8; 16] = [
    0xD5, 0x59, 0xD3, 0x93, 0x1F, 0x83, 0xB4, 0x47, 0x90, 0xBE, 0x83, 0x83, 0xAF, 0x8F, 0x1B, 0x0E,
];

#[derive(Default)]
struct ResolvedAddrs {
    cdefpolicy_query: Option<arm64_pe::Arm64Function>,
    single_session_enabled: Option<arm64_pe::Arm64Function>,
    single_session_per_user: Option<arm64_pe::Arm64Function>,
    is_local_only: Option<arm64_pe::Arm64Function>,
    is_allow_nonrdp: Option<arm64_pe::Arm64Function>,
    is_appserver: Option<arm64_pe::Arm64Function>,
}

/// Apply ARM64 termsrv.dll patches.
///
/// # Safety
/// - `hmod` must be a valid handle to the loaded termsrv.dll.
/// - All other threads must be suspended.
pub unsafe fn apply_patches(hmod: HMODULE) {
    let base = hmod.0 as usize;

    let pe = match unsafe { LoadedPe::from_base(base) } {
        Ok(pe) => pe,
        Err(e) => {
            debug_log(&format!("TermWrap ARM64: Failed to parse PE: {e}"));
            return;
        }
    };

    let rdata = match pe.find_rdata_section() {
        Ok(s) => s,
        Err(e) => {
            debug_log(&format!("TermWrap ARM64: Failed to find .rdata: {e}"));
            return;
        }
    };

    let cdefpolicy_query_rva = find_pattern_in_section(&pe, &rdata, strings::CDEFPOLICY_QUERY).ok();
    let single_session_enabled_rva =
        find_pattern_in_section(&pe, &rdata, strings::IS_SINGLE_SESSION_ENABLED).ok();
    let is_local_only_rva =
        find_pattern_in_section(&pe, &rdata, strings::CSLQUERY_IS_LOCAL_ONLY).ok();
    let is_allow_nonrdp_rva = find_pattern_in_section(&pe, &rdata, strings::IS_ALLOW_NONRDP).ok();
    let is_appserver_rva =
        find_pattern_in_section(&pe, &rdata, strings::CSLQUERY_IS_APPSERVER).ok();

    let single_session_per_user_rva = single_session_per_user_rva(&pe, &rdata);

    let addrs = ResolvedAddrs {
        cdefpolicy_query: find_function(&pe, cdefpolicy_query_rva),
        single_session_enabled: find_function(&pe, single_session_enabled_rva),
        single_session_per_user: find_function(&pe, single_session_per_user_rva),
        is_local_only: find_function(&pe, is_local_only_rva),
        is_allow_nonrdp: find_function(&pe, is_allow_nonrdp_rva),
        is_appserver: find_function(&pe, is_appserver_rva),
    };

    if let Some(func) = addrs.cdefpolicy_query {
        apply_def_policy(&pe, func);
    } else {
        debug_log("TermWrap ARM64: CDefPolicy_Query not found\n");
    }

    let mut patched_single_user = false;
    if let Some(func) = addrs.single_session_enabled {
        patched_single_user |= patch_function_start(
            &pe,
            func,
            bytecodes::ARM64_MOV_W0_0_RET,
            "SingleSessionEnabled",
        );
    }
    if let Some(func) = addrs.single_session_per_user {
        patched_single_user |= patch_function_start(
            &pe,
            func,
            bytecodes::ARM64_MOV_W0_0_RET,
            "SingleSessionPerUser",
        );
    }
    if !patched_single_user {
        debug_log("TermWrap ARM64: SingleUserPatch not found\n");
    }

    if let Some(func) = addrs.is_local_only {
        patch_function_start(&pe, func, bytecodes::ARM64_MOV_W0_0_RET, "LocalOnly");
    } else {
        debug_log("TermWrap ARM64: IsTerminalTypeLocalOnly not found\n");
    }

    if let Some(func) = addrs.is_appserver {
        patch_function_start(
            &pe,
            func,
            bytecodes::ARM64_MOV_W0_1_RET,
            "IsAppServerInstalled",
        );
    } else {
        debug_log("TermWrap ARM64: IsAppServerInstalled not found\n");
    }

    if let Some(func) = addrs.is_allow_nonrdp {
        patch_function_start(&pe, func, bytecodes::ARM64_MOV_W0_1_RET, "AllowNonRDPStack");
    }

    apply_property_device(&pe, &rdata);
    apply_sl_policy(&pe, &rdata);
}

fn find_function(pe: &LoadedPe, rva: Option<usize>) -> Option<arm64_pe::Arm64Function> {
    arm64_pe::find_function_referencing_rva(pe, rva?)
}

fn single_session_per_user_rva(pe: &LoadedPe, rdata: &SectionInfo) -> Option<usize> {
    find_pattern_in_section(pe, rdata, strings::IS_SINGLE_SESSION_PER_USER)
        .ok()
        .map(|rva| {
            if rva < 8 {
                return rva;
            }

            let check_addr = pe.base + rva - 8;
            // SAFETY: rva >= 8, and the matched string is inside the mapped PE image.
            let prefix = unsafe { std::slice::from_raw_parts(check_addr as *const u8, 8) };
            if prefix == b"CUtils::" {
                rva - 8
            } else {
                rva
            }
        })
}

fn patch_function_start(
    pe: &LoadedPe,
    func: arm64_pe::Arm64Function,
    patch: &[u8],
    label: &str,
) -> bool {
    let len = (func.end_address - func.begin_address) as usize;
    if len < patch.len() {
        debug_log(&format!("TermWrap ARM64: {label} function too short\n"));
        return false;
    }

    let addr = pe.adjusted_base + func.begin_address as usize;
    // SAFETY: addr is the start of an ARM64 function inside loaded PE .text;
    // threads are suspended by the caller.
    match unsafe { write_patch(addr, patch) } {
        Ok(_) => {
            debug_log(&format!("TermWrap ARM64: {label} patched\n"));
            true
        }
        Err(e) => {
            debug_log(&format!(
                "TermWrap ARM64: {label} patch write failed: {e}\n"
            ));
            false
        }
    }
}

fn apply_def_policy(pe: &LoadedPe, func: arm64_pe::Arm64Function) {
    let begin = func.begin_address as usize;
    let len = ((func.end_address - func.begin_address) as usize).min(256);
    if len < 12 {
        debug_log("TermWrap ARM64: DefPolicy function too short\n");
        return;
    }

    // SAFETY: function bounds come from `.pdata` and are clamped to `.text`.
    let code = unsafe { pe.read_bytes(begin, len) };
    let words: Vec<u32> = code
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();

    for (idx, word) in words.iter().copied().enumerate() {
        let Some(load) = arm64_pe::decode_ldr_w_unsigned(word) else {
            continue;
        };
        if load.offset != DEF_POLICY_COMPARE_OFFSET && load.offset != DEF_POLICY_ALLOW_OFFSET {
            continue;
        }
        if !looks_like_def_policy_check(&words, idx) {
            continue;
        }

        let Some(mov) = arm64_pe::encode_movz_w(load.rt, 0x100) else {
            continue;
        };
        let Some(str_word) =
            arm64_pe::encode_str_w_unsigned(load.rt, load.rn, DEF_POLICY_ALLOW_OFFSET)
        else {
            continue;
        };

        let mut patch = Vec::with_capacity(12);
        patch.extend_from_slice(&mov.to_le_bytes());
        patch.extend_from_slice(&str_word.to_le_bytes());
        patch.extend_from_slice(&ARM64_NOP.to_le_bytes());

        let patch_addr = pe.adjusted_base + begin + idx * 4;
        // SAFETY: patch_addr is inside the ARM64 CDefPolicy::Query function;
        // threads are suspended by the caller.
        match unsafe { write_patch(patch_addr, &patch) } {
            Ok(_) => debug_log("TermWrap ARM64: DefPolicyPatch applied\n"),
            Err(e) => debug_log(&format!(
                "TermWrap ARM64: DefPolicyPatch write failed: {e}\n"
            )),
        }
        return;
    }

    debug_log("TermWrap ARM64: DefPolicyPatch not found\n");
}

fn looks_like_def_policy_check(words: &[u32], idx: usize) -> bool {
    let end = (idx + 5).min(words.len());
    words[idx + 1..end]
        .iter()
        .copied()
        .any(arm64_pe::is_cond_branch)
}

fn apply_property_device(pe: &LoadedPe, rdata: &SectionInfo) {
    let Ok(pnp_rva) = find_pattern_in_section(pe, rdata, &IS_PNP_DISABLED) else {
        debug_log("TermWrap ARM64: IS_PNP_DISABLED not found\n");
        return;
    };

    let Some(site) = arm64_pe::find_bl_after_reference_rva(pe, pnp_rva, SL_POLICY_CALL_WINDOW)
    else {
        debug_log("TermWrap ARM64: PropertyDevice call not found\n");
        return;
    };

    let call_addr = pe.adjusted_base + site.call_rva as usize;
    // SAFETY: call_addr is a BL instruction in loaded PE .text; threads are
    // suspended by the caller.
    match unsafe { write_patch(call_addr, bytecodes::ARM64_MOV_W0_0) } {
        Ok(_) => debug_log("TermWrap ARM64: PropertyDevice patched\n"),
        Err(e) => debug_log(&format!(
            "TermWrap ARM64: PropertyDevice write failed: {e}\n"
        )),
    }
}

fn apply_sl_policy(pe: &LoadedPe, rdata: &SectionInfo) {
    let policies = [
        ("AllowRemoteConnections", strings::ALLOW_REMOTE_BYTES),
        (
            "AllowMultipleSessions",
            strings::ALLOW_MULTIPLE_SESSIONS_BYTES,
        ),
        ("AllowAppServerMode", strings::ALLOW_APPSERVER_BYTES),
        ("AllowMultimon", strings::ALLOW_MULTIMON_BYTES),
    ];

    let mut patched = 0usize;
    for (label, pattern) in policies {
        let Ok(rva) = find_pattern_in_section(pe, rdata, pattern) else {
            debug_log(&format!(
                "TermWrap ARM64: SLPolicy {label} string not found\n"
            ));
            continue;
        };

        let Some(site) = arm64_pe::find_bl_after_reference_rva(pe, rva, SL_POLICY_CALL_WINDOW)
        else {
            debug_log(&format!(
                "TermWrap ARM64: SLPolicy {label} call not found\n"
            ));
            continue;
        };

        let call_addr = pe.adjusted_base + site.call_rva as usize;
        // SAFETY: call_addr is a BL instruction in loaded PE .text; threads are
        // suspended by the caller.
        match unsafe { write_patch(call_addr, bytecodes::ARM64_MOV_W0_1) } {
            Ok(_) => {
                patched += 1;
                debug_log(&format!("TermWrap ARM64: SLPolicy {label} patched\n"));
            }
            Err(e) => debug_log(&format!(
                "TermWrap ARM64: SLPolicy {label} write failed: {e}\n"
            )),
        }
    }

    if patched == 0 {
        debug_log("TermWrap ARM64: SLPolicyPatch not found\n");
    }
}
