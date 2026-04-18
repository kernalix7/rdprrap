mod def_policy;
mod local_only;
mod nonrdp;
mod property_device;
mod single_user;
mod sl_policy;

use patcher::patch::debug_log;
use patcher::pattern::{find_pattern_in_section, termsrv_strings as strings};
use patcher::pe::LoadedPe;
use windows::Win32::Foundation::HMODULE;

#[cfg(target_arch = "x86_64")]
use patcher::disasm::search_xref_in_function;

/// Resolved function addresses for all patch targets
struct ResolvedAddrs {
    cdefpolicy_query: Option<usize>,
    get_instance_of_tslicense: Option<usize>,
    single_session_enabled: Option<usize>,
    single_session_per_user: Option<usize>,
    is_local_only: Option<usize>,
    is_allow_nonrdp: Option<usize>,
    is_appserver: Option<usize>,
    get_connection_property: Option<usize>,
    cslquery_initialize: Option<usize>,
    cslquery_initialize_len: usize,
    #[cfg(target_arch = "x86_64")]
    is_appserver_idx: usize,
}

/// Apply all termsrv.dll patches.
///
/// # Safety
/// - `hmod` must be a valid handle to the loaded termsrv.dll
/// - All other threads must be suspended
pub unsafe fn apply_patches(hmod: HMODULE) {
    let base = hmod.0 as usize;

    let pe = match unsafe { LoadedPe::from_base(base) } {
        Ok(pe) => pe,
        Err(e) => {
            debug_log(&format!("Failed to parse PE: {e}"));
            return;
        }
    };

    let rdata = match pe.find_rdata_section() {
        Ok(s) => s,
        Err(e) => {
            debug_log(&format!("Failed to find .rdata: {e}"));
            return;
        }
    };

    // Locate known strings in .rdata
    let cdefpolicy_query_rva = find_pattern_in_section(&pe, &rdata, strings::CDEFPOLICY_QUERY).ok();
    let get_instance_rva =
        find_pattern_in_section(&pe, &rdata, strings::GET_INSTANCE_OF_TSLICENSE).ok();
    let single_session_enabled_rva =
        find_pattern_in_section(&pe, &rdata, strings::IS_SINGLE_SESSION_ENABLED).ok();
    let is_local_only_rva =
        find_pattern_in_section(&pe, &rdata, strings::CSLQUERY_IS_LOCAL_ONLY).ok();
    let is_allow_nonrdp_rva = find_pattern_in_section(&pe, &rdata, strings::IS_ALLOW_NONRDP).ok();
    let is_appserver_rva =
        find_pattern_in_section(&pe, &rdata, strings::CSLQUERY_IS_APPSERVER).ok();
    let get_connection_property_rva =
        find_pattern_in_section(&pe, &rdata, strings::GET_CONNECTION_PROPERTY).ok();
    let allow_remote_rva = find_pattern_in_section(&pe, &rdata, strings::ALLOW_REMOTE_BYTES).ok();

    // IsSingleSessionPerUser — check for CUtils:: prefix
    let single_session_per_user_rva =
        find_pattern_in_section(&pe, &rdata, strings::IS_SINGLE_SESSION_PER_USER)
            .ok()
            .map(|rva| {
                // Check if "CUtils::" prefix exists 8 bytes before
                if rva < 8 {
                    return rva;
                }
                let check_addr = pe.base + rva - 8;
                // SAFETY: check_addr is within the mapped PE image (rva >= 8 checked above)
                let prefix = unsafe { std::slice::from_raw_parts(check_addr as *const u8, 8) };
                if prefix == b"CUtils::" {
                    rva - 8
                } else {
                    rva
                }
            });

    // Find import functions
    let imports = pe.get_imports();
    let memset_addr = find_memset_import(&pe, &imports);
    let verify_version_addr = find_verify_version_import(&pe, &imports);

    // Resolve function addresses
    #[cfg(target_arch = "x86_64")]
    let addrs = resolve_functions_x64(
        &pe,
        cdefpolicy_query_rva,
        get_instance_rva,
        single_session_enabled_rva,
        single_session_per_user_rva,
        is_local_only_rva,
        is_allow_nonrdp_rva,
        is_appserver_rva,
        get_connection_property_rva,
        allow_remote_rva,
    );

    #[cfg(target_arch = "x86")]
    let addrs = resolve_functions_x86(
        &pe,
        cdefpolicy_query_rva,
        get_instance_rva,
        single_session_enabled_rva,
        single_session_per_user_rva,
        is_local_only_rva,
        is_allow_nonrdp_rva,
        is_appserver_rva,
        get_connection_property_rva,
        allow_remote_rva,
    );

    // === Apply SingleUserPatch ===
    if let Some(memset) = memset_addr {
        let mut patched = false;
        if let Some(addr) = addrs.single_session_enabled {
            if unsafe { single_user::apply(&pe, addr, memset, verify_version_addr) } {
                patched = true;
            }
        }
        if let Some(addr) = addrs.single_session_per_user {
            if unsafe { single_user::apply(&pe, addr, memset, verify_version_addr) } {
                patched = true;
            }
        }
        if !patched {
            debug_log("SingleUserPatch not found\n");
        }
    }

    // === Apply DefPolicyPatch ===
    if let Some(addr) = addrs.cdefpolicy_query {
        unsafe { def_policy::apply(&pe, addr) };
    } else {
        debug_log("CDefPolicy_Query not found\n");
    }

    // === Apply PropertyDevicePatch ===
    if let Some(conn_prop_addr) = addrs.get_connection_property {
        let pnp_disabled_rva =
            find_pattern_in_section(&pe, &rdata, &property_device::IS_PNP_DISABLED);
        if let Ok(pnp_rva) = pnp_disabled_rva {
            if let Some(prop_addr) =
                unsafe { property_device::find_property_device_addr(&pe, conn_prop_addr, pnp_rva) }
            {
                unsafe { property_device::apply(&pe, prop_addr) };
            } else {
                debug_log("PropertyAddr not found\n");
            }
        } else {
            debug_log("IS_PNP_DISABLED not found\n");
        }
    } else {
        debug_log("GetConnectionProperty not found\n");
    }

    // === Check CSLQuery::Initialize ===
    if addrs.cslquery_initialize.is_none() {
        debug_log("CSLQuery_Initialize not found\n");
        return;
    }

    // === Apply LocalOnlyPatch ===
    if let Some(instance_addr) = addrs.get_instance_of_tslicense {
        if let Some(local_only_addr) = addrs.is_local_only {
            unsafe { local_only::apply(&pe, instance_addr, local_only_addr) };
        } else {
            debug_log("IsLicenseTypeLocalOnly not found\n");
        }
    } else {
        debug_log("GetInstanceOfTSLicense not found\n");
    }

    // === Apply NonRDPPatch ===
    if let Some(nonrdp_addr) = addrs.is_allow_nonrdp {
        if let Some(appserver_addr) = addrs.is_appserver {
            if !unsafe { nonrdp::apply(&pe, nonrdp_addr, appserver_addr) } {
                // IsAppServerInstalled may be inlined, try searching more
                #[cfg(target_arch = "x86_64")]
                {
                    let func_table = pe.get_exception_table().unwrap_or_default();
                    let mut found = false;
                    for func in func_table.iter().skip(addrs.is_appserver_idx) {
                        if let Some(is_appserver_rva) = is_appserver_rva {
                            if search_xref_in_function(&pe, func, is_appserver_rva as u64).is_some()
                            {
                                let bt = pe.backtrace_function(func);
                                if unsafe {
                                    nonrdp::apply(&pe, nonrdp_addr, bt.begin_address as usize)
                                } {
                                    found = true;
                                    break;
                                }
                            }
                        }
                    }
                    if !found {
                        debug_log("NonRDPPatch not found\n");
                    }
                }
            }
        } else {
            debug_log("IsAppServerInstalled not found\n");
        }
    }

    // === Apply CSLQuery::Initialize SL policy patching ===
    if let Some(init_rva) = addrs.cslquery_initialize {
        let allow_multiple_rva =
            find_pattern_in_section(&pe, &rdata, strings::ALLOW_MULTIPLE_SESSIONS_BYTES).ok();
        let allow_appserver_rva =
            find_pattern_in_section(&pe, &rdata, strings::ALLOW_APPSERVER_BYTES).ok();
        let allow_multimon_rva =
            find_pattern_in_section(&pe, &rdata, strings::ALLOW_MULTIMON_BYTES).ok();

        // Clamp length to available memory (x86 has no exception table, uses hardcoded 0x11000)
        let text = pe.find_section(".text").ok();
        let max_len = text
            .map(|t| {
                let text_end = t.virtual_address as usize + t.raw_data_size as usize;
                text_end.saturating_sub(init_rva)
            })
            .unwrap_or(addrs.cslquery_initialize_len);
        let safe_len = addrs.cslquery_initialize_len.min(max_len);

        unsafe {
            sl_policy::apply(
                &pe,
                init_rva,
                safe_len,
                allow_remote_rva,
                allow_multiple_rva,
                allow_appserver_rva,
                allow_multimon_rva,
            )
        };
    }
}

/// Find memset import thunk RVA
fn find_memset_import(pe: &LoadedPe, imports: &[patcher::pe::ImportInfo]) -> Option<usize> {
    for dll in &["api-ms-win-crt-string-l1-1-0.dll", "msvcrt.dll"] {
        if let Some(imp) = imports
            .iter()
            .find(|i| i.dll_name.eq_ignore_ascii_case(dll))
        {
            if let Ok(rva) = pe.find_import_function(imp, "memset") {
                return Some(rva);
            }
        }
    }
    None
}

/// Find VerifyVersionInfoW import thunk RVA
fn find_verify_version_import(pe: &LoadedPe, imports: &[patcher::pe::ImportInfo]) -> Option<usize> {
    for dll in &["api-ms-win-core-kernel32-legacy-l1-1-1.dll", "KERNEL32.dll"] {
        if let Some(imp) = imports
            .iter()
            .find(|i| i.dll_name.eq_ignore_ascii_case(dll))
        {
            if let Ok(rva) = pe.find_import_function(imp, "VerifyVersionInfoW") {
                return Some(rva);
            }
        }
    }
    None
}

/// x64: resolve all function addresses by scanning exception table for xrefs
#[cfg(target_arch = "x86_64")]
#[allow(clippy::too_many_arguments)]
fn resolve_functions_x64(
    pe: &LoadedPe,
    cdefpolicy_query_rva: Option<usize>,
    get_instance_rva: Option<usize>,
    single_session_enabled_rva: Option<usize>,
    single_session_per_user_rva: Option<usize>,
    is_local_only_rva: Option<usize>,
    is_allow_nonrdp_rva: Option<usize>,
    is_appserver_rva: Option<usize>,
    get_connection_property_rva: Option<usize>,
    allow_remote_rva: Option<usize>,
) -> ResolvedAddrs {
    let func_table = pe.get_exception_table().unwrap_or_default();

    let mut addrs = ResolvedAddrs {
        cdefpolicy_query: None,
        get_instance_of_tslicense: None,
        single_session_enabled: None,
        single_session_per_user: None,
        is_local_only: None,
        is_allow_nonrdp: None,
        is_appserver: None,
        get_connection_property: None,
        cslquery_initialize: None,
        cslquery_initialize_len: 0x11000,
        is_appserver_idx: 0,
    };

    for (i, func) in func_table.iter().enumerate() {
        macro_rules! try_resolve {
            ($field:ident, $rva:expr) => {
                if addrs.$field.is_none() {
                    if let Some(rva) = $rva {
                        if search_xref_in_function(pe, func, rva as u64).is_some() {
                            let bt = pe.backtrace_function(func);
                            addrs.$field = Some(bt.begin_address as usize);
                            continue;
                        }
                    }
                }
            };
        }

        try_resolve!(cdefpolicy_query, cdefpolicy_query_rva);
        try_resolve!(get_instance_of_tslicense, get_instance_rva);
        try_resolve!(single_session_enabled, single_session_enabled_rva);
        try_resolve!(single_session_per_user, single_session_per_user_rva);
        try_resolve!(is_local_only, is_local_only_rva);

        if addrs.is_allow_nonrdp.is_none() && is_allow_nonrdp_rva.is_some() {
            if let Some(rva) = is_allow_nonrdp_rva {
                if search_xref_in_function(pe, func, rva as u64).is_some() {
                    addrs.is_allow_nonrdp =
                        Some(pe.backtrace_function(func).begin_address as usize);
                    continue;
                }
            }
        }

        if addrs.is_appserver.is_none() {
            if let Some(rva) = is_appserver_rva {
                if search_xref_in_function(pe, func, rva as u64).is_some() {
                    addrs.is_appserver = Some(pe.backtrace_function(func).begin_address as usize);
                    addrs.is_appserver_idx = i;
                    continue;
                }
            }
        }

        try_resolve!(get_connection_property, get_connection_property_rva);

        if addrs.cslquery_initialize.is_none() {
            if let Some(rva) = allow_remote_rva {
                if search_xref_in_function(pe, func, rva as u64).is_some() {
                    let bt = pe.backtrace_function(func);
                    addrs.cslquery_initialize = Some(bt.begin_address as usize);
                    addrs.cslquery_initialize_len = (bt.end_address - bt.begin_address) as usize;
                    continue;
                }
            }
        }

        // Check if all found
        if addrs.cdefpolicy_query.is_some()
            && addrs.get_instance_of_tslicense.is_some()
            && addrs.single_session_enabled.is_some()
            && addrs.single_session_per_user.is_some()
            && addrs.is_local_only.is_some()
            && (addrs.is_allow_nonrdp.is_some() || is_allow_nonrdp_rva.is_none())
            && addrs.is_appserver.is_some()
            && addrs.get_connection_property.is_some()
            && addrs.cslquery_initialize.is_some()
        {
            break;
        }
    }

    addrs
}

/// x86: resolve function addresses by scanning .text for function prologues
/// and PUSH/MOV immediate references to string RVAs
#[cfg(target_arch = "x86")]
#[allow(clippy::too_many_arguments)]
fn resolve_functions_x86(
    pe: &LoadedPe,
    cdefpolicy_query_rva: Option<usize>,
    get_instance_rva: Option<usize>,
    single_session_enabled_rva: Option<usize>,
    single_session_per_user_rva: Option<usize>,
    is_local_only_rva: Option<usize>,
    is_allow_nonrdp_rva: Option<usize>,
    is_appserver_rva: Option<usize>,
    get_connection_property_rva: Option<usize>,
    allow_remote_rva: Option<usize>,
) -> ResolvedAddrs {
    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;

    let text = match pe.find_section(".text") {
        Ok(s) => s,
        Err(_) => {
            debug_log("x86: .text section not found\n");
            return ResolvedAddrs {
                cdefpolicy_query: None,
                get_instance_of_tslicense: None,
                single_session_enabled: None,
                single_session_per_user: None,
                is_local_only: None,
                is_allow_nonrdp: None,
                is_appserver: None,
                get_connection_property: None,
                cslquery_initialize: None,
                cslquery_initialize_len: 0x11000,
            };
        }
    };

    let mut addrs = ResolvedAddrs {
        cdefpolicy_query: None,
        get_instance_of_tslicense: None,
        single_session_enabled: None,
        single_session_per_user: None,
        is_local_only: None,
        is_allow_nonrdp: None,
        is_appserver: None,
        get_connection_property: None,
        cslquery_initialize: None,
        cslquery_initialize_len: 0x11000,
    };

    let base = pe.adjusted_base;
    let text_start = base + text.virtual_address as usize;
    let text_size = text.raw_data_size as usize;

    // x86 prologue pattern: mov edi,edi; push ebp; mov ebp,esp
    const PROLOGUE: &[u8] = &[0x8B, 0xFF, 0x55, 0x8B, 0xEC];

    let all_rvas: Vec<(usize, &str)> = [
        (cdefpolicy_query_rva, "cdefpolicy"),
        (get_instance_rva, "get_instance"),
        (single_session_enabled_rva, "single_enabled"),
        (single_session_per_user_rva, "single_per_user"),
        (is_local_only_rva, "local_only"),
        (is_allow_nonrdp_rva, "nonrdp"),
        (is_appserver_rva, "appserver"),
        (get_connection_property_rva, "conn_property"),
        (allow_remote_rva, "allow_remote"),
    ]
    .iter()
    .filter_map(|(rva, name)| rva.map(|r| (r, *name)))
    .collect();

    let mut ip = text_start;
    let mut remaining = text_size;

    while remaining >= 5 {
        // SAFETY: ip is within the .text section (text_start..text_start+text_size)
        let prologue_match = unsafe { std::slice::from_raw_parts(ip as *const u8, 5) };

        if prologue_match != PROLOGUE {
            ip += 1;
            remaining -= 1;
            continue;
        }

        let func_start_rva = ip - base;

        // Decode the function with a priority queue for branch targets
        let mut jmp_addrs: BinaryHeap<Reverse<usize>> = BinaryHeap::new();
        jmp_addrs.push(Reverse(ip));

        while let Some(Reverse(block_start)) = jmp_addrs.pop() {
            // SAFETY: block_start is within .text section, avail is clamped to section bounds
            let block_code = unsafe {
                let avail = text_size.saturating_sub(block_start - text_start);
                std::slice::from_raw_parts(block_start as *const u8, avail.min(4096))
            };
            let mut decoder =
                Decoder::with_ip(32, block_code, block_start as u64, DecoderOptions::NONE);
            let mut inst = Instruction::default();

            while decoder.can_decode() {
                decoder.decode_out(&mut inst);

                // Check PUSH imm32 (5 bytes) or MOV reg/mem, imm32
                let is_push_imm32 = inst.len() == 5
                    && inst.mnemonic() == Mnemonic::Push
                    && inst.op0_kind() == OpKind::Immediate32;
                let is_mov_imm32 = inst.mnemonic() == Mnemonic::Mov
                    && inst.op1_kind() == OpKind::Immediate32
                    && ((inst.op0_kind() == OpKind::Register && inst.len() == 5)
                        || (inst.op0_kind() == OpKind::Memory
                            && inst.len() >= 7
                            && (inst.memory_base() == Register::EBP
                                || inst.memory_base() == Register::ESP)));
                let target_val = if is_push_imm32 || is_mov_imm32 {
                    Some((inst.immediate32() as usize).wrapping_sub(base))
                } else {
                    None
                };

                if let Some(tv) = target_val {
                    for &(rva, name) in &all_rvas {
                        if tv == rva {
                            match name {
                                "cdefpolicy" if addrs.cdefpolicy_query.is_none() => {
                                    addrs.cdefpolicy_query = Some(func_start_rva);
                                }
                                "get_instance" if addrs.get_instance_of_tslicense.is_none() => {
                                    addrs.get_instance_of_tslicense = Some(func_start_rva);
                                }
                                "single_enabled" if addrs.single_session_enabled.is_none() => {
                                    addrs.single_session_enabled = Some(func_start_rva);
                                }
                                "single_per_user" if addrs.single_session_per_user.is_none() => {
                                    addrs.single_session_per_user = Some(func_start_rva);
                                }
                                "local_only" if addrs.is_local_only.is_none() => {
                                    addrs.is_local_only = Some(func_start_rva);
                                }
                                "nonrdp" if addrs.is_allow_nonrdp.is_none() => {
                                    addrs.is_allow_nonrdp = Some(func_start_rva);
                                }
                                "appserver" if addrs.is_appserver.is_none() => {
                                    addrs.is_appserver = Some(func_start_rva);
                                }
                                "conn_property" if addrs.get_connection_property.is_none() => {
                                    addrs.get_connection_property = Some(func_start_rva);
                                }
                                "allow_remote" if addrs.cslquery_initialize.is_none() => {
                                    addrs.cslquery_initialize = Some(func_start_rva);
                                }
                                _ => continue,
                            }
                            // Found a match — skip rest of this function
                            break;
                        }
                    }
                }

                // Follow conditional branches
                if inst.mnemonic() >= Mnemonic::Ja
                    && inst.mnemonic() <= Mnemonic::Js
                    && inst.mnemonic() != Mnemonic::Jmp
                    && inst.op0_kind() == OpKind::NearBranch32
                {
                    let branch = inst.near_branch_target() as usize;
                    if branch >= text_start && branch < text_start + text_size {
                        jmp_addrs.push(Reverse(branch));
                    }
                }

                if inst.mnemonic() == Mnemonic::Ret || inst.mnemonic() == Mnemonic::Jmp {
                    break;
                }
            }
        }

        // Check if all found
        let all_found = addrs.cdefpolicy_query.is_some()
            && addrs.get_instance_of_tslicense.is_some()
            && addrs.single_session_enabled.is_some()
            && addrs.single_session_per_user.is_some()
            && addrs.is_local_only.is_some()
            && (addrs.is_allow_nonrdp.is_some() || is_allow_nonrdp_rva.is_none())
            && addrs.is_appserver.is_some()
            && addrs.cslquery_initialize.is_some()
            && addrs.get_connection_property.is_some();

        if all_found {
            break;
        }

        ip += 5;
        remaining -= 5;
    }

    addrs
}
