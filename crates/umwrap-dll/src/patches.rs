use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use patcher::patch::{bytecodes, debug_log, write_patch};
use patcher::pattern::find_pattern_in_section;
use patcher::pe::{LoadedPe, RuntimeFunction};
use windows::Win32::Foundation::HMODULE;

/// Wide string: "TerminalServices-DeviceRedirection-Licenses-PnpRedirectionAllowed"
const ALLOW_PNP_BYTES: &[u8] =
    b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0D\0e\0v\0i\0c\0e\0R\0e\0d\0i\0r\0e\0c\0t\0i\0o\0n\0-\0L\0i\0c\0e\0n\0s\0e\0s\0-\0P\0n\0p\0R\0e\0d\0i\0r\0e\0c\0t\0i\0o\0n\0A\0l\0l\0o\0w\0e\0d\0\0\0";

/// Wide string: "TerminalServices-DeviceRedirection-Licenses-CameraRedirectionAllowed"
const ALLOW_CAMERA_BYTES: &[u8] =
    b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0D\0e\0v\0i\0c\0e\0R\0e\0d\0i\0r\0e\0c\0t\0i\0o\0n\0-\0L\0i\0c\0e\0n\0s\0e\0s\0-\0C\0a\0m\0e\0r\0a\0R\0e\0d\0i\0r\0e\0c\0t\0i\0o\0n\0A\0l\0l\0o\0w\0e\0d\0\0\0";

/// Apply umrdp.dll patches for PnP and camera redirection.
///
/// # Safety
/// `hmod` must be a valid handle to the loaded umrdp.dll, threads suspended
pub unsafe fn apply_patches(hmod: HMODULE) {
    let base = hmod.0 as usize;

    let pe = match unsafe { LoadedPe::from_base(base) } {
        Ok(pe) => pe,
        Err(e) => {
            debug_log(&format!("UmWrap: Failed to parse PE: {e}"));
            return;
        }
    };

    let rdata = match pe.find_rdata_section() {
        Ok(s) => s,
        Err(e) => {
            debug_log(&format!("UmWrap: Failed to find .rdata: {e}"));
            return;
        }
    };

    let pnp_rva = match find_pattern_in_section(&pe, &rdata, ALLOW_PNP_BYTES) {
        Ok(rva) => rva,
        Err(_) => {
            debug_log("PnpRedirectionAllowed not found\n");
            return;
        }
    };
    let camera_rva = find_pattern_in_section(&pe, &rdata, ALLOW_CAMERA_BYTES).ok();

    let func_table = match pe.get_exception_table() {
        Some(t) => t,
        None => {
            debug_log("UmWrap: no exception table\n");
            return;
        }
    };

    // Detect legacy mode (imports slc.dll)
    let legacy = pe.find_import_image("slc.dll").is_some();

    let adjusted = pe.adjusted_base;

    for func in func_table.iter() {
        let begin = func.begin_address as usize;
        let length = (func.end_address - func.begin_address) as usize;
        let code = unsafe { std::slice::from_raw_parts((adjusted + begin) as *const u8, length) };
        let mut decoder =
            Decoder::with_ip(64, code, (adjusted + begin) as u64, DecoderOptions::NONE);
        let mut inst = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut inst);

            // Look for LEA reg, [rip+disp] pointing to PnpRedirectionAllowed
            if inst.mnemonic() == Mnemonic::Lea
                && inst.op1_kind() == OpKind::Memory
                && inst.memory_base() == Register::RIP
                && inst.op0_kind() == OpKind::Register
            {
                let lea_target = inst.memory_displacement64();
                if lea_target != (adjusted + pnp_rva) as u64 {
                    continue;
                }

                // Found PnpRedirectionAllowed reference
                let remaining_len =
                    length.saturating_sub((decoder.ip() as usize) - (adjusted + begin));

                // Short-circuit: if large function and no camera string and not legacy
                if remaining_len > 0x1000 && camera_rva.is_none() && !legacy {
                    // Patch function start: xor eax,eax; inc eax; ret
                    let bt = pe.backtrace_function(func);
                    let func_addr = adjusted + bt.begin_address as usize;
                    if let Err(e) = unsafe { write_patch(func_addr, bytecodes::XOR_EAX_INC_RET) } {
                        debug_log(&format!("UmWrap: PnP shortcut write failed: {e}\n"));
                    }
                    return;
                }

                // Search for CALL (5 bytes) after the LEA
                let search_code = unsafe {
                    std::slice::from_raw_parts(
                        decoder.ip() as usize as *const u8,
                        16.min(remaining_len),
                    )
                };
                let mut search_decoder =
                    Decoder::with_ip(64, search_code, decoder.ip(), DecoderOptions::NONE);
                let mut search_inst = Instruction::default();

                while search_decoder.can_decode() {
                    let call_ip = search_decoder.ip() as usize;
                    search_decoder.decode_out(&mut search_inst);

                    if search_inst.mnemonic() == Mnemonic::Call && search_inst.len() == 5 {
                        if !legacy {
                            // mov eax, 1
                            if let Err(e) = unsafe { write_patch(call_ip, bytecodes::MOV_EAX_1) } {
                                debug_log(&format!("UmWrap: PnP patch write failed: {e}\n"));
                            }

                            // Also patch camera if available
                            if let Some(cam_rva) = camera_rva {
                                if !unsafe { search_and_patch_camera(&pe, func, cam_rva) } {
                                    debug_log("CameraRedirection patch not found\n");
                                }
                            }
                        } else {
                            // Legacy: check for TEST after CALL
                            if search_decoder.can_decode() {
                                search_decoder.decode_out(&mut search_inst);
                                if search_inst.mnemonic() == Mnemonic::Test
                                    && search_inst.len() == 2
                                {
                                    // or dword ptr [rsp+0x40], 1; xor eax, eax
                                    let legacy_patch: &[u8] =
                                        &[0x83, 0x4C, 0x24, 0x40, 0x01, 0x31, 0xC0];
                                    if let Err(e) = unsafe { write_patch(call_ip, legacy_patch) } {
                                        debug_log(&format!(
                                            "UmWrap: legacy PnP patch failed: {e}\n"
                                        ));
                                    }
                                } else {
                                    continue; // not the right CALL, keep searching
                                }
                            }
                        }
                        return;
                    }
                }

                debug_log("PnpRedirection patch not found\n");
                return;
            }
        }
    }

    debug_log("Found nothing to patch\n");
}

/// Search within a function for a LEA to camera RVA, then patch the CALL after it.
///
/// # Safety
/// Threads must be suspended
unsafe fn search_and_patch_camera(
    pe: &LoadedPe,
    func: &RuntimeFunction,
    camera_rva: usize,
) -> bool {
    let adjusted = pe.adjusted_base;
    let begin = func.begin_address as usize;
    let length = (func.end_address - func.begin_address) as usize;
    let code = unsafe { std::slice::from_raw_parts((adjusted + begin) as *const u8, length) };
    let mut decoder = Decoder::with_ip(64, code, (adjusted + begin) as u64, DecoderOptions::NONE);
    let mut inst = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut inst);

        if inst.mnemonic() == Mnemonic::Lea
            && inst.op1_kind() == OpKind::Memory
            && inst.memory_base() == Register::RIP
            && inst.op0_kind() == OpKind::Register
        {
            let lea_target = inst.memory_displacement64();
            if lea_target != (adjusted + camera_rva) as u64 {
                continue;
            }

            // Find CALL after LEA
            let remaining = 16usize;
            let search_code = unsafe {
                std::slice::from_raw_parts(decoder.ip() as usize as *const u8, remaining)
            };
            let mut search = Decoder::with_ip(64, search_code, decoder.ip(), DecoderOptions::NONE);
            let mut search_inst = Instruction::default();

            while search.can_decode() {
                let call_ip = search.ip() as usize;
                search.decode_out(&mut search_inst);

                if search_inst.mnemonic() == Mnemonic::Call && search_inst.len() == 5 {
                    if let Err(e) = unsafe { write_patch(call_ip, bytecodes::MOV_EAX_1) } {
                        debug_log(&format!("CameraRedirection write failed: {e}\n"));
                        return false;
                    }
                    return true;
                }
            }
            return false;
        }
    }

    false
}
