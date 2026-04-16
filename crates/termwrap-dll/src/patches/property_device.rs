use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use patcher::patch::{debug_log, write_patch};
use patcher::pe::LoadedPe;

/// GUID for IS_PNP_DISABLED: {93D359D5-831F-47B4-90BE-8383AF8F1B0E}
pub const IS_PNP_DISABLED: [u8; 16] = [
    0xD5, 0x59, 0xD3, 0x93, 0x1F, 0x83, 0xB4, 0x47, 0x90, 0xBE, 0x83, 0x83, 0xAF, 0x8F, 0x1B, 0x0E,
];

/// Find the address of the inner function called from GetConnectionProperty
/// that references the IS_PNP_DISABLED GUID.
///
/// # Safety
/// PE must be valid and loaded
pub unsafe fn find_property_device_addr(
    pe: &LoadedPe,
    func_rva: usize,
    pnp_disabled_rva: usize,
) -> Option<usize> {
    let base = pe.adjusted_base;
    let ip_start = base + func_rva;
    let target_abs = (base + pnp_disabled_rva) as u64;
    let code = unsafe { std::slice::from_raw_parts(ip_start as *const u8, 256) };

    let bits = if cfg!(target_arch = "x86_64") { 64 } else { 32 };
    let mut decoder = Decoder::with_ip(bits, code, ip_start as u64, DecoderOptions::NONE);
    let mut inst = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut inst);

        #[cfg(target_arch = "x86_64")]
        {
            // Look for MOV reg, [rip+disp] pointing to IS_PNP_DISABLED
            if inst.mnemonic() == Mnemonic::Mov
                && inst.op0_kind() == OpKind::Register
                && inst.op1_kind() == OpKind::Memory
            {
                let resolved = if inst.memory_base() == Register::RIP {
                    inst.memory_displacement64() // iced-x86: already resolved for RIP-relative
                } else if inst.memory_segment() == Register::DS
                    && inst.memory_base() == Register::None
                {
                    inst.memory_displacement64() // DS absolute address — already resolved
                } else {
                    continue;
                };

                if resolved == target_abs {
                    // Follow through JZ/JMP and find the CALL
                    while decoder.can_decode() {
                        decoder.decode_out(&mut inst);
                        if inst.mnemonic() == Mnemonic::Je || inst.mnemonic() == Mnemonic::Jmp {
                            // Jump to target
                            let new_ip = inst.near_branch_target() as usize;
                            let remaining =
                                unsafe { std::slice::from_raw_parts(new_ip as *const u8, 64) };
                            let mut inner = Decoder::with_ip(
                                64,
                                remaining,
                                new_ip as u64,
                                DecoderOptions::NONE,
                            );
                            while inner.can_decode() {
                                inner.decode_out(&mut inst);
                                if inst.mnemonic() == Mnemonic::Call
                                    && patcher::disasm::is_near_branch(&inst)
                                {
                                    return Some(inst.near_branch_target() as usize - base);
                                }
                            }
                            return None;
                        }
                        if inst.mnemonic() == Mnemonic::Call
                            && patcher::disasm::is_near_branch(&inst)
                        {
                            return Some(inst.near_branch_target() as usize - base);
                        }
                    }
                    return None;
                }
            }

            // LEA rcx, [rip+disp] pointing to IS_PNP_DISABLED
            if inst.mnemonic() == Mnemonic::Lea
                && inst.op0_kind() == OpKind::Register
                && inst.op0_register() == Register::RCX
                && inst.op1_kind() == OpKind::Memory
            {
                let resolved = if inst.memory_base() == Register::RIP {
                    inst.memory_displacement64() // iced-x86: already resolved for RIP-relative
                } else if inst.memory_segment() == Register::DS
                    && inst.memory_base() == Register::None
                {
                    inst.memory_displacement64() // DS absolute address — already resolved
                } else {
                    continue;
                };

                if resolved == target_abs {
                    let mut found_jnz = false;
                    while decoder.can_decode() {
                        decoder.decode_out(&mut inst);
                        if !found_jnz && inst.mnemonic() == Mnemonic::Jne {
                            // Follow JNZ
                            let new_ip = inst.near_branch_target() as usize;
                            let remaining =
                                unsafe { std::slice::from_raw_parts(new_ip as *const u8, 64) };
                            decoder = Decoder::with_ip(
                                64,
                                remaining,
                                new_ip as u64,
                                DecoderOptions::NONE,
                            );
                            found_jnz = true;
                        }
                        if found_jnz
                            && inst.mnemonic() == Mnemonic::Call
                            && patcher::disasm::is_near_branch(&inst)
                        {
                            return Some(inst.near_branch_target() as usize - base);
                        }
                    }
                    return None;
                }
            }
        }

        #[cfg(target_arch = "x86")]
        {
            if inst.mnemonic() == Mnemonic::Mov
                && inst.op0_kind() == OpKind::Register
                && inst.op1_kind() == OpKind::Immediate32
                && inst.immediate32() as u64 == target_abs
            {
                let mut found_jnz = false;
                while decoder.can_decode() {
                    decoder.decode_out(&mut inst);
                    if !found_jnz && inst.mnemonic() == Mnemonic::Jne {
                        let new_ip = inst.near_branch_target() as usize;
                        let remaining =
                            unsafe { std::slice::from_raw_parts(new_ip as *const u8, 64) };
                        decoder =
                            Decoder::with_ip(32, remaining, new_ip as u64, DecoderOptions::NONE);
                        found_jnz = true;
                    }
                    if found_jnz
                        && inst.mnemonic() == Mnemonic::Call
                        && inst.op0_kind() == OpKind::NearBranch32
                    {
                        return Some(inst.near_branch_target() as usize - base);
                    }
                }
                return None;
            }
        }
    }

    None
}

/// Apply PropertyDevicePatch — patches the PnP device property check.
///
/// Finds `shr reg, 0x0b` + `and reg, 1` pattern and replaces with
/// `mov reg, 0; nop` to disable PnP filtering.
///
/// # Safety
/// All threads must be suspended
pub unsafe fn apply(pe: &LoadedPe, func_rva: usize) {
    let base = pe.adjusted_base;
    let ip_start = base + func_rva;
    let code = unsafe { std::slice::from_raw_parts(ip_start as *const u8, 256) };

    let bits = if cfg!(target_arch = "x86_64") { 64 } else { 32 };
    let mut decoder = Decoder::with_ip(bits, code, ip_start as u64, DecoderOptions::NONE);
    let mut inst = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut inst);

        // Look for MOV reg, [mem+0x1f00] or [mem+0x1f28]
        if inst.mnemonic() == Mnemonic::Mov
            && inst.op0_kind() == OpKind::Register
            && inst.op0_register().size() == 4  // 32-bit register
            && inst.op1_kind() == OpKind::Memory
            && inst.memory_base() != Register::RIP
            && (inst.memory_displacement64() == 0x1f00
                || inst.memory_displacement64() == 0x1f28)
        {
            let reg = inst.op0_register();

            // Search for SHR reg, 0x0b
            while decoder.can_decode() {
                let shr_ip = decoder.ip() as usize;
                decoder.decode_out(&mut inst);

                if inst.mnemonic() == Mnemonic::Shr
                    && inst.op0_kind() == OpKind::Register
                    && inst.op0_register() == reg
                    && inst.op1_kind() == OpKind::Immediate8
                    && inst.immediate8() == 0x0b
                {
                    // Next should be AND reg, 1
                    if !decoder.can_decode() {
                        break;
                    }
                    let and_ip = decoder.ip() as usize;
                    decoder.decode_out(&mut inst);

                    if inst.mnemonic() != Mnemonic::And
                        || inst.op0_kind() != OpKind::Register
                        || inst.op0_register() != reg
                        || inst.len() > 3
                    {
                        break;
                    }

                    let and_len = inst.len();
                    let total_len = 3 + and_len; // shr(3) + and

                    // Check registry: if PnP redirection is explicitly disabled, skip
                    if read_setting("fDisablePNPRedir", 0) == 1 {
                        return;
                    }

                    // Build patch: mov reg, 0 + nop padding
                    let mov_opcode = match reg {
                        Register::EAX => 0xB8u8,
                        Register::ECX => 0xB9,
                        Register::EDX => 0xBA,
                        Register::EBX => 0xBB,
                        Register::ESI => 0xBE,
                        Register::EDI => 0xBF,
                        _ => {
                            debug_log("PropertyPatch: unknown register\n");
                            return;
                        }
                    };

                    let mut patch = vec![mov_opcode, 0x00, 0x00, 0x00, 0x00];
                    while patch.len() < total_len {
                        patch.push(0x90);
                    }

                    if let Err(e) = unsafe { write_patch(shr_ip, &patch) } {
                        debug_log(&format!("PropertyPatch write failed: {e}\n"));
                    }
                    return;
                }

                // Also check for JNZ/JZ → SHR reg, 0x0c pattern (alternate)
                if (inst.mnemonic() == Mnemonic::Jne || inst.mnemonic() == Mnemonic::Je)
                    && patcher::disasm::is_near_branch(&inst)
                {
                    let target = inst.near_branch_target() as usize;
                    let target_code =
                        unsafe { std::slice::from_raw_parts(target as *const u8, 15) };
                    let mut target_decoder = Decoder::with_ip(
                        bits as u32,
                        target_code,
                        target as u64,
                        DecoderOptions::NONE,
                    );
                    let mut target_inst = Instruction::default();

                    if target_decoder.can_decode() {
                        target_decoder.decode_out(&mut target_inst);

                        if target_inst.mnemonic() == Mnemonic::Shr
                            && target_inst.op0_kind() == OpKind::Register
                            && target_inst.op0_register() == reg
                            && target_inst.op1_kind() == OpKind::Immediate8
                            && target_inst.immediate8() == 0x0c
                        {
                            // Check for AND after SHR
                            if target_decoder.can_decode() {
                                target_decoder.decode_out(&mut target_inst);

                                if target_inst.mnemonic() == Mnemonic::And
                                    && target_inst.op0_kind() == OpKind::Register
                                    && target_inst.op0_register() == reg
                                    && target_inst.op1_kind() == OpKind::Immediate8
                                    && target_inst.immediate8() == 7
                                {
                                    let and_len = target_inst.len();
                                    let total_len = 3 + and_len;

                                    // UseUniversalPrinterDriverFirst: default 3, registry can set to 4
                                    let driver_val =
                                        read_setting("UseUniversalPrinterDriverFirst", 3) as u8;
                                    let mov_opcode = match reg {
                                        Register::EAX => 0xB8u8,
                                        Register::ECX => 0xB9,
                                        Register::ESI => 0xBE,
                                        _ => {
                                            debug_log("PropertyPatch: unknown register\n");
                                            return;
                                        }
                                    };

                                    let mut patch = vec![mov_opcode, driver_val, 0x00, 0x00, 0x00];
                                    while patch.len() < total_len {
                                        patch.push(0x90);
                                    }

                                    if let Err(e) = unsafe { write_patch(target, &patch) } {
                                        debug_log(&format!("PropertyPatch write failed: {e}\n"));
                                    }
                                }
                            }
                        }
                    }
                }

                if inst.mnemonic() == Mnemonic::Ret || inst.mnemonic() == Mnemonic::Jmp {
                    break;
                }
            }
            break;
        }
    }

    debug_log("PropertyPatch not found\n");
}

/// Read a DWORD registry setting value.
#[cfg(windows)]
pub fn read_setting(name: &str, default: u32) -> u32 {
    use std::ffi::CString;
    use windows::Win32::System::Registry::*;

    let mut val = default;
    let c_name = match CString::new(name) {
        Ok(s) => s,
        Err(_) => return default,
    };

    let keys = [
        "System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
        "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services",
    ];

    for key_path in &keys {
        let c_path = match CString::new(*key_path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut hkey = HKEY::default();
        // SAFETY: valid registry key path
        let result = unsafe {
            RegOpenKeyExA(
                HKEY_LOCAL_MACHINE,
                windows::core::PCSTR(c_path.as_ptr() as *const u8),
                0,
                KEY_READ,
                &mut hkey,
            )
        };

        if result.is_ok() {
            let mut data: u32 = 0;
            let mut cb_data: u32 = 4;
            // SAFETY: reading a DWORD from registry
            let query_result = unsafe {
                RegQueryValueExA(
                    hkey,
                    windows::core::PCSTR(c_name.as_ptr() as *const u8),
                    None,
                    None,
                    Some(&mut data as *mut u32 as *mut u8),
                    Some(&mut cb_data),
                )
            };
            if query_result.is_ok() {
                val = data;
            }
            unsafe { RegCloseKey(hkey) };
        }
    }

    val
}

#[cfg(not(windows))]
pub fn read_setting(_name: &str, default: u32) -> u32 {
    default
}
