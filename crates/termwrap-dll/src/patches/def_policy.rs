use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use patcher::patch::{bytecodes, debug_log, write_patch};
use patcher::pe::LoadedPe;

/// Apply DefPolicyPatch — patches CDefPolicy::Query to allow multiple sessions.
///
/// Looks for a CMP instruction comparing a field at offset 0x63c (x64) or 0x320 (x86)
/// and replaces it with code that sets the field to 0x100 (fAllowConnections).
///
/// # Safety
/// - All threads must be suspended
/// - `func_rva` must be the RVA of CDefPolicy::Query
pub unsafe fn apply(pe: &LoadedPe, func_rva: usize) {
    let base = pe.adjusted_base;
    let ip = base + func_rva;
    let code = unsafe { std::slice::from_raw_parts(ip as *const u8, 128) };
    let mut decoder = Decoder::with_ip(arch_bits(), code, ip as u64, DecoderOptions::NONE);

    let mut last_length: usize = 0;
    let mut inst = Instruction::default();

    #[cfg(target_arch = "x86_64")]
    let mut mov_base = Register::None;
    #[cfg(target_arch = "x86_64")]
    let mut mov_target = Register::None;

    while decoder.can_decode() {
        let current_ip = decoder.ip() as usize;
        decoder.decode_out(&mut inst);
        let inst_length = inst.len();

        if inst.mnemonic() == Mnemonic::Cmp {
            #[cfg(target_arch = "x86_64")]
            {
                // x64: CMP [reg+0x63c], reg
                if inst.op0_kind() == OpKind::Memory
                    && inst.memory_displacement64() == 0x63c
                    && inst.op1_kind() == OpKind::Register
                {
                    let reg1 = inst.op1_register();
                    let reg2 = inst.memory_base();
                    unsafe { apply_defpolicy_patch(pe, current_ip, last_length, reg1, reg2) };
                    return;
                }
            }

            #[cfg(target_arch = "x86")]
            {
                // x86: CMP reg, [reg+0x320]
                if inst.op1_kind() == OpKind::Memory
                    && inst.memory_displacement64() == 0x320
                    && inst.op0_kind() == OpKind::Register
                {
                    let reg1 = inst.op0_register();
                    let reg2 = inst.memory_base();
                    unsafe { apply_defpolicy_patch(pe, current_ip, last_length, reg1, reg2) };
                    return;
                }
            }
        }

        #[cfg(target_arch = "x86_64")]
        {
            // Track MOV patterns for indirect CMP (newer Windows versions)
            if mov_base == Register::None
                && inst.mnemonic() == Mnemonic::Mov
                && inst.op0_kind() == OpKind::Register
                && inst.op1_kind() == OpKind::Memory
                && inst.memory_displacement64() == 0x63c
            {
                mov_base = inst.memory_base();
                mov_target = inst.op0_register();
            } else if inst.mnemonic() == Mnemonic::Mov
                && inst.op0_kind() == OpKind::Register
                && inst.op1_kind() == OpKind::Memory
                && inst.memory_base() == mov_base
                && inst.memory_displacement64() == 0x638
            {
                let mov_target2 = inst.op0_register();

                // Search forward for CMP between mov_target and mov_target2
                let offset_from_start = (current_ip + inst_length) - ip;
                let remaining = unsafe {
                    std::slice::from_raw_parts(
                        (current_ip + inst_length) as *const u8,
                        128usize.saturating_sub(offset_from_start),
                    )
                };
                let mut inner_decoder = Decoder::with_ip(
                    64,
                    remaining,
                    (current_ip + inst_length) as u64,
                    DecoderOptions::NONE,
                );
                let mut inner_inst = Instruction::default();

                while inner_decoder.can_decode() {
                    inner_decoder.decode_out(&mut inner_inst);
                    if inner_inst.mnemonic() == Mnemonic::Cmp
                        && inner_inst.op0_kind() == OpKind::Register
                        && inner_inst.op1_kind() == OpKind::Register
                        && ((inner_inst.op0_register() == mov_target
                            && inner_inst.op1_register() == mov_target2)
                            || (inner_inst.op0_register() == mov_target2
                                && inner_inst.op1_register() == mov_target))
                    {
                        // Found the CMP — check next instruction for JNZ/JZ
                        if inner_decoder.can_decode() {
                            inner_decoder.decode_out(&mut inner_inst);
                            if inner_inst.mnemonic() == Mnemonic::Jne {
                                // JNZ variant for indirect pattern — not supported in C++ either
                                debug_log("DefPolicyPatch: indirect _jmp not supported\n");
                                return;
                            }
                            if inner_inst.mnemonic() != Mnemonic::Je
                                && inner_inst.mnemonic() != Mnemonic::Pop
                            {
                                break;
                            }
                            // JZ/POP variant for indirect (patch hardcodes rcx)
                            if mov_base != Register::RCX {
                                debug_log("DefPolicyPatch: indirect unsupported base reg\n");
                                return;
                            }
                            if mov_target2 == Register::EDI {
                                let patch: &[u8] = &[
                                    0xBF, 0x00, 0x01, 0x00, 0x00, // mov edi, 0x100
                                    0x89, 0xB9, 0x38, 0x06, 0x00,
                                    0x00, // mov [rcx+0x638], edi
                                    0x90, 0x90, 0x90, // nop*3
                                ];
                                if let Err(e) = unsafe { write_patch(current_ip, patch) } {
                                    debug_log(&format!("DefPolicyPatch write failed: {e}\n"));
                                }
                            } else {
                                debug_log("DefPolicyPatch: indirect unknown reg1\n");
                            }
                        }
                        return;
                    }
                }
            }
        }

        last_length = inst_length;
    }

    debug_log("DefPolicyPatch not found\n");
}

/// Apply the actual DefPolicy patch bytes based on register operands.
///
/// # Safety
/// Threads must be suspended, addresses must be valid
unsafe fn apply_defpolicy_patch(
    _pe: &LoadedPe,
    cmp_ip: usize,
    last_inst_length: usize,
    reg1: Register,
    reg2: Register,
) {
    let mut next_inst = Instruction::default();

    // Decode the CMP instruction to get its length, then check the conditional jump after it
    // SAFETY: cmp_ip is within the loaded DLL's .text section (from disassembly)
    let cmp_code = unsafe { std::slice::from_raw_parts(cmp_ip as *const u8, 15) };
    let mut cmp_decoder =
        Decoder::with_ip(arch_bits(), cmp_code, cmp_ip as u64, DecoderOptions::NONE);
    cmp_decoder.decode_out(&mut next_inst);
    let cmp_length = next_inst.len();

    // SAFETY: cmp_ip + cmp_length is the next instruction within the loaded DLL
    let after_cmp = unsafe { std::slice::from_raw_parts((cmp_ip + cmp_length) as *const u8, 15) };
    let mut after_decoder = Decoder::with_ip(
        arch_bits(),
        after_cmp,
        (cmp_ip + cmp_length) as u64,
        DecoderOptions::NONE,
    );
    after_decoder.decode_out(&mut next_inst);

    let is_jnz = next_inst.mnemonic() == Mnemonic::Jne;
    let patch_addr = if is_jnz {
        cmp_ip - last_inst_length
    } else {
        cmp_ip
    };

    let patch_bytes = select_defpolicy_bytes(reg1, reg2, is_jnz);

    if let Some(bytes) = patch_bytes {
        if let Err(e) = unsafe { write_patch(patch_addr, bytes) } {
            debug_log(&format!("DefPolicyPatch write failed: {e}\n"));
        }
    } else {
        debug_log(&format!(
            "DefPolicyPatch: unknown register combination {reg1:?} / {reg2:?}\n"
        ));
    }
}

/// Select the correct patch bytecode based on register combination
#[cfg_attr(not(target_arch = "x86"), allow(unused_variables))]
fn select_defpolicy_bytes(reg1: Register, reg2: Register, is_jnz: bool) -> Option<&'static [u8]> {
    #[cfg(target_arch = "x86_64")]
    {
        if is_jnz {
            match reg2 {
                Register::RCX => Some(bytecodes::DEFPOLICY_X64_RCX_JMP),
                Register::RDI => Some(bytecodes::DEFPOLICY_X64_RDI_JMP),
                _ => None,
            }
        } else {
            match reg2 {
                Register::RCX => Some(bytecodes::DEFPOLICY_X64_RCX),
                Register::RDI => Some(bytecodes::DEFPOLICY_X64_RDI),
                _ => None,
            }
        }
    }

    #[cfg(target_arch = "x86")]
    {
        if is_jnz {
            match (reg1, reg2) {
                (Register::EAX, Register::ECX) => Some(bytecodes::DEFPOLICY_X86_ECX_JNZ),
                _ => None,
            }
        } else {
            match (reg1, reg2) {
                (Register::EAX, Register::ECX) => Some(bytecodes::DEFPOLICY_X86_ECX_JZ),
                (Register::EAX, Register::ESI) => Some(bytecodes::DEFPOLICY_X86_ESI),
                (Register::EDX, Register::ECX) => Some(bytecodes::DEFPOLICY_X86_EDX_ECX),
                _ => None,
            }
        }
    }
}

fn arch_bits() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        64
    }
    #[cfg(target_arch = "x86")]
    {
        32
    }
}
