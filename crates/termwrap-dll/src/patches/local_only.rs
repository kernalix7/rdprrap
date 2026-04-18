use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};
use patcher::patch::{bytecodes, debug_log, write_patch};
use patcher::pe::LoadedPe;

/// Apply LocalOnlyPatch — prevents license type local-only restriction.
///
/// Scans CEnforcementCore::GetInstanceOfTSLicense for a call to
/// CSLQuery::IsTerminalTypeLocalOnly, then finds the conditional jump
/// pattern (TEST → JS/JNS → CMP → JZ) and converts the JZ to JMP.
///
/// # Safety
/// All threads must be suspended
pub unsafe fn apply(pe: &LoadedPe, func_rva: usize, target_rva: usize) {
    let base = pe.adjusted_base;
    let ip_start = base + func_rva;
    let target_abs = (base + target_rva) as u64;
    let code = unsafe { std::slice::from_raw_parts(ip_start as *const u8, 256) };
    let mut decoder = Decoder::with_ip(arch_bits(), code, ip_start as u64, DecoderOptions::NONE);
    let mut inst = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut inst);

        // Look for CALL to IsTerminalTypeLocalOnly (relative call)
        if inst.mnemonic() != Mnemonic::Call || !patcher::disasm::is_near_branch(&inst) {
            continue;
        }

        if inst.near_branch_target() != target_abs {
            continue;
        }

        // Skip MOV instructions after the call
        while decoder.can_decode() {
            decoder.decode_out(&mut inst);
            if inst.mnemonic() != Mnemonic::Mov {
                break;
            }
        }

        // Expect TEST
        if inst.mnemonic() != Mnemonic::Test {
            break;
        }

        // Expect JS or JNS
        if !decoder.can_decode() {
            break;
        }
        decoder.decode_out(&mut inst);

        if inst.mnemonic() != Mnemonic::Js && inst.mnemonic() != Mnemonic::Jns {
            break;
        }

        let (cmp_location, jz_expected_target) = if inst.mnemonic() == Mnemonic::Jns {
            // JNS: CMP is at branch destination, JZ should jump back to fall-through
            (inst.near_branch_target(), inst.next_ip())
        } else {
            // JS: CMP is at fall-through, JZ should jump to branch destination
            (inst.next_ip(), inst.near_branch_target())
        };

        // At cmp_location: expect CMP
        let cmp_code =
            unsafe { std::slice::from_raw_parts(cmp_location as usize as *const u8, 30) };
        let mut cmp_decoder =
            Decoder::with_ip(arch_bits(), cmp_code, cmp_location, DecoderOptions::NONE);
        let mut cmp_inst = Instruction::default();

        if !cmp_decoder.can_decode() {
            break;
        }
        cmp_decoder.decode_out(&mut cmp_inst);

        if cmp_inst.mnemonic() != Mnemonic::Cmp {
            break;
        }

        // Expect JZ after CMP
        if !cmp_decoder.can_decode() {
            break;
        }
        let jz_ip = cmp_decoder.ip() as usize;
        cmp_decoder.decode_out(&mut cmp_inst);

        if cmp_inst.mnemonic() != Mnemonic::Je {
            break;
        }

        // Verify JZ target matches expected jz_expected_target
        let jz_target = cmp_inst.near_branch_target();
        if jz_target != jz_expected_target {
            break;
        }

        // Apply patch: convert JZ to JMP
        if cmp_inst.len() > 2 {
            // 6-byte JZ → NOP + JMP near
            if let Err(e) = unsafe { write_patch(jz_ip, bytecodes::NOP_JMP_NEAR) } {
                debug_log(&format!("LocalOnlyPatch write failed: {e}\n"));
            }
        } else {
            // 2-byte JZ → JMP short
            if let Err(e) = unsafe { write_patch(jz_ip, bytecodes::JMP_SHORT) } {
                debug_log(&format!("LocalOnlyPatch write failed: {e}\n"));
            }
        }

        return;
    }

    debug_log("LocalOnlyPatch not found\n");
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
