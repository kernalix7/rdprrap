use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use patcher::patch::{bytecodes, debug_log, nop_fill, write_patch};
use patcher::pe::LoadedPe;

use super::util::read_image_bytes;

/// Apply SingleUserPatch — prevents single-session-per-user enforcement.
///
/// Finds the call to memset within the function, then searches for either:
/// - A call to VerifyVersionInfoW → replace with `mov eax, 1` (x64) or `pop eax; add esp, 12` (x86)
/// - A CMP [rbp/rsp+XX], 1 → NOP it out
///
/// Returns true if patch was applied.
///
/// # Safety
/// All threads must be suspended, func_rva must be valid
pub unsafe fn apply(
    pe: &LoadedPe,
    func_rva: usize,
    memset_rva: usize,
    verify_version_rva: Option<usize>,
) -> bool {
    let base = pe.adjusted_base;
    let ip_start = base + func_rva;

    // In-memory extent of the loaded termsrv.dll image. `func_rva` is the begin
    // address of a (possibly chained-unwind-resolved) RUNTIME_FUNCTION, and the
    // memset JMP-thunk target below is a decoded near-branch; both can resolve
    // outside the mapping on a layout-shifted build, and an unbounded read
    // there can fault and crash the Terminal Services svchost. Every raw read
    // is bounded against this span and degrades to "not found"
    // (SEC-UNSAFE-001 / SEC-PATCH-004).
    let (img_lo, img_hi) = pe.image_extent();

    // SAFETY: bounded by `read_image_bytes`, which validates `ip_start` lies
    // within `[img_lo, img_hi)` and clamps the read length to the bytes mapped
    // after it; an out-of-image function start degrades to "not found".
    let code = match read_image_bytes("SingleUserPatch", ip_start, 256, img_lo, img_hi) {
        Some(c) => c,
        None => {
            debug_log("SingleUserPatch function start outside image\n");
            return false;
        }
    };
    let mut decoder = Decoder::with_ip(arch_bits(), code, ip_start as u64, DecoderOptions::NONE);
    let mut inst = Instruction::default();

    let memset_abs = (base + memset_rva) as u64;

    while decoder.can_decode() {
        decoder.decode_out(&mut inst);

        // Look for CALL to memset (through import thunk)
        if inst.mnemonic() != Mnemonic::Call {
            continue;
        }

        // Check if this CALL goes to memset via JMP thunk
        if !is_call_to_memset(&inst, pe, memset_abs, img_lo, img_hi) {
            continue;
        }

        // Found memset call — now search for VerifyVersionInfoW or CMP pattern.
        // `remaining_ip` is still inside the disassembled function body, but the
        // read is bounded for uniformity and degrades to "not found".
        let remaining_ip = decoder.ip() as usize;
        let remaining = match read_image_bytes("SingleUserPatch", remaining_ip, 128, img_lo, img_hi)
        {
            Some(r) => r,
            None => return false,
        };
        let mut inner = Decoder::with_ip(
            arch_bits(),
            remaining,
            remaining_ip as u64,
            DecoderOptions::NONE,
        );
        let mut inner_inst = Instruction::default();

        while inner.can_decode() {
            let patch_ip = inner.ip() as usize;
            inner.decode_out(&mut inner_inst);

            #[cfg(target_arch = "x86_64")]
            {
                // Check for call [rip+disp] to VerifyVersionInfoW
                if let Some(vv_rva) = verify_version_rva {
                    if inner_inst.mnemonic() == Mnemonic::Call
                        && inner_inst.len() >= 5
                        && inner_inst.len() <= 7
                        && inner_inst.op0_kind() == OpKind::Memory
                        && inner_inst.memory_base() == Register::RIP
                    {
                        let target = inner_inst.memory_displacement64();
                        if target == (base + vv_rva) as u64 {
                            // Replace call with `mov eax, 1` + NOP padding
                            let mut patch = bytecodes::MOV_EAX_1.to_vec();
                            while patch.len() < inner_inst.len() {
                                patch.push(0x90);
                            }
                            if let Err(e) = unsafe { write_patch(patch_ip, &patch) } {
                                debug_log(&format!("SingleUserPatch write failed: {e}\n"));
                            }
                            return true;
                        }
                    }
                }

                // Check for CMP [rbp/rsp+XX], 1
                if inner_inst.mnemonic() == Mnemonic::Cmp
                    && inner_inst.len() <= 8
                    && inner_inst.op0_kind() == OpKind::Memory
                    && (inner_inst.memory_base() == Register::RBP
                        || inner_inst.memory_base() == Register::RSP)
                    && ((inner_inst.op1_kind() == OpKind::Immediate8
                        && inner_inst.immediate8() == 1)
                        || inner_inst.op1_kind() == OpKind::Register)
                {
                    if let Err(e) = unsafe { nop_fill(patch_ip, inner_inst.len()) } {
                        debug_log(&format!("SingleUserPatch NOP failed: {e}\n"));
                    }
                    return true;
                }
            }

            #[cfg(target_arch = "x86")]
            {
                // Check for call [disp] to VerifyVersionInfoW
                if let Some(vv_rva) = verify_version_rva {
                    if inner_inst.mnemonic() == Mnemonic::Call
                        && inner_inst.len() >= 5
                        && inner_inst.len() <= 7
                        && inner_inst.op0_kind() == OpKind::Memory
                        && inner_inst.memory_segment() == Register::DS
                        && inner_inst.memory_displacement64() == (base + vv_rva) as u64
                    {
                        // Replace with pop eax; add esp, 12; nop padding
                        let patch = &bytecodes::SINGLEUSER_X86_POP[..inner_inst.len()];
                        if let Err(e) = unsafe { write_patch(patch_ip, patch) } {
                            debug_log(&format!("SingleUserPatch write failed: {e}\n"));
                        }
                        return true;
                    }
                }

                // Check for CMP [ebp+XX], 1
                if inner_inst.mnemonic() == Mnemonic::Cmp
                    && inner_inst.len() <= 8
                    && inner_inst.op0_kind() == OpKind::Memory
                    && inner_inst.memory_base() == Register::EBP
                    && inner_inst.op1_kind() == OpKind::Immediate8
                    && inner_inst.immediate8() == 1
                {
                    if let Err(e) = unsafe { nop_fill(patch_ip, inner_inst.len()) } {
                        debug_log(&format!("SingleUserPatch NOP failed: {e}\n"));
                    }
                    return true;
                }
            }
        }

        break;
    }

    false
}

/// Check if a CALL instruction targets memset via an import thunk.
/// Follows the pattern: CALL → JMP [import_thunk] → memset
///
/// `img_lo`/`img_hi` are the loaded image extent (from `pe.image_extent()`);
/// the JMP-thunk read at the decoded call target is bounded against them so a
/// mis-decoded near-branch cannot read outside the mapping.
fn is_call_to_memset(
    inst: &Instruction,
    _pe: &LoadedPe,
    memset_abs: u64,
    img_lo: usize,
    img_hi: usize,
) -> bool {
    if inst.mnemonic() != Mnemonic::Call || !patcher::disasm::is_near_branch(inst) {
        return false;
    }

    let jmp_addr = inst.near_branch_target() as usize;

    // Read the JMP instruction at the call target. The target is a decoded
    // near-branch that can resolve outside the image on a mis-decoded build, so
    // the read is bounded and a "not a memset thunk" result degrades to `false`.
    let jmp_code = match read_image_bytes("SingleUserPatch", jmp_addr, 15, img_lo, img_hi) {
        Some(c) => c,
        None => return false,
    };
    let mut jmp_decoder =
        Decoder::with_ip(arch_bits(), jmp_code, jmp_addr as u64, DecoderOptions::NONE);
    let mut jmp_inst = Instruction::default();

    if !jmp_decoder.can_decode() {
        return false;
    }
    jmp_decoder.decode_out(&mut jmp_inst);

    if jmp_inst.mnemonic() != Mnemonic::Jmp {
        return false;
    }

    #[cfg(target_arch = "x86_64")]
    {
        if jmp_inst.op0_kind() == OpKind::Memory && jmp_inst.memory_base() == Register::RIP {
            let target = jmp_inst.memory_displacement64();
            return target == memset_abs;
        }
    }

    #[cfg(target_arch = "x86")]
    {
        if jmp_inst.op0_kind() == OpKind::Memory && jmp_inst.memory_segment() == Register::DS {
            return jmp_inst.memory_displacement64() == memset_abs;
        }
    }

    false
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
