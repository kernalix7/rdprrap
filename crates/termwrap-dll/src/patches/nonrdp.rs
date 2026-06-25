use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};
use patcher::patch::{bytecodes, debug_log, write_patch};
use patcher::pe::LoadedPe;

use super::util::read_image_bytes;

/// Apply NonRDPPatch — patches CRemoteConnectionManager::IsAllowNonRDPStack.
///
/// Finds a CALL to CSLQuery::IsAppServerInstalled and replaces it with:
/// `inc dword ptr [ecx/rcx]; xor eax, eax; nop`
///
/// Returns true if patch was applied.
///
/// # Safety
/// All threads must be suspended
pub unsafe fn apply(pe: &LoadedPe, func_rva: usize, target_rva: usize) -> bool {
    let base = pe.adjusted_base;
    let ip_start = base + func_rva;
    let target_abs = (base + target_rva) as u64;

    // In-memory extent of the loaded termsrv.dll image. `func_rva` is the begin
    // address of a (possibly chained-unwind-resolved) RUNTIME_FUNCTION; on a
    // layout-shifted build that can resolve outside the mapping, and an
    // unbounded 256-byte read there can fault and crash the Terminal Services
    // svchost. Bound the read and degrade to "patch not found".
    let (img_lo, img_hi) = pe.image_extent();

    // SAFETY: bounded by `read_image_bytes`, which validates `ip_start` lies
    // within `[img_lo, img_hi)` and clamps the read length to the bytes mapped
    // after it; an out-of-image function start degrades to "patch not found".
    let code = match read_image_bytes("NonRDPPatch", ip_start, 256, img_lo, img_hi) {
        Some(c) => c,
        None => {
            debug_log("NonRDPPatch function start outside image\n");
            return false;
        }
    };

    let bits = if cfg!(target_arch = "x86_64") { 64 } else { 32 };
    let mut decoder = Decoder::with_ip(bits, code, ip_start as u64, DecoderOptions::NONE);
    let mut inst = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut inst);

        if inst.mnemonic() == Mnemonic::Call
            && patcher::disasm::is_near_branch(&inst)
            && inst.near_branch_target() == target_abs
        {
            if inst.len() != 5 {
                break;
            }

            // Replace the call with: inc [ecx]; xor eax,eax; nop
            let patch_addr = inst.ip() as usize;
            if let Err(e) = unsafe { write_patch(patch_addr, bytecodes::NONRDP_PATCH) } {
                debug_log(&format!("NonRDPPatch write failed: {e}\n"));
                return false;
            }
            return true;
        }
    }

    false
}
