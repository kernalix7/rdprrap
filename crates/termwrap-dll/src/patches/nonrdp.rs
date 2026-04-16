use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use patcher::patch::{bytecodes, debug_log, write_patch};
use patcher::pe::LoadedPe;

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
    let code = unsafe { std::slice::from_raw_parts(ip_start as *const u8, 256) };

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
            let patch_addr = (inst.ip() as usize);
            if let Err(e) = unsafe { write_patch(patch_addr, bytecodes::NONRDP_PATCH) } {
                debug_log(&format!("NonRDPPatch write failed: {e}\n"));
                return false;
            }
            return true;
        }
    }

    false
}
