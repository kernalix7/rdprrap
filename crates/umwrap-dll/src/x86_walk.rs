//! x86 function-body walker for umrdp.dll patch discovery.
//!
//! This module is deliberately pure-Rust / no-Windows-FFI so that it compiles
//! and runs under `cargo test` on any host. The actual memory-writing patcher
//! lives in `patches.rs` and calls into this walker on x86 targets.
//!
//! Algorithm (see termwrap-dll's `resolve_functions_x86` for the reference):
//!   1. Caller has already located the x86 prologue `8B FF 55 8B EC`.
//!   2. For each hit we BFS through basic blocks via a min-heap of branch
//!      targets (`BinaryHeap<Reverse<usize>>`).
//!   3. In each block we decode 32-bit and look for `PUSH imm32` (5 bytes)
//!      or `MOV reg/[ebp|esp+disp], imm32` whose immediate equals an absolute
//!      VA we care about (i.e. `base + tracked_rva`).
//!   4. On such a hit, the first following `CALL rel32` (5 bytes) inside the
//!      same function is the patch site — the caller overwrites it with
//!      `mov eax, 1` (for umrdp) or the prologue (for rdpendp).

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// x86 function prologue: `mov edi,edi; push ebp; mov ebp,esp`.
pub const PROLOGUE: &[u8] = &[0x8B, 0xFF, 0x55, 0x8B, 0xEC];

/// Result of walking one function body.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FunctionHits {
    /// Absolute IPs of CALL rel32 sites preceded by an imm32 ref to `pnp_rva`.
    pub pnp_calls: Vec<usize>,
    /// Absolute IPs of CALL rel32 sites preceded by an imm32 ref to `camera_rva`.
    pub camera_calls: Vec<usize>,
    /// Whether we ever saw an imm32 reference to `pnp_rva`.
    pub saw_pnp_ref: bool,
    /// Whether we ever saw an imm32 reference to `camera_rva`.
    pub saw_camera_ref: bool,
}

/// BFS one function body. `text_slice` is the live bytes of `.text`,
/// `text_start` is the absolute address at which `text_slice[0]` sits in
/// the process, and `func_ip` is the absolute address of the function
/// prologue we are walking.
///
/// `base` is `pe.adjusted_base` — the value we subtract from a decoded
/// `immediate32` to recover an RVA.
pub fn walk_function(
    text_slice: &[u8],
    text_start: usize,
    func_ip: usize,
    base: usize,
    pnp_rva: usize,
    camera_rva: Option<usize>,
) -> FunctionHits {
    let mut hits = FunctionHits::default();
    let mut visited: Vec<usize> = Vec::new();
    let mut queue: BinaryHeap<Reverse<usize>> = BinaryHeap::new();
    queue.push(Reverse(func_ip));

    while let Some(Reverse(block_start)) = queue.pop() {
        if visited.contains(&block_start) {
            continue;
        }
        visited.push(block_start);

        if block_start < text_start {
            continue;
        }
        let block_off = block_start - text_start;
        if block_off >= text_slice.len() {
            continue;
        }

        let avail = (text_slice.len() - block_off).min(4096);
        let block_code = &text_slice[block_off..block_off + avail];
        let mut decoder =
            Decoder::with_ip(32, block_code, block_start as u64, DecoderOptions::NONE);
        let mut inst = Instruction::default();

        // We enter a basic block with no pending imm32 ref — references only
        // count as "preceding" within the same block. If a PUSH/MOV was in the
        // predecessor block we rely on the fact that the code pattern in
        // umrdp.dll places the PUSH immediately before the CALL in the same
        // linear run; branches do not separate them in practice.
        let mut pending_pnp = false;
        let mut pending_camera = false;

        while decoder.can_decode() {
            decoder.decode_out(&mut inst);

            if let Some(rva) = detect_imm32_rva(&inst, base) {
                if rva == pnp_rva {
                    pending_pnp = true;
                    hits.saw_pnp_ref = true;
                } else if Some(rva) == camera_rva {
                    pending_camera = true;
                    hits.saw_camera_ref = true;
                }
            }

            if inst.mnemonic() == Mnemonic::Call
                && inst.len() == 5
                && inst.op0_kind() == OpKind::NearBranch32
            {
                let call_ip = inst.ip() as usize;
                if pending_pnp {
                    hits.pnp_calls.push(call_ip);
                    pending_pnp = false;
                }
                if pending_camera {
                    hits.camera_calls.push(call_ip);
                    pending_camera = false;
                }
            }

            // Follow conditional near branches (Jcc rel32) into new blocks.
            if inst.mnemonic() >= Mnemonic::Ja
                && inst.mnemonic() <= Mnemonic::Js
                && inst.mnemonic() != Mnemonic::Jmp
                && inst.op0_kind() == OpKind::NearBranch32
            {
                let target = inst.near_branch_target() as usize;
                if target >= text_start && target < text_start + text_slice.len() {
                    queue.push(Reverse(target));
                }
            }

            if inst.mnemonic() == Mnemonic::Ret || inst.mnemonic() == Mnemonic::Jmp {
                break;
            }
        }
    }

    hits
}

/// Return `Some(rva)` if `inst` is `PUSH imm32` (5 bytes) or
/// `MOV reg/[ebp|esp+disp], imm32` (>=5 bytes), interpreting the immediate
/// as an absolute VA and subtracting `base` to recover an RVA.
fn detect_imm32_rva(inst: &Instruction, base: usize) -> Option<usize> {
    let is_push_imm32 = inst.len() == 5
        && inst.mnemonic() == Mnemonic::Push
        && inst.op0_kind() == OpKind::Immediate32;

    let is_mov_imm32 = inst.mnemonic() == Mnemonic::Mov
        && inst.op1_kind() == OpKind::Immediate32
        && ((inst.op0_kind() == OpKind::Register && inst.len() == 5)
            || (inst.op0_kind() == OpKind::Memory
                && inst.len() >= 7
                && (inst.memory_base() == Register::EBP || inst.memory_base() == Register::ESP)));

    if !(is_push_imm32 || is_mov_imm32) {
        return None;
    }

    let imm = inst.immediate32() as usize;
    Some(imm.wrapping_sub(base))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: usize = 0x1000_0000;
    const TEXT_RVA: usize = 0x1000;
    const TEXT_START: usize = BASE + TEXT_RVA;

    /// One function: prologue + `PUSH abs_addr` + `CALL rel32` + `XOR eax,eax; RET`.
    fn synthetic_push_then_call(fake_rva: u32) -> Vec<u8> {
        let abs_addr = BASE as u32 + fake_rva;
        let mut code = Vec::new();
        code.extend_from_slice(PROLOGUE);
        code.push(0x68); // push imm32
        code.extend_from_slice(&abs_addr.to_le_bytes());
        code.push(0xE8); // call rel32
        code.extend_from_slice(&0i32.to_le_bytes());
        code.extend_from_slice(&[0x31, 0xC0, 0xC3]); // xor eax,eax; ret
        code
    }

    #[test]
    fn finds_push_then_call() {
        let fake_rva = 0x2000u32;
        let func_code = synthetic_push_then_call(fake_rva);

        let mut text = vec![0x90u8; 16];
        let func_off = text.len();
        text.extend_from_slice(&func_code);
        let func_ip = TEXT_START + func_off;

        let hits = walk_function(&text, TEXT_START, func_ip, BASE, fake_rva as usize, None);

        assert!(hits.saw_pnp_ref, "should see PUSH imm32 for PnP RVA");
        assert_eq!(hits.pnp_calls.len(), 1);
        // CALL is right after prologue (5) + push (5)
        assert_eq!(hits.pnp_calls[0], func_ip + PROLOGUE.len() + 5);
    }

    #[test]
    fn finds_mov_reg_imm32_then_call() {
        let fake_rva = 0x3000u32;
        let abs_addr = BASE as u32 + fake_rva;
        let mut code = Vec::new();
        code.extend_from_slice(PROLOGUE);
        code.push(0xB8); // mov eax, imm32
        code.extend_from_slice(&abs_addr.to_le_bytes());
        code.push(0xE8);
        code.extend_from_slice(&0i32.to_le_bytes());
        code.push(0xC3);

        let mut text = vec![0x90u8; 8];
        let func_off = text.len();
        text.extend_from_slice(&code);
        let func_ip = TEXT_START + func_off;

        let hits = walk_function(&text, TEXT_START, func_ip, BASE, fake_rva as usize, None);

        assert_eq!(hits.pnp_calls.len(), 1);
        assert_eq!(hits.pnp_calls[0], func_ip + PROLOGUE.len() + 5);
    }

    #[test]
    fn ignores_non_matching_imm32() {
        let fake_rva = 0x4000u32;
        let code = synthetic_push_then_call(fake_rva);

        let mut text = vec![0x90u8; 4];
        let func_off = text.len();
        text.extend_from_slice(&code);
        let func_ip = TEXT_START + func_off;

        let hits = walk_function(&text, TEXT_START, func_ip, BASE, 0xDEAD, None);

        assert!(!hits.saw_pnp_ref);
        assert!(hits.pnp_calls.is_empty());
    }

    #[test]
    fn finds_camera_secondary() {
        let pnp_rva = 0x2000u32;
        let camera_rva = 0x2020u32;
        let abs_pnp = BASE as u32 + pnp_rva;
        let abs_cam = BASE as u32 + camera_rva;

        let mut code = Vec::new();
        code.extend_from_slice(PROLOGUE);
        code.push(0x68);
        code.extend_from_slice(&abs_pnp.to_le_bytes());
        code.push(0xE8);
        code.extend_from_slice(&0i32.to_le_bytes());
        code.push(0x68);
        code.extend_from_slice(&abs_cam.to_le_bytes());
        code.push(0xE8);
        code.extend_from_slice(&0i32.to_le_bytes());
        code.push(0xC3);

        let mut text = vec![0x90u8; 4];
        let func_off = text.len();
        text.extend_from_slice(&code);
        let func_ip = TEXT_START + func_off;

        let hits = walk_function(
            &text,
            TEXT_START,
            func_ip,
            BASE,
            pnp_rva as usize,
            Some(camera_rva as usize),
        );

        assert_eq!(hits.pnp_calls.len(), 1);
        assert_eq!(hits.camera_calls.len(), 1);
        assert!(hits.camera_calls[0] > hits.pnp_calls[0]);
    }
}
