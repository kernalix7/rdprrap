//! x86 function-body walker for rdpendp.dll patch discovery.
//!
//! Pure-Rust / no-Windows-FFI so tests run on any host. Mirrors the algorithm
//! described in `termwrap-dll`'s `resolve_functions_x86` and in this crate's
//! sibling `umwrap-dll/src/x86_walk.rs`.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// x86 function prologue: `mov edi,edi; push ebp; mov ebp,esp`.
pub const PROLOGUE: &[u8] = &[0x8B, 0xFF, 0x55, 0x8B, 0xEC];

/// Walk one function body and report whether any PUSH imm32 or MOV imm32
/// inside it references the absolute VA `base + target_rva`.
///
/// BFS through basic blocks via a min-heap of branch targets so we do not
/// miss references hidden behind a Jcc.
pub fn function_references_rva(
    text_slice: &[u8],
    text_start: usize,
    func_ip: usize,
    base: usize,
    target_rva: usize,
) -> bool {
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

        while decoder.can_decode() {
            decoder.decode_out(&mut inst);

            if let Some(rva) = detect_imm32_rva(&inst, base) {
                if rva == target_rva {
                    return true;
                }
            }

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

    false
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

    const BASE: usize = 0x2000_0000;
    const TEXT_RVA: usize = 0x1000;
    const TEXT_START: usize = BASE + TEXT_RVA;

    fn mk_function_pushing(fake_rva: u32) -> Vec<u8> {
        let abs_addr = BASE as u32 + fake_rva;
        let mut code = Vec::new();
        code.extend_from_slice(PROLOGUE);
        code.push(0x68); // push imm32
        code.extend_from_slice(&abs_addr.to_le_bytes());
        // pad with a few NOPs and a RET
        code.extend_from_slice(&[0x90, 0x90, 0xC3]);
        code
    }

    #[test]
    fn detects_push_imm32_reference() {
        let fake_rva = 0x2500u32;
        let func = mk_function_pushing(fake_rva);
        let mut text = vec![0x90u8; 8];
        let off = text.len();
        text.extend_from_slice(&func);
        let func_ip = TEXT_START + off;

        assert!(function_references_rva(
            &text,
            TEXT_START,
            func_ip,
            BASE,
            fake_rva as usize,
        ));
    }

    #[test]
    fn detects_mov_reg_imm32_reference() {
        let fake_rva = 0x2600u32;
        let abs_addr = BASE as u32 + fake_rva;
        let mut func = Vec::new();
        func.extend_from_slice(PROLOGUE);
        func.push(0xB8); // mov eax, imm32
        func.extend_from_slice(&abs_addr.to_le_bytes());
        func.push(0xC3);

        let mut text = vec![0x90u8; 4];
        let off = text.len();
        text.extend_from_slice(&func);
        let func_ip = TEXT_START + off;

        assert!(function_references_rva(
            &text,
            TEXT_START,
            func_ip,
            BASE,
            fake_rva as usize,
        ));
    }

    #[test]
    fn ignores_unrelated_imm32() {
        let fake_rva = 0x2700u32;
        let func = mk_function_pushing(fake_rva);
        let mut text = vec![0x90u8; 4];
        let off = text.len();
        text.extend_from_slice(&func);
        let func_ip = TEXT_START + off;

        assert!(!function_references_rva(
            &text,
            TEXT_START,
            func_ip,
            BASE,
            0xDEADusize,
        ));
    }

    #[test]
    fn finds_reference_across_conditional_branch() {
        // Prologue; JE short +??; fall-through: RET. Taken branch: PUSH imm32; RET.
        let fake_rva = 0x2800u32;
        let abs = BASE as u32 + fake_rva;

        let mut func = Vec::new();
        func.extend_from_slice(PROLOGUE);
        // JE short to +5 (skip the inline ret+NOPs to a branch that pushes)
        //   74 05        ; JE +5
        //   C3           ; RET
        //   90 90 90 90 90 ; 5 NOPs padding so target is well past
        //   68 xx xx xx xx ; push abs
        //   C3           ; RET
        func.extend_from_slice(&[0x74, 0x06]); // JE +6
        func.push(0xC3);
        func.extend_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90]); // 5 NOPs
        func.push(0x68);
        func.extend_from_slice(&abs.to_le_bytes());
        func.push(0xC3);

        let mut text = vec![0x90u8; 4];
        let off = text.len();
        text.extend_from_slice(&func);
        let func_ip = TEXT_START + off;

        assert!(function_references_rva(
            &text,
            TEXT_START,
            func_ip,
            BASE,
            fake_rva as usize,
        ));
    }
}
