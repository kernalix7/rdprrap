//! x86 function-address xref walker (operates on pelite byte slices).
//!
//! Unlike `termwrap-dll::patches::mod::resolve_functions_x86`, which walks a
//! *loaded* image through raw pointers, this walker consumes the on-disk
//! `.text` bytes obtained from `pelite::PeFile32`. It is therefore safe to run
//! on any host (including Linux) without loading the DLL into memory.
//!
//! Algorithm:
//!   1. Scan `.text` for the standard WinSDK prologue `8B FF 55 8B EC`
//!      (`mov edi,edi; push ebp; mov ebp,esp`).
//!   2. For each prologue hit, decode the function body with a priority-queue
//!      branch walker so short/near `Jcc` targets are explored too.
//!   3. Within each basic block, match `PUSH imm32` (5 bytes) or
//!      `MOV reg/mem, imm32` where the immediate equals a target string's
//!      absolute VA (`image_base + str_rva`).
//!   4. First matching prologue wins for that target.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

/// Prologue: `mov edi,edi; push ebp; mov ebp,esp`.
const PROLOGUE: [u8; 5] = [0x8B, 0xFF, 0x55, 0x8B, 0xEC];

/// Per-function budget for the branch walker — caps pathological control flow.
const MAX_BLOCKS_PER_FUNCTION: usize = 4096;
/// Max bytes to decode per basic block before giving up on it.
const MAX_BLOCK_BYTES: usize = 4096;

/// Find x86 function start RVAs that reference the supplied target VAs.
///
/// Arguments:
/// - `text_data`: raw `.text` section bytes from pelite.
/// - `text_va`: `.text` section virtual address (relative to image base).
/// - `targets`: slice of `(name, target_va)` — `target_va` is the absolute VA
///   of the referenced string (i.e. `image_base + str_rva`). Callers compute
///   the VA themselves so this helper stays agnostic of how the target is
///   derived.
///
/// Returns a map from target `name` to the discovered function-start RVA.
/// A target is present only if a prologue whose body references that VA was
/// located. Names absent from the result were not resolved.
pub fn find_xref_functions<'a>(
    text_data: &[u8],
    text_va: u32,
    targets: &[(&'a str, u32)],
) -> HashMap<&'a str, u32> {
    let mut resolved: HashMap<&str, u32> = HashMap::with_capacity(targets.len());
    if text_data.len() < PROLOGUE.len() || targets.is_empty() {
        return resolved;
    }

    let text_len = text_data.len();
    let text_end_va = text_va.saturating_add(text_len as u32);

    let mut i = 0usize;
    while i + PROLOGUE.len() <= text_len {
        if text_data[i..i + PROLOGUE.len()] != PROLOGUE {
            i += 1;
            continue;
        }

        let prologue_offset = i;
        let prologue_va = text_va.wrapping_add(prologue_offset as u32);
        let func_start_rva = prologue_va; // RVA == VA - image_base, but we store RVA

        if walk_function(
            text_data,
            text_va,
            text_end_va,
            prologue_offset,
            targets,
            &mut resolved,
            func_start_rva,
        ) && resolved.len() == targets.len()
        {
            break;
        }

        // Always advance past this prologue header before looking for the next.
        // (Matches termwrap-dll's `ip += 5` stride.)
        i += PROLOGUE.len();
    }

    resolved
}

/// Returns true if at least one new target was resolved from this function.
fn walk_function<'a>(
    text_data: &[u8],
    text_va: u32,
    text_end_va: u32,
    prologue_offset: usize,
    targets: &[(&'a str, u32)],
    resolved: &mut HashMap<&'a str, u32>,
    func_start_rva: u32,
) -> bool {
    let text_len = text_data.len();
    let prologue_va = text_va.wrapping_add(prologue_offset as u32);

    let mut heap: BinaryHeap<Reverse<u32>> = BinaryHeap::new();
    let mut visited: HashSet<u32> = HashSet::new();
    heap.push(Reverse(prologue_va));
    visited.insert(prologue_va);

    let mut found_any = false;
    let mut blocks_seen = 0usize;

    while let Some(Reverse(block_va)) = heap.pop() {
        if block_va < text_va || block_va >= text_end_va {
            continue;
        }
        blocks_seen += 1;
        if blocks_seen > MAX_BLOCKS_PER_FUNCTION {
            break;
        }

        let block_offset = (block_va - text_va) as usize;
        if block_offset >= text_len {
            continue;
        }
        let avail = text_len - block_offset;
        let take = avail.min(MAX_BLOCK_BYTES);
        let block_code = &text_data[block_offset..block_offset + take];

        let mut decoder = Decoder::with_ip(32, block_code, block_va as u64, DecoderOptions::NONE);
        let mut inst = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut inst);

            // Match PUSH imm32 (opcode 0x68, 5 bytes) or MOV reg/[ebp|esp+disp], imm32.
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

            if is_push_imm32 || is_mov_imm32 {
                let imm = inst.immediate32();
                for (name, target_va) in targets {
                    if imm == *target_va && !resolved.contains_key(name) {
                        // Function start RVA == prologue VA (both relative to
                        // image base since prologue_va = text_va + offset).
                        resolved.insert(*name, func_start_rva);
                        found_any = true;
                    }
                }
                // Early exit if everything is resolved globally.
                if resolved.len() == targets.len() {
                    return found_any;
                }
            }

            // Follow conditional branches (Ja..Js range, excluding Jmp) into the queue.
            // Matches arch-independent behaviour via NearBranch32 (x86) check.
            if inst.mnemonic() >= Mnemonic::Ja
                && inst.mnemonic() <= Mnemonic::Js
                && inst.mnemonic() != Mnemonic::Jmp
                && inst.op0_kind() == OpKind::NearBranch32
            {
                let target = inst.near_branch32();
                if target >= text_va
                    && target < text_end_va
                    && visited.insert(target)
                    && heap.len() < MAX_BLOCKS_PER_FUNCTION
                {
                    heap.push(Reverse(target));
                }
            }

            // Terminate block on RET or unconditional JMP (matches termwrap-dll).
            if inst.mnemonic() == Mnemonic::Ret || inst.mnemonic() == Mnemonic::Jmp {
                break;
            }
        }
    }

    found_any
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-assembled x86 function:
    ///   8B FF            mov edi, edi
    ///   55               push ebp
    ///   8B EC            mov ebp, esp
    ///   68 EF BE AD DE   push 0xDEADBEEF
    ///   C3               ret
    fn tiny_function(imm: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&PROLOGUE);
        v.push(0x68);
        v.extend_from_slice(&imm.to_le_bytes());
        v.push(0xC3);
        v
    }

    #[test]
    fn walker_finds_push_imm32_target() {
        // Simulate a .text section that starts at RVA 0x1000 and an image base of 0x10000000.
        // So the string VA the function pushes is image_base + some str_rva.
        const IMAGE_BASE: u32 = 0x1000_0000;
        const TEXT_VA: u32 = 0x1000;
        const STR_RVA: u32 = 0x4321;
        let target_va = IMAGE_BASE.wrapping_add(STR_RVA);

        // Pad a few bytes of garbage in front so the prologue is not at offset 0.
        let mut text = vec![0x90u8; 7]; // NOPs
        text.extend_from_slice(&tiny_function(target_va));

        let targets = [("cdefpolicy", target_va)];
        let resolved = find_xref_functions(&text, TEXT_VA, &targets);

        // Prologue begins at offset 7 → RVA = TEXT_VA + 7.
        assert_eq!(resolved.get("cdefpolicy"), Some(&(TEXT_VA + 7)));
    }

    #[test]
    fn walker_ignores_unrelated_immediates() {
        const IMAGE_BASE: u32 = 0x1000_0000;
        const TEXT_VA: u32 = 0x1000;
        let target_va = IMAGE_BASE + 0x1234;

        let text = tiny_function(0xCAFE_BABE);

        let targets = [("cdefpolicy", target_va)];
        let resolved = find_xref_functions(&text, TEXT_VA, &targets);

        assert!(!resolved.contains_key("cdefpolicy"));
    }

    #[test]
    fn walker_follows_jcc_into_basic_block() {
        // Prologue, JZ +3 (skip 3 NOPs), NOPs, PUSH imm32 @ branch target, RET.
        //   8B FF 55 8B EC    prologue      (5 bytes, offset 0..5)
        //   74 03             jz +3         (2 bytes, offset 5..7)
        //   90 90 90          3 NOPs        (3 bytes, offset 7..10, skipped)
        //   68 EF BE AD DE    push imm32    (5 bytes, offset 10..15 — JZ target)
        //   C3                ret
        const TEXT_VA: u32 = 0x2000;
        let imm: u32 = 0xDEADBEEF;

        let mut text = Vec::new();
        text.extend_from_slice(&PROLOGUE); // 0..5
        text.extend_from_slice(&[0x74, 0x03]); // jz +3 (to offset 10)
        text.extend_from_slice(&[0x90, 0x90, 0x90]); // 7..10 (fallthrough NOPs)
        text.push(0x68);
        text.extend_from_slice(&imm.to_le_bytes()); // 10..15
        text.push(0xC3); // 15

        let targets = [("x", imm)];
        let resolved = find_xref_functions(&text, TEXT_VA, &targets);

        // Found via fallthrough OR the jcc branch — both paths reach the PUSH.
        assert_eq!(resolved.get("x"), Some(&TEXT_VA));
    }

    #[test]
    fn walker_handles_empty_inputs() {
        assert!(find_xref_functions(&[], 0x1000, &[("a", 1)]).is_empty());
        assert!(find_xref_functions(&tiny_function(0), 0x1000, &[]).is_empty());
    }

    #[test]
    fn walker_matches_mov_reg_imm32() {
        // mov eax, 0xDEADBEEF encoded as B8 EF BE AD DE (5 bytes).
        const TEXT_VA: u32 = 0x3000;
        let imm: u32 = 0xDEAD_BEEF;

        let mut text = Vec::new();
        text.extend_from_slice(&PROLOGUE); // 0..5
        text.push(0xB8); // mov eax, imm32
        text.extend_from_slice(&imm.to_le_bytes()); // 5..10
        text.push(0xC3); // ret

        let targets = [("movhit", imm)];
        let resolved = find_xref_functions(&text, TEXT_VA, &targets);
        assert_eq!(resolved.get("movhit"), Some(&TEXT_VA));
    }
}
