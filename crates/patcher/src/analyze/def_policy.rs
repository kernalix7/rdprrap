//! Pure, side-effect-free analysis core for the DefPolicy patch.
//!
//! This module decodes `CDefPolicy::Query` and produces a [`DefPolicyPatch`]
//! descriptor with a dynamically captured struct-member displacement. It does no
//! memory writes and depends only on `iced-x86` (plus [`crate::encode`]), so it
//! is compiled and unit tested on every host (including the Linux sandbox) and
//! is reused by the Windows-only `def_policy` wrapper that performs the actual
//! patch write, as well as by the `offset-finder` patch-site dry-run.
//!
//! The displacement is captured at runtime because `CDefPolicy`'s member offset
//! shifts between Windows builds; a previous hardcoded `0x63c`/`0x638` scan
//! silently missed the patch site on shifted-struct builds (issue #3).
//!
//! # Region-length reconciliation (safety discipline)
//!
//! Every descriptor written into the *live* termsrv.dll inside svchost must have
//! its emitted byte length reconciled against the exact original region it
//! overwrites, computed from already-decoded instruction lengths — never from a
//! fixed assumption. A short or long write misaligns the trailing short-JMP
//! opcode or overruns following instructions, corrupting a critical system
//! service. The reconciliation rules are:
//!
//! * **Direct JZ / indirect JZ (neutralise form):** the store + NOP padding spans
//!   the entire original region *including* the `CMP`+`Jcc`, so no live
//!   conditional branch is left to test stale registers. `emitted.len() ==
//!   region_len` exactly.
//! * **Direct JNZ (branch-rewrite form):** the `Jne` is turned into an
//!   *unconditional* jump to the SAME target it took (the allow path), encoded by
//!   length:
//!   - **short `75 rel8` (2 bytes):** the store + NOP padding fills the region up
//!     to the `Jne` opcode, then a single `0xEB` is appended that overwrites the
//!     opcode in place, preserving the original `rel8` at `jcc_ip + 1`.
//!     `emitted.len() == region_len + 1`.
//!   - **near `0F 85 rel32` (6 bytes):** a single `0xEB` would corrupt control
//!     flow (`EB 85` plus stray rel32 bytes), so a fresh near `E9 <rel32>` (5
//!     bytes) re-targeted to the original target is emitted, plus one `0x90` NOP
//!     to fill the 6th byte. `emitted.len() == ip_after_jcc - patch_addr`.
//!   - **any other length:** not supported — returns `None` with a skip reason.
//! * **Indirect JNZ:** not supported — returns `None` with a logged skip reason.
//!
//! On any mismatch or non-encodable register the analyzer returns `None` and
//! logs a skip reason (mirroring the umwrap log-and-skip posture) rather than
//! emitting a write whose length has not been reconciled.

use crate::patch::debug_log;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

/// How many bytes of the function body to disassemble while searching for the
/// DefPolicy compare site. Consumed by the Windows `def_policy` wrapper and the
/// `offset-finder` dry-run; on hosts that use neither it exists solely so the
/// core compiles for testing.
#[cfg_attr(all(not(windows), not(test)), allow(dead_code))]
pub const SCAN_LEN: usize = 128;

/// Plausible range for a `CDefPolicy` struct-member displacement. The compare we
/// are after reads a member well inside the object, never a small stack slot or
/// a tiny field near the vtable. Anchoring on this range (plus "immediately
/// followed by Jcc") avoids matching unrelated CMP instructions.
const MIN_STRUCT_DISP: i64 = 0x100;
const MAX_STRUCT_DISP: i64 = 0x4000;

/// Result of analysing `CDefPolicy::Query` for its patch site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefPolicyPatch {
    /// Absolute address where `bytes` must be written.
    pub patch_addr: u64,
    /// `this`-pointer register that holds the struct base.
    pub base_reg: Register,
    /// Register written by the rewritten store (and compared in the original).
    pub value_reg: Register,
    /// Captured write displacement (struct member offset to overwrite).
    pub write_disp: i32,
    /// Whether the compare is followed by `Jne` (JNZ) instead of `Je` (JZ).
    pub is_jnz: bool,
    /// Emitted patch bytes with the captured displacement already spliced in.
    pub bytes: Vec<u8>,
}

/// Return the disassembler bitness for the current target architecture.
fn arch_bits() -> u32 {
    #[cfg(target_arch = "x86")]
    {
        32
    }
    #[cfg(not(target_arch = "x86"))]
    {
        64
    }
}

/// A recently-decoded register load `MOV dst, [base + disp]`, captured with the
/// load instruction's own IP so the direct form can anchor `patch_addr` to the
/// *same* instruction it recovers the write displacement from. Anchoring W and
/// `patch_addr` to one instruction is what guarantees the trailing `0xEB` lands
/// on the original Jcc opcode (see SEC-PATCH-001).
#[derive(Clone, Copy)]
struct RecentLoad {
    base: Register,
    dst: Register,
    disp: i32,
    ip: u64,
}

impl RecentLoad {
    const EMPTY: RecentLoad = RecentLoad {
        base: Register::None,
        dst: Register::None,
        disp: 0,
        ip: 0,
    };
}

/// Pure analysis core: decode `code` (loaded at `base_ip`) and return the patch
/// descriptor, or `None` if no DefPolicy compare site can be identified.
///
/// This performs no memory writes and reads only the supplied slice, which makes
/// it directly unit-testable with hand-built byte sequences. The disassembler
/// bitness is chosen from the build target; [`analyze_defpolicy_bits`] exposes an
/// explicit-bitness variant so both arch shapes can be exercised from one host.
pub fn analyze_defpolicy(code: &[u8], base_ip: u64) -> Option<DefPolicyPatch> {
    analyze_defpolicy_bits(code, base_ip, arch_bits())
}

/// Arch-parameterized core of [`analyze_defpolicy`]. `bits` selects 32-bit
/// (x86) or 64-bit (x64) decoding *and* the matching CMP operand shape, so the
/// host test suite can drive both shapes without cross-compiling. The indirect
/// `MOV;MOV;CMP r,r` form only exists at 64-bit and is gated on `bits == 64`.
pub fn analyze_defpolicy_bits(code: &[u8], base_ip: u64, bits: u32) -> Option<DefPolicyPatch> {
    let mut decoder = Decoder::with_ip(bits, code, base_ip, DecoderOptions::NONE);
    let mut inst = Instruction::default();

    // Bounded ring of recently-decoded register loads `MOV dst, [base + disp]`.
    // Used by the direct form to recover the write displacement `W` *and* the
    // anchor `patch_addr` from the load whose destination is the compared value
    // register, rather than assuming a `compare_disp - 4` field or backing up by
    // the single preceding instruction length.
    let mut recent_loads: [RecentLoad; RECENT_LOAD_WINDOW] =
        [RecentLoad::EMPTY; RECENT_LOAD_WINDOW];
    let mut recent_len: usize = 0;

    // Indirect-form state: first MOV reading a struct member into a register,
    // recorded as (base_reg, dst_reg, first_mov_ip) so a later second MOV + CMP
    // can be matched. The indirect path exists only at 64-bit.
    let mut mov1: Option<(Register, Register, u64)> = None;

    while decoder.can_decode() {
        let current_ip = decoder.ip();
        decoder.decode_out(&mut inst);
        let inst_length = inst.len();

        // === Direct form: CMP of a struct member followed by Jcc ===
        if inst.mnemonic() == Mnemonic::Cmp {
            if let Some((base_reg, value_reg, disp)) = direct_cmp_operands(&inst, bits) {
                if (MIN_STRUCT_DISP..=MAX_STRUCT_DISP).contains(&disp) {
                    let jcc_ip = current_ip + inst_length as u64;
                    if let Some(jcc) = peek_conditional_jump(code, base_ip, jcc_ip, bits) {
                        let CondJump {
                            is_jnz,
                            jcc_len,
                            target: jcc_target,
                        } = jcc;
                        // Recover BOTH `patch_addr` and the write displacement
                        // `W` from the SAME preceding load whose destination is
                        // the compared value register. If no such load exists we
                        // cannot anchor the patch safely, so we skip (SEC-PATCH-
                        // 001 / SEC-PATCH-002): guessing `compare_disp - 4`
                        // mis-targets the wrong CDefPolicy member.
                        let Some(load) =
                            preceding_load(&recent_loads[..recent_len], base_reg, value_reg)
                        else {
                            debug_log("DefPolicy: write displacement not recoverable, skipping\n");
                            return None;
                        };
                        let patch_addr = load.ip;
                        let write_disp = load.disp;
                        let ip_after_jcc = jcc_ip + jcc_len as u64;
                        let bytes = emit_defpolicy_direct(
                            base_reg,
                            value_reg,
                            write_disp,
                            is_jnz,
                            patch_addr,
                            jcc_ip,
                            jcc_len,
                            jcc_target,
                            ip_after_jcc,
                        )?;
                        return Some(DefPolicyPatch {
                            patch_addr,
                            base_reg,
                            value_reg,
                            write_disp,
                            is_jnz,
                            bytes,
                        });
                    }
                }
            }
        }

        // === Indirect form (x64 only): MOV r1,[base+d1]; MOV r2,[base+d2]; CMP r1,r2; Jcc ===
        if bits == 64
            && inst.mnemonic() == Mnemonic::Mov
            && inst.op0_kind() == OpKind::Register
            && inst.op1_kind() == OpKind::Memory
            && inst.memory_base() != Register::RIP
        {
            let disp = inst.memory_displacement64() as i64;
            let mbase = inst.memory_base();
            let dst = inst.op0_register();
            if (MIN_STRUCT_DISP..=MAX_STRUCT_DISP).contains(&disp) {
                match mov1 {
                    Some((b1, r1, first_ip)) if b1 == mbase => {
                        if let Some(patch) = analyze_indirect_compare(
                            code,
                            base_ip,
                            current_ip + inst_length as u64,
                            first_ip,
                            mbase,
                            r1,
                            dst,
                            disp as i32,
                        ) {
                            return Some(patch);
                        }
                        mov1 = Some((mbase, dst, current_ip));
                    }
                    _ => {
                        mov1 = Some((mbase, dst, current_ip));
                    }
                }
            }
        }

        // Record this instruction in the recent-load ring if it is a register
        // load from `[base + disp]`. The direct form consults this to recover
        // both the exact write displacement `W` and the `patch_addr` anchor from
        // the load preceding the compare.
        if inst.mnemonic() == Mnemonic::Mov
            && inst.op0_kind() == OpKind::Register
            && inst.op1_kind() == OpKind::Memory
            && is_plain_base_memory(&inst, bits)
        {
            push_recent_load(
                &mut recent_loads,
                &mut recent_len,
                RecentLoad {
                    base: inst.memory_base(),
                    dst: inst.op0_register(),
                    disp: inst.memory_displacement64() as i32,
                    ip: current_ip,
                },
            );
        }
    }

    None
}

/// How many preceding register loads to retain for direct-form `W` recovery.
/// The matching load is almost always the instruction immediately before the
/// compare; a small window tolerates a few interleaved unrelated instructions
/// while keeping the backward search bounded and allocation-free.
const RECENT_LOAD_WINDOW: usize = 8;

/// Whether `inst`'s memory operand is a plain `[base + disp]` (a real base
/// register, no RIP-relative addressing). Arch-aware: x64 excludes `RIP`, x86
/// requires a non-`None` base.
fn is_plain_base_memory(inst: &Instruction, bits: u32) -> bool {
    if bits == 64 {
        inst.memory_base() != Register::RIP && inst.memory_base() != Register::None
    } else {
        inst.memory_base() != Register::None
    }
}

/// Insert a load record into the fixed-size ring, keeping the most recent
/// [`RECENT_LOAD_WINDOW`] entries in chronological order (oldest first). Older
/// entries are shifted out once the window is full.
fn push_recent_load(
    ring: &mut [RecentLoad; RECENT_LOAD_WINDOW],
    len: &mut usize,
    entry: RecentLoad,
) {
    if *len < RECENT_LOAD_WINDOW {
        ring[*len] = entry;
        *len += 1;
    } else {
        ring.copy_within(1.., 0);
        ring[RECENT_LOAD_WINDOW - 1] = entry;
    }
}

/// Find the nearest preceding `MOV value_reg, [base + W]` in the recent-load
/// window. Scans newest-to-oldest so the closest match wins. Returns the full
/// record (including its IP and displacement) so the caller anchors both
/// `patch_addr` and `write_disp` to one instruction. Returns `None` when no
/// preceding load targets the same value register from the same base register;
/// the caller then skips rather than guessing.
fn preceding_load(
    recent: &[RecentLoad],
    base_reg: Register,
    value_reg: Register,
) -> Option<RecentLoad> {
    recent
        .iter()
        .rev()
        .find(|l| l.base == base_reg && l.dst == value_reg)
        .copied()
}

/// Extract `(base_reg, value_reg, disp)` for a direct DefPolicy compare.
///
/// - x64 shape: `CMP [base+disp], value_reg`
/// - x86 shape: `CMP value_reg, [base+disp]`
fn direct_cmp_operands(inst: &Instruction, bits: u32) -> Option<(Register, Register, i64)> {
    if bits == 64 {
        if inst.op0_kind() == OpKind::Memory
            && inst.op1_kind() == OpKind::Register
            && inst.memory_base() != Register::RIP
        {
            return Some((
                inst.memory_base(),
                inst.op1_register(),
                inst.memory_displacement64() as i64,
            ));
        }
        None
    } else {
        if inst.op1_kind() == OpKind::Memory
            && inst.op0_kind() == OpKind::Register
            && inst.memory_base() != Register::None
        {
            return Some((
                inst.memory_base(),
                inst.op0_register(),
                inst.memory_displacement64() as i64,
            ));
        }
        None
    }
}

/// Outcome of peeking the conditional jump that follows the DefPolicy compare.
///
/// Carries everything the caller needs to neutralise *or* rewrite the branch
/// without re-decoding it: whether it is `Jne` (JZ-inverted), its encoded length
/// (2 for the short `74`/`75 rel8` form, 6 for the near `0F 84`/`0F 85 rel32`
/// form), and — crucially for the direct-JNZ rewrite — the resolved ABSOLUTE
/// branch target. iced-x86's `near_branch_target()` already resolves the target
/// (do NOT add `next_ip()`), and `is_near_branch()` is arch-independent.
#[derive(Clone, Copy)]
struct CondJump {
    is_jnz: bool,
    jcc_len: usize,
    target: u64,
}

/// Decode the instruction at `jcc_ip` from the original `code` slice and report
/// whether it is the conditional jump DefPolicy uses, plus the jump's encoded
/// length and its resolved absolute target (so the caller can compute
/// `ip_after_jcc` for the JZ-neutralise form and re-target the rewritten
/// unconditional jump for the JNZ form regardless of short/near encoding).
///
/// `iced_x86::Decoder` is not `Clone`, so we decode from the byte slice at the
/// computed offset instead of cloning the caller's decoder. Returns
/// `Some(CondJump { .. })` for `Je`/`Jne`, `None` otherwise (including when
/// `jcc_ip` is past the end of `code`, the bytes do not decode, or — defensively
/// — the conditional jump is not a near branch and thus has no resolvable
/// target).
fn peek_conditional_jump(code: &[u8], base_ip: u64, jcc_ip: u64, bits: u32) -> Option<CondJump> {
    let off = jcc_ip.checked_sub(base_ip)? as usize;
    if off >= code.len() {
        return None;
    }
    let mut peek = Decoder::with_ip(bits, &code[off..], jcc_ip, DecoderOptions::NONE);
    if !peek.can_decode() {
        return None;
    }
    let mut inst = Instruction::default();
    peek.decode_out(&mut inst);
    let is_jnz = match inst.mnemonic() {
        Mnemonic::Je => false,
        Mnemonic::Jne => true,
        _ => return None,
    };
    // Both short (`74`/`75 rel8`) and near (`0F 84`/`0F 85 rel32`) Je/Jne are
    // near branches; `near_branch_target()` returns the resolved absolute
    // address for either. Guard defensively so the JNZ rewrite never reads a
    // bogus target from a non-near-branch shape.
    if !crate::disasm::is_near_branch(&inst) {
        return None;
    }
    Some(CondJump {
        is_jnz,
        jcc_len: inst.len(),
        target: inst.near_branch_target(),
    })
}

/// Indirect form (x64): confirm a `CMP r1,r2` (either order) starting at
/// `search_ip`, immediately followed by a conditional jump. On success build a
/// descriptor that rewrites from `first_mov_ip` using `write_disp` (= the second
/// MOV's displacement).
///
/// Only the `Je` (JZ) shape is supported. The `Jne` (JZ-inverted) shape is
/// deliberately *not* patched: the region between `first_mov_ip` and the `Jne`
/// is too small to fit the store, NOP padding, and a correctly-placed short JMP
/// without borrowing the `CMP` ModRM bytes, which historically produced an
/// `EB FE` (`jmp $-2`) infinite self-loop in live termsrv (SEC-ROBUST-01).
///
/// Reachable only from the `bits == 64` arm of [`analyze_defpolicy_bits`], so it
/// is always compiled (no `cfg` gate) and decodes at a fixed 64-bit bitness.
#[allow(clippy::too_many_arguments)]
fn analyze_indirect_compare(
    code: &[u8],
    base_ip: u64,
    search_ip: u64,
    first_mov_ip: u64,
    base_reg: Register,
    r1: Register,
    r2: Register,
    write_disp: i32,
) -> Option<DefPolicyPatch> {
    let start = (search_ip - base_ip) as usize;
    if start >= code.len() {
        return None;
    }
    let mut decoder = Decoder::with_ip(64, &code[start..], search_ip, DecoderOptions::NONE);
    let mut inst = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut inst);
        if inst.mnemonic() == Mnemonic::Cmp
            && inst.op0_kind() == OpKind::Register
            && inst.op1_kind() == OpKind::Register
        {
            let a = inst.op0_register();
            let b = inst.op1_register();
            if (a == r1 && b == r2) || (a == r2 && b == r1) {
                let jcc_ip = inst.ip() + inst.len() as u64;
                let CondJump {
                    is_jnz, jcc_len, ..
                } = peek_conditional_jump(code, base_ip, jcc_ip, 64)?;
                if is_jnz {
                    // SEC-ROBUST-01: the indirect JNZ shape cannot be neutralised
                    // within the available region without corrupting the CMP, so
                    // bail conservatively instead of emitting an EB FE self-loop.
                    debug_log("DefPolicy: indirect JNZ not supported, skipping\n");
                    return None;
                }
                let value_reg = indirect_value_reg(r2);
                // SEC-ROBUST-02: span the store + NOP padding through the original
                // CMP+Jcc so the conditional branch is neutralised rather than
                // left to test stale registers.
                let ip_after_jcc = jcc_ip + jcc_len as u64;
                let region_len = (ip_after_jcc - first_mov_ip) as usize;
                let bytes = emit_store_padded(base_reg, value_reg, write_disp, region_len)?;
                return Some(DefPolicyPatch {
                    patch_addr: first_mov_ip,
                    base_reg,
                    value_reg,
                    write_disp,
                    is_jnz,
                    bytes,
                });
            }
        }
        if matches!(inst.mnemonic(), Mnemonic::Ret) {
            break;
        }
    }
    None
}

/// Map the register loaded by the second indirect MOV to the 32-bit register
/// encoded into the rewritten `mov [base+W], reg` store.
fn indirect_value_reg(r2: Register) -> Register {
    match r2 {
        Register::EDI | Register::RDI => Register::EDI,
        Register::EAX | Register::RAX => Register::EAX,
        Register::R9D | Register::R9 => Register::R9D,
        other => other,
    }
}

/// Build the direct-form patch bytes with full region-length reconciliation.
///
/// * JZ form: the store + NOP padding spans the whole region (load .. after Jcc),
///   so `emitted.len() == region_len` and the `CMP`+`Jcc` are overwritten. This
///   form is length-agnostic w.r.t. the Jcc encoding: `ip_after_jcc` already
///   accounts for `jcc_len`, so both the short (2-byte) and near (6-byte) `Je`
///   are covered by the same store + NOP fill.
/// * JNZ form: the original `Jne` is rewritten into an *unconditional* jump to the
///   SAME target it jumped to (the allow path). The encoding depends on
///   `jcc_len`:
///   - `jcc_len == 2` (short `75 rel8`): store + NOP padding fills the region up
///     to the `Jne` opcode (`prefix.len() == jcc_ip - patch_addr`), then a single
///     `0xEB` is appended that overwrites the `Jne` opcode in place, preserving
///     the original `rel8` at `jcc_ip + 1`. `emitted.len() == region_len + 1`.
///     (Byte-identical to the validated 26200.8037 patch.)
///   - `jcc_len == 6` (near `0F 85 rel32`): store + NOP padding fills the region
///     up to the `Jne` opcode, then a near `E9 <rel32>` (5 bytes) re-targeted to
///     the original `Jne`'s absolute target is appended, plus one `0x90` NOP to
///     fill the 6th byte. `emitted.len() == ip_after_jcc - patch_addr` (the full
///     `[patch_addr, jcc_ip + 6)` region). The spliced bytes decode to an
///     unconditional `JMP` to `target`.
///   - any other `jcc_len`: returns `None` with a logged skip reason.
///
/// Returns `None` (with a logged skip reason) for a non-encodable register, when
/// the store already exceeds the region it must fit inside, when the rewritten
/// near `rel32` does not fit in `i32`, or for an unsupported `Jne` encoding.
#[allow(clippy::too_many_arguments)]
fn emit_defpolicy_direct(
    base_reg: Register,
    value_reg: Register,
    write_disp: i32,
    is_jnz: bool,
    patch_addr: u64,
    jcc_ip: u64,
    jcc_len: usize,
    jcc_target: u64,
    ip_after_jcc: u64,
) -> Option<Vec<u8>> {
    if is_jnz {
        match jcc_len {
            2 => {
                // Short `75 rel8`. Region = [patch_addr, jcc_ip): load + cmp (the
                // Jne opcode itself is replaced in place by the appended 0xEB,
                // which preserves its rel8 at jcc_ip + 1).
                let region_len = (jcc_ip - patch_addr) as usize;
                let mut prefix = emit_store_padded(base_reg, value_reg, write_disp, region_len)?;
                // The appended short-JMP opcode overwrites the original Jne opcode
                // at jcc_ip, turning it into `jmp rel8` while keeping the rel8.
                prefix.push(0xEB);
                Some(prefix)
            }
            6 => {
                // Near `0F 85 rel32`. A single 0xEB here would corrupt control
                // flow (`EB 85` + stray rel32 bytes), so emit a fresh 5-byte near
                // jump `E9 rel32` re-targeted to the ORIGINAL Jne target, then one
                // NOP to fill the 6th byte. Region = [patch_addr, jcc_ip).
                let region_len = (jcc_ip - patch_addr) as usize;
                let mut bytes = emit_store_padded(base_reg, value_reg, write_disp, region_len)?;
                // rel32 is relative to the address AFTER the 5-byte E9 instruction,
                // which starts at jcc_ip. Per CLAUDE.md, `near_branch_target()` is
                // already the resolved absolute target — do NOT add next_ip().
                let rel = (jcc_target as i64) - (jcc_ip as i64 + 5);
                let Ok(rel32) = i32::try_from(rel) else {
                    debug_log("DefPolicy: near JNZ rel32 out of range, skipping\n");
                    return None;
                };
                bytes.push(0xE9);
                bytes.extend_from_slice(&rel32.to_le_bytes());
                bytes.push(0x90); // NOP fills the 6th byte of the original Jne.
                Some(bytes)
            }
            _ => {
                debug_log("DefPolicy: unsupported Jcc length, skipping\n");
                None
            }
        }
    } else {
        // Region = [patch_addr, ip_after_jcc): load + cmp + Jcc, fully replaced
        // by the forced store and NOP padding (no live CMP/Jcc remains). This is
        // length-agnostic: `ip_after_jcc` already folds in `jcc_len` for both the
        // short and near `Je`, so the store + NOP fill spans the whole region.
        let region_len = (ip_after_jcc - patch_addr) as usize;
        emit_store_padded(base_reg, value_reg, write_disp, region_len)
    }
}

/// Emit `mov value32, 0x100` (`fAllowConnections`) then `mov [base+W], value32`,
/// NOP-padded to exactly `region_len` bytes. Returns `None` (with a logged skip
/// reason) for a non-encodable register or when the encoded store is already
/// longer than the region it must fit inside — never a short or long write.
///
/// This is the single choke point for the universal length guard (SEC-WRITE-004
/// / BF-4 / SEC-PATCH-003): extended registers add a REX prefix and RSP/R12/ESP
/// bases add a SIB byte, so the emitted length is computed from the actual
/// encoding and reconciled against `region_len` here rather than assumed.
fn emit_store_padded(
    base_reg: Register,
    value_reg: Register,
    write_disp: i32,
    region_len: usize,
) -> Option<Vec<u8>> {
    let Some(value32) = value_reg_32(value_reg) else {
        debug_log("DefPolicy: value register not encodable as r32, skipping\n");
        return None;
    };

    let Some(mut bytes) = crate::encode::mov_reg_imm32(value32, 0x100) else {
        debug_log("DefPolicy: mov-imm encode failed, skipping\n");
        return None;
    };
    let Some(store) = crate::encode::mov_mem_base_disp32_reg(base_reg, write_disp, value32) else {
        debug_log("DefPolicy: store encode failed, skipping\n");
        return None;
    };
    bytes.extend(store);

    if bytes.len() > region_len {
        debug_log("DefPolicy: emitted store exceeds overwrite region, skipping\n");
        return None;
    }
    while bytes.len() < region_len {
        bytes.push(0x90); // nop
    }

    // Reconciliation invariant: the emitted store must exactly fill the region.
    debug_assert_eq!(bytes.len(), region_len, "store length must equal region");
    Some(bytes)
}

/// Normalize a captured `value_reg` (which may be the 64-bit alias the compiler
/// loaded, e.g. `RAX`/`R9`) to its 32-bit GP register so the encoder emits the
/// `mov r32, 0x100` / `mov [base+W], r32` 32-bit store. Returns `None` for any
/// register that has no 32-bit GP form.
fn value_reg_32(value_reg: Register) -> Option<Register> {
    use iced_x86::Register::*;
    let r = match value_reg {
        EAX | RAX => EAX,
        ECX | RCX => ECX,
        EDX | RDX => EDX,
        EBX | RBX => EBX,
        ESP | RSP => ESP,
        EBP | RBP => EBP,
        ESI | RSI => ESI,
        EDI | RDI => EDI,
        R8D | R8 => R8D,
        R9D | R9 => R9D,
        R10D | R10 => R10D,
        R11D | R11 => R11D,
        R12D | R12 => R12D,
        R13D | R13 => R13D,
        R14D | R14 => R14D,
        R15D | R15 => R15D,
        // `Register::None` is glob-imported above and shadows `Option::None`,
        // so the fall-through arm returns `Option::None` explicitly.
        _ => return Option::None,
    };
    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x1_0000_0000;

    // The x64-shape tests below build 64-bit instruction bytes and therefore
    // pin `analyze_defpolicy_bits(.., 64)` (rather than `analyze_defpolicy`,
    // which keys off the build target) so the suite gives identical results on
    // every host, including the i686/aarch64 cross-clippy targets.

    fn decode_one(bytes: &[u8], ip: u64) -> Instruction {
        let mut dec = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
        let mut inst = Instruction::default();
        dec.decode_out(&mut inst);
        inst
    }

    /// `mov eax, [rcx+disp]` (32-bit load) with a full disp32. Opcode 8B /r,
    /// ModRM mod=10 reg=EAX(000) rm=RCX(001) → 6 bytes.
    fn mov_eax_rcx(disp: i32) -> Vec<u8> {
        let d = disp.to_le_bytes();
        vec![0x8B, 0x81, d[0], d[1], d[2], d[3]]
    }

    /// Build `cmp [base+disp], eax` (opcode 0x39) followed by `jcc rel8`.
    fn cmp_disp_then_jcc(base: Register, disp: i32, jcc: u8) -> Vec<u8> {
        // 39 /r : CMP r/m32, r32 ; ModRM mod=10 (disp32), reg=EAX(000)
        let modrm = match base {
            Register::RCX => 0x81, // mod=10 reg=000 rm=001 (rcx)
            Register::RDI => 0x87, // mod=10 reg=000 rm=111 (rdi)
            _ => panic!("unsupported test base"),
        };
        let d = disp.to_le_bytes();
        let mut v = vec![0x39, modrm, d[0], d[1], d[2], d[3]];
        v.extend_from_slice(&[jcc, 0x10]); // jz/jnz rel8 +0x10
        v
    }

    /// Build `cmp [base+disp], eax` (opcode 0x39) followed by a NEAR `jcc rel32`
    /// (`0F 84`/`0F 85` + 4-byte displacement). `jcc2` is the second opcode byte
    /// (0x84 = je, 0x85 = jne). `rel32` is large enough that it can never be the
    /// short form, so the analyzer is forced through the 6-byte path.
    fn cmp_disp_then_near_jcc(base: Register, disp: i32, jcc2: u8, rel32: i32) -> Vec<u8> {
        let modrm = match base {
            Register::RCX => 0x81, // mod=10 reg=000 rm=001 (rcx)
            Register::RDI => 0x87, // mod=10 reg=000 rm=111 (rdi)
            _ => panic!("unsupported test base"),
        };
        let d = disp.to_le_bytes();
        let mut v = vec![0x39, modrm, d[0], d[1], d[2], d[3]];
        v.push(0x0F);
        v.push(jcc2);
        v.extend_from_slice(&rel32.to_le_bytes());
        v
    }

    /// Splice the emitted patch over a fresh copy of `original` at `patch_off`,
    /// then return the spliced buffer so a test can re-decode it and assert the
    /// control-flow result. Models the in-place write into live termsrv.
    fn splice(original: &[u8], patch_off: usize, patch: &[u8]) -> Vec<u8> {
        let mut out = original.to_vec();
        out[patch_off..patch_off + patch.len()].copy_from_slice(patch);
        out
    }

    fn assert_store(emitted: &[u8], store_off: usize, base: Register, value: Register, disp: i32) {
        let inst = decode_one(&emitted[store_off..], BASE);
        assert_eq!(inst.mnemonic(), Mnemonic::Mov, "store mnemonic");
        assert_eq!(inst.op0_kind(), OpKind::Memory, "store dst memory");
        assert_eq!(inst.memory_base(), base, "store base reg");
        assert_eq!(
            inst.memory_displacement64() as i64,
            disp as i64,
            "store disp"
        );
        assert_eq!(inst.op1_kind(), OpKind::Register, "store src register");
        assert_eq!(inst.op1_register(), value, "store value reg");
    }

    fn assert_load_imm(emitted: &[u8], value: Register) {
        let inst = decode_one(emitted, BASE);
        assert_eq!(inst.mnemonic(), Mnemonic::Mov);
        assert_eq!(inst.op0_kind(), OpKind::Register);
        assert_eq!(inst.op0_register(), value);
        assert_eq!(inst.op1_kind(), OpKind::Immediate32);
        assert_eq!(inst.immediate32(), 0x100);
    }

    // --- Variant 1: eax_rcx (direct, JZ) with a preceding load ---
    #[test]
    fn variant_eax_rcx_jz() {
        // load mov eax,[rcx+0x638]; cmp [rcx+0x63c],eax; jz +0x10.
        let mut code = mov_eax_rcx(0x638);
        code.extend(cmp_disp_then_jcc(Register::RCX, 0x63c, 0x74)); // jz
        let p = analyze_defpolicy_bits(&code, BASE, 64).expect("eax_rcx jz");
        assert_eq!(p.base_reg, Register::RCX);
        assert_eq!(p.value_reg, Register::EAX);
        assert_eq!(p.write_disp, 0x638);
        assert!(!p.is_jnz);
        assert_eq!(p.patch_addr, BASE, "anchor is the load IP");
        assert_load_imm(&p.bytes, Register::EAX);
        assert_store(&p.bytes, 5, Register::RCX, Register::EAX, 0x638);

        // JZ region spans load(6)+cmp(6)+jz(2) = 14; emitted exactly fills it.
        assert_eq!(p.bytes.len(), 14, "JZ emitted == region");

        // Round-trip: the spliced buffer must contain NO live CMP/Jcc.
        let spliced = splice(&code, 0, &p.bytes);
        assert_no_live_cmp_jcc(&spliced, BASE, code.len());
    }

    // --- Variant 2: eax_rcx_jmp (direct, JNZ) with a preceding load ---
    #[test]
    fn variant_eax_rcx_jnz() {
        // load mov eax,[rcx+0x638]; cmp [rcx+0x63c],eax; jnz +0x10.
        let mut code = mov_eax_rcx(0x638);
        code.extend(cmp_disp_then_jcc(Register::RCX, 0x63c, 0x75)); // jnz
        let p = analyze_defpolicy_bits(&code, BASE, 64).expect("eax_rcx jnz");
        assert!(p.is_jnz);
        assert_eq!(p.write_disp, 0x638);
        assert_eq!(p.patch_addr, BASE, "anchor is the load IP");
        assert_load_imm(&p.bytes, Register::EAX);
        assert_store(&p.bytes, 5, Register::RCX, Register::EAX, 0x638);
        assert_eq!(*p.bytes.last().expect("non-empty"), 0xEB);

        // JNZ prefix fills [load, jcc) = 12; +1 for the 0xEB → 13 emitted.
        let jcc_ip = BASE + 12;
        assert_eq!(p.bytes.len(), 13, "JNZ emitted == region + 1");

        // Round-trip: the 0xEB must land on the jne opcode (jcc_ip) and decode
        // to a short JMP whose rel8 is the ORIGINAL +0x10.
        let spliced = splice(&code, 0, &p.bytes);
        assert_short_jmp_at(&spliced, BASE, jcc_ip, 0x10);
    }

    // --- 26200.8037 no-regression: byte-identical to the validated bytes ---
    #[test]
    fn build_26200_8037_byte_identical() {
        // value-load `mov eax,[rcx+638h]` immediately before
        // `cmp [rcx+63c],eax ; jne`.
        let mut code = mov_eax_rcx(0x638);
        code.extend(cmp_disp_then_jcc(Register::RCX, 0x63c, 0x75)); // jne
        let p = analyze_defpolicy_bits(&code, BASE, 64).expect("validated build");
        assert_eq!(p.patch_addr, BASE);
        assert_eq!(p.write_disp, 0x638);
        assert!(p.is_jnz);
        assert_eq!(
            p.bytes,
            vec![
                0xB8, 0x00, 0x01, 0x00, 0x00, // mov eax,0x100
                0x89, 0x81, 0x38, 0x06, 0x00, 0x00, // mov [rcx+0x638],eax
                0x90, // nop
                0xEB, // jmp (short) — overwrites the jne opcode in place
            ],
            "must be byte-identical to the validated 26200.8037 patch"
        );
    }

    // --- Near-form JNZ regression (SEC-NEARJMP-01): `0F 85 rel32` must NOT be
    // patched with a bare 0xEB. The fix re-targets the original Jne via a fresh
    // near `E9 rel32` + NOP; the spliced bytes must decode to an unconditional
    // JMP to the SAME absolute target the Jne took. ---
    #[test]
    fn near_form_jnz_rewrites_unconditional_jmp_to_original_target() {
        // load mov eax,[rcx+0x638] (6); cmp [rcx+0x63c],eax (6); jne near +0x1000.
        // rel32 = 0x1000 is far larger than any rel8 → forces the 6-byte form.
        const REL32: i32 = 0x1000;
        let mut code = mov_eax_rcx(0x638);
        code.extend(cmp_disp_then_near_jcc(Register::RCX, 0x63c, 0x85, REL32)); // jne near
        let jcc_ip = BASE + 12; // load(6)+cmp(6)
        let ip_after_jcc = jcc_ip + 6; // near Jne is 6 bytes
                                       // The ORIGINAL Jne target is resolved absolute: ip_after_jcc + rel32.
        let original_target = ip_after_jcc + REL32 as u64;

        let p = analyze_defpolicy_bits(&code, BASE, 64).expect("near jne");
        assert!(p.is_jnz);
        assert_eq!(p.patch_addr, BASE, "anchor is the load IP");
        assert_eq!(p.write_disp, 0x638);
        assert_load_imm(&p.bytes, Register::EAX);
        assert_store(&p.bytes, 5, Register::RCX, Register::EAX, 0x638);

        // Total emitted must span the FULL region [patch_addr, jcc_ip+6).
        assert_eq!(
            p.bytes.len(),
            (ip_after_jcc - BASE) as usize,
            "near JNZ emitted == full region (load+cmp+6-byte jne)"
        );
        // Final byte is the NOP that fills the 6th byte of the original Jne.
        assert_eq!(*p.bytes.last().expect("non-empty"), 0x90);

        // Round-trip: the rewritten branch at jcc_ip must decode to an
        // UNCONDITIONAL near JMP whose resolved target == the original Jne target.
        let spliced = splice(&code, 0, &p.bytes);
        let off = (jcc_ip - BASE) as usize;
        let jmp = decode_one(&spliced[off..], jcc_ip);
        assert_eq!(jmp.mnemonic(), Mnemonic::Jmp, "0F85 must become a JMP");
        assert_eq!(jmp.len(), 5, "near JMP must be 5 bytes (E9 rel32)");
        assert_eq!(jmp.op0_kind(), OpKind::NearBranch64, "near branch");
        assert_eq!(
            jmp.near_branch_target(),
            original_target,
            "rewritten JMP must target the ORIGINAL Jne destination"
        );

        // And no live conditional branch must remain anywhere in the region.
        assert_no_live_cmp_jcc(&spliced, BASE, code.len());
    }

    // --- emit_defpolicy_direct: an unsupported Jcc length returns None. The
    // analyzer's peek only yields len 2 or 6, so exercise the guard directly. ---
    #[test]
    fn unsupported_jcc_length_returns_none() {
        // Contrive jcc_len = 3 (neither short nor near): the JNZ arm must bail.
        let patch_addr = BASE;
        let jcc_ip = BASE + 12;
        let jcc_len = 3usize;
        let ip_after_jcc = jcc_ip + jcc_len as u64;
        assert!(
            emit_defpolicy_direct(
                Register::RCX,
                Register::EAX,
                0x638,
                true, // is_jnz
                patch_addr,
                jcc_ip,
                jcc_len,
                jcc_ip + 0x100, // arbitrary target
                ip_after_jcc,
            )
            .is_none(),
            "unsupported Jcc length must skip"
        );
    }

    // --- Near-form JZ regression: the JZ neutralise form must already be
    // length-agnostic. A `0F 84 rel32` Je is fully overwritten by store+NOP with
    // no bare-0xEB assumption; emitted == full region, no live CMP/Jcc remains. ---
    #[test]
    fn near_form_jz_neutralised_full_region() {
        const REL32: i32 = 0x2000;
        let mut code = mov_eax_rcx(0x638);
        code.extend(cmp_disp_then_near_jcc(Register::RCX, 0x63c, 0x84, REL32)); // je near
        let ip_after_jcc = BASE + 12 + 6; // load(6)+cmp(6)+near-je(6)
        let p = analyze_defpolicy_bits(&code, BASE, 64).expect("near je");
        assert!(!p.is_jnz);
        assert_eq!(
            p.bytes.len(),
            (ip_after_jcc - BASE) as usize,
            "near JZ emitted == full region"
        );
        let spliced = splice(&code, 0, &p.bytes);
        assert_no_live_cmp_jcc(&spliced, BASE, code.len());
    }

    // --- SEC-PATCH-001: an intervening instruction between load and CMP ---
    #[test]
    fn intervening_instr_direct_jnz_lands_eb_on_jcc() {
        // load mov eax,[rcx+0x638]; <nop>; cmp [rcx+0x63c],eax; jnz +0x10.
        // The matching load is now 2 instructions back, not 1. The naive
        // `current_ip - last_length` would back up by the nop length only and
        // write 0xEB 3 bytes past the jne; the fix anchors on the load IP.
        let mut code = mov_eax_rcx(0x638); // 6 bytes, load_ip = BASE
        code.push(0x90); // nop at BASE+6 (the intervening instruction)
        code.extend(cmp_disp_then_jcc(Register::RCX, 0x63c, 0x75)); // jnz
        let p = analyze_defpolicy_bits(&code, BASE, 64).expect("intervening jnz");
        assert!(p.is_jnz);
        assert_eq!(p.patch_addr, BASE, "anchor stays on the load IP");
        assert_eq!(p.write_disp, 0x638);

        // load(6)+nop(1)+cmp(6) = 13 → jcc_ip = BASE+13; prefix == 13, +1 EB.
        let jcc_ip = BASE + 13;
        assert_eq!(p.bytes.len(), 14, "prefix(13) + 0xEB");
        assert_eq!(*p.bytes.last().expect("non-empty"), 0xEB);

        let spliced = splice(&code, 0, &p.bytes);
        assert_short_jmp_at(&spliced, BASE, jcc_ip, 0x10);
    }

    // --- Variant 3: edi_rcx (indirect, JZ) where second loaded reg is ESI ---
    #[test]
    fn variant_edi_rcx_indirect() {
        let mut code = Vec::new();
        code.extend_from_slice(&[0x8B, 0xB9, 0x3C, 0x06, 0x00, 0x00]); // mov edi,[rcx+0x63c]
        code.extend_from_slice(&[0x8B, 0xB1, 0x38, 0x06, 0x00, 0x00]); // mov esi,[rcx+0x638]
        code.extend_from_slice(&[0x3B, 0xFE]); // cmp edi,esi
        code.extend_from_slice(&[0x74, 0x10]); // jz +0x10
        let p = analyze_defpolicy_bits(&code, BASE, 64).expect("edi_rcx indirect");
        assert_eq!(p.base_reg, Register::RCX);
        assert_eq!(p.write_disp, 0x638); // second MOV displacement
        assert!(!p.is_jnz);
        assert_eq!(p.patch_addr, BASE); // rewrite starts at first MOV
        assert_eq!(p.value_reg, Register::ESI);
        assert_store(&p.bytes, 5, Register::RCX, Register::ESI, 0x638);

        // Region spans both MOVs + cmp + jz = 6+6+2+2 = 16; emitted fills it.
        assert_eq!(p.bytes.len(), 16, "indirect JZ emitted == region");
        let spliced = splice(&code, 0, &p.bytes);
        assert_no_live_cmp_jcc(&spliced, BASE, code.len());
    }

    // --- Variant 3b: indirect (JZ) with EDI as the second loaded reg ---
    #[test]
    fn variant_edi_rcx_indirect_edi_value() {
        let mut code = Vec::new();
        code.extend_from_slice(&[0x8B, 0xB1, 0x3C, 0x06, 0x00, 0x00]); // mov esi,[rcx+0x63c]
        code.extend_from_slice(&[0x8B, 0xB9, 0x38, 0x06, 0x00, 0x00]); // mov edi,[rcx+0x638]
        code.extend_from_slice(&[0x3B, 0xF7]); // cmp esi,edi
        code.extend_from_slice(&[0x74, 0x10]); // jz
        let p = analyze_defpolicy_bits(&code, BASE, 64).expect("edi value indirect");
        assert_eq!(p.value_reg, Register::EDI);
        assert_eq!(p.write_disp, 0x638);
        assert_load_imm(&p.bytes, Register::EDI);
        assert_store(&p.bytes, 5, Register::RCX, Register::EDI, 0x638);
        assert_eq!(p.bytes.len(), 16);
    }

    // --- SEC-ROBUST-01: indirect JNZ must bail (return None) ---
    #[test]
    fn indirect_jnz_returns_none() {
        let mut code = Vec::new();
        code.extend_from_slice(&[0x8B, 0xB9, 0x3C, 0x06, 0x00, 0x00]); // mov edi,[rcx+0x63c]
        code.extend_from_slice(&[0x8B, 0xB1, 0x38, 0x06, 0x00, 0x00]); // mov esi,[rcx+0x638]
        code.extend_from_slice(&[0x3B, 0xFE]); // cmp edi,esi
        code.extend_from_slice(&[0x75, 0x10]); // jnz +0x10
                                               // The indirect JNZ shape historically produced EB FE; it must now bail.
        assert!(
            analyze_defpolicy_bits(&code, BASE, 64).is_none(),
            "indirect JNZ must not be patched"
        );
    }

    // --- Variant 4: r9d_rdi (direct, JNZ) with a preceding load ---
    #[test]
    fn variant_r9d_rdi_jnz() {
        // mov r9d,[rdi+0x638] : 44 8B 8F 38 06 00 00 (7 bytes), load_ip=BASE.
        let mut code = vec![0x44, 0x8B, 0x8F, 0x38, 0x06, 0x00, 0x00];
        // 44 39 8F 3C 06 00 00 : cmp [rdi+0x63c], r9d (7 bytes)
        code.extend_from_slice(&[0x44, 0x39, 0x8F, 0x3C, 0x06, 0x00, 0x00]);
        code.extend_from_slice(&[0x75, 0x10]); // jnz +0x10
        let p = analyze_defpolicy_bits(&code, BASE, 64).expect("r9d_rdi jnz");
        assert_eq!(p.base_reg, Register::RDI);
        assert_eq!(p.value_reg, Register::R9D);
        assert_eq!(p.write_disp, 0x638);
        assert!(p.is_jnz);
        assert_eq!(p.patch_addr, BASE);
        let load = decode_one(&p.bytes, BASE);
        assert_eq!(load.mnemonic(), Mnemonic::Mov);
        assert_eq!(load.op0_register(), Register::R9D);
        assert_eq!(load.immediate32(), 0x100);
        // mov r9d,0x100 is 6 bytes (REX.B+B9+imm32); store starts at 6.
        assert_store(&p.bytes, 6, Register::RDI, Register::R9D, 0x638);
        assert_eq!(*p.bytes.last().expect("non-empty"), 0xEB);

        // load(7)+cmp(7) = 14 → jcc_ip = BASE+14; prefix == 14, +1 EB.
        let jcc_ip = BASE + 14;
        assert_eq!(p.bytes.len(), 15);
        let spliced = splice(&code, 0, &p.bytes);
        assert_short_jmp_at(&spliced, BASE, jcc_ip, 0x10);
    }

    // --- SEC-WRITE-004: extended register (R10D) length parity ---
    #[test]
    fn extended_register_length_parity_round_trip() {
        // base=R8, value=R10D: REX prefixes grow the load/store.
        // mov r10d,[r8+0x700] : 45 8B 90 00 07 00 00 (7), load_ip=BASE.
        let mut code = vec![0x45, 0x8B, 0x90, 0x00, 0x07, 0x00, 0x00];
        // cmp [r8+0x704], r10d : 45 39 90 04 07 00 00 (7)
        code.extend_from_slice(&[0x45, 0x39, 0x90, 0x04, 0x07, 0x00, 0x00]);
        code.extend_from_slice(&[0x74, 0x10]); // jz +0x10
        let p = analyze_defpolicy_bits(&code, BASE, 64).expect("r8/r10d encodable");
        assert_eq!(p.base_reg, Register::R8);
        assert_eq!(p.value_reg, Register::R10D);
        assert_eq!(p.write_disp, 0x700, "W from preceding r10d load");
        assert!(!p.is_jnz);
        assert_load_imm(&p.bytes, Register::R10D);
        // mov r10d,0x100 is REX.B(0x41)+BA+imm32 = 6 bytes; store starts at 6.
        assert_store(&p.bytes, 6, Register::R8, Register::R10D, 0x700);

        // JZ region = load(7)+cmp(7)+jz(2) = 16; emitted must exactly fill it.
        assert_eq!(p.bytes.len(), 16, "extended-reg length parity");
        let spliced = splice(&code, 0, &p.bytes);
        assert_no_live_cmp_jcc(&spliced, BASE, code.len());
    }

    // --- SEC-WRITE-004: SIB-base (RSP) length parity ---
    #[test]
    fn sib_base_length_parity_round_trip() {
        // base=RSP forces a SIB byte in the store, growing it by one byte.
        // mov eax,[rsp+0x638] : 8B 84 24 38 06 00 00 (7), load_ip=BASE.
        let mut code = vec![0x8B, 0x84, 0x24, 0x38, 0x06, 0x00, 0x00];
        // cmp [rsp+0x63c], eax : 39 84 24 3C 06 00 00 (7)
        code.extend_from_slice(&[0x39, 0x84, 0x24, 0x3C, 0x06, 0x00, 0x00]);
        code.extend_from_slice(&[0x74, 0x10]); // jz +0x10
        let p = analyze_defpolicy_bits(&code, BASE, 64).expect("rsp base encodable");
        assert_eq!(p.base_reg, Register::RSP);
        assert_eq!(p.value_reg, Register::EAX);
        assert_eq!(p.write_disp, 0x638);
        assert!(!p.is_jnz);
        // mov eax,0x100 (5) + store-with-SIB (7) = 12; region = 7+7+2 = 16.
        assert_store(&p.bytes, 5, Register::RSP, Register::EAX, 0x638);
        assert_eq!(p.bytes.len(), 16, "SIB-base length parity");
        let spliced = splice(&code, 0, &p.bytes);
        assert_no_live_cmp_jcc(&spliced, BASE, code.len());
    }

    // --- SEC-PATCH-002: no preceding load → return None (no disp-4 guess) ---
    #[test]
    fn no_preceding_load_returns_none() {
        // cmp [rcx+0x63c],eax; jz — no MOV ever loaded EAX from [rcx+W], so the
        // analyzer must skip rather than guess `compare_disp - 4`.
        let code = cmp_disp_then_jcc(Register::RCX, 0x63c, 0x74); // jz
        assert!(
            analyze_defpolicy_bits(&code, BASE, 64).is_none(),
            "missing value-load must skip, not guess disp-4"
        );
    }

    // --- A different preceding-load register/base does NOT match → skip ---
    #[test]
    fn preceding_load_other_register_skips() {
        // Preceding load targets EDX (not the compared EAX), so it must be
        // ignored and, with no matching load, the analyzer skips.
        let mut code = Vec::new();
        // 8B 91 00 06 00 00 : mov edx, [rcx+0x600]
        code.extend_from_slice(&[0x8B, 0x91, 0x00, 0x06, 0x00, 0x00]);
        code.extend(cmp_disp_then_jcc(Register::RCX, 0x63c, 0x74)); // jz
        assert!(analyze_defpolicy_bits(&code, BASE, 64).is_none());
    }

    // --- Shifted displacement: prove disp is dynamic (from preceding load) ---
    #[test]
    fn shifted_displacement_is_dynamic() {
        // Compare at 0x9F8 instead of 0x63c (a shifted-struct build), with a
        // matching preceding load from [rcx+0x9F4].
        let mut code = mov_eax_rcx(0x9F4);
        code.extend(cmp_disp_then_jcc(Register::RCX, 0x9F8, 0x74)); // jz
        let p = analyze_defpolicy_bits(&code, BASE, 64).expect("shifted disp");
        assert_eq!(p.write_disp, 0x9F4, "W is the preceding load's disp");
        assert_store(&p.bytes, 5, Register::RCX, Register::EAX, 0x9F4);
    }

    // --- Negative: CMP not followed by Jcc → no match ---
    #[test]
    fn no_jcc_after_cmp_no_match() {
        let mut code = mov_eax_rcx(0x638);
        code.extend(cmp_disp_then_jcc(Register::RCX, 0x63c, 0x74));
        let len = code.len();
        code[len - 2] = 0x90; // overwrite jz opcode
        code[len - 1] = 0x90; // overwrite rel8
        assert!(analyze_defpolicy_bits(&code, BASE, 64).is_none());
    }

    // --- Negative: displacement out of struct range → no match ---
    #[test]
    fn tiny_displacement_rejected() {
        let mut code = mov_eax_rcx(0x0c);
        code.extend(cmp_disp_then_jcc(Register::RCX, 0x10, 0x74));
        assert!(analyze_defpolicy_bits(&code, BASE, 64).is_none());
    }

    // --- W captured from preceding load, NOT assumed `compare_disp - 4` ---
    #[test]
    fn write_disp_captured_from_preceding_load() {
        // Load EAX from [rcx+0x600], then compare [rcx+0x63c] against EAX.
        // `compare_disp - 4` would be 0x638, but the real preceding load is at
        // 0x600 — the analyzer must capture 0x600 AND anchor patch_addr there.
        let mut code = mov_eax_rcx(0x600);
        code.extend(cmp_disp_then_jcc(Register::RCX, 0x63c, 0x75)); // jnz
        let p = analyze_defpolicy_bits(&code, BASE, 64).expect("preceding-load disp");
        assert_eq!(p.base_reg, Register::RCX);
        assert_eq!(p.value_reg, Register::EAX);
        assert_eq!(p.write_disp, 0x600, "W must be the preceding load's disp");
        assert_eq!(p.patch_addr, BASE, "anchor must be the load IP");
        assert!(p.is_jnz);
        assert_load_imm(&p.bytes, Register::EAX);
        assert_store(&p.bytes, 5, Register::RCX, Register::EAX, 0x600);
    }

    /// Decode the whole `[base_ip, base_ip+len)` window and assert no live `CMP`
    /// or `Je`/`Jne` instruction remains (used to prove the JZ-neutralise forms
    /// fully overwrote the conditional branch).
    fn assert_no_live_cmp_jcc(code: &[u8], base_ip: u64, len: usize) {
        let mut dec = Decoder::with_ip(64, &code[..len], base_ip, DecoderOptions::NONE);
        let mut inst = Instruction::default();
        while dec.can_decode() {
            dec.decode_out(&mut inst);
            assert_ne!(inst.mnemonic(), Mnemonic::Cmp, "no live CMP must remain");
            assert_ne!(inst.mnemonic(), Mnemonic::Je, "no live JE must remain");
            assert_ne!(inst.mnemonic(), Mnemonic::Jne, "no live JNE must remain");
        }
    }

    /// Assert that decoding from `base_ip` reaches a short `JMP` whose IP is
    /// exactly `jcc_ip` and whose rel8 target preserves the original branch
    /// displacement `expected_rel8` (target = jcc_ip + 2 + rel8).
    fn assert_short_jmp_at(code: &[u8], base_ip: u64, jcc_ip: u64, expected_rel8: i8) {
        let off = (jcc_ip - base_ip) as usize;
        let inst = decode_one(&code[off..], jcc_ip);
        assert_eq!(
            inst.mnemonic(),
            Mnemonic::Jmp,
            "0xEB must decode as short JMP"
        );
        // A true short JMP (0xEB) is a 2-byte rel8 near branch.
        assert_eq!(inst.len(), 2, "short JMP must be 2 bytes (EB rel8)");
        assert_eq!(
            inst.op0_kind(),
            OpKind::NearBranch64,
            "must be a near branch"
        );
        let want = jcc_ip + 2 + expected_rel8 as u64;
        assert_eq!(inst.near_branch_target(), want, "rel8 must be preserved");
    }

    // ---- x86 (32-bit) shape, driven via analyze_defpolicy_bits(.., 32) ----
    //
    // The x86 direct compare is `CMP value, [base+disp]` (opcode 0x3B). Running
    // these on the x86_64 host through the explicit-bitness entry point lets the
    // sandbox CI exercise the 32-bit operand shape without cross-compiling.

    /// x86 `mov eax, [ecx+disp]` = 8B 81 disp32 (reg=EAX, rm=ECX, mod=10).
    fn x86_mov_eax_ecx(disp: i32) -> Vec<u8> {
        let d = disp.to_le_bytes();
        vec![0x8B, 0x81, d[0], d[1], d[2], d[3]]
    }

    /// x86 `cmp eax, [ecx+disp]` = 3B 81 disp32, then `jcc rel8`.
    fn x86_cmp_eax_ecx_then_jcc(disp: i32, jcc: u8) -> Vec<u8> {
        let d = disp.to_le_bytes();
        let mut v = vec![0x3B, 0x81, d[0], d[1], d[2], d[3]];
        v.extend_from_slice(&[jcc, 0x10]);
        v
    }

    // --- x86 direct JZ with a preceding load: full neutralise + length parity ---
    #[test]
    fn x86_direct_jz_preceding_load() {
        let mut code = x86_mov_eax_ecx(0x320 - 4); // load from [ecx+0x31c]
        code.extend(x86_cmp_eax_ecx_then_jcc(0x320, 0x74)); // cmp; jz
        let p = analyze_defpolicy_bits(&code, BASE, 32).expect("x86 jz");
        assert_eq!(p.base_reg, Register::ECX);
        assert_eq!(p.value_reg, Register::EAX);
        assert_eq!(p.write_disp, 0x31c, "W from the preceding x86 load");
        assert!(!p.is_jnz);
        assert_eq!(p.patch_addr, BASE, "anchor is the load IP");
        // load(6)+cmp(6)+jz(2) = 14; emitted must exactly fill the region.
        assert_eq!(p.bytes.len(), 14, "x86 JZ length parity");
        let store = decode_one_bits(&p.bytes[5..], BASE, 32);
        assert_eq!(store.mnemonic(), Mnemonic::Mov);
        assert_eq!(store.memory_base(), Register::ECX);
        assert_eq!(store.memory_displacement64() as i64, 0x31c);
    }

    // --- x86 disp-4 fallback removed: no preceding load → None ---
    #[test]
    fn x86_no_preceding_load_returns_none() {
        // `cmp eax,[ecx+0x320]; jz` with NO preceding `mov eax,[ecx+W]`. On the
        // common x86 shape the compare reads the field directly, so guessing
        // `disp-4` would mis-target; the analyzer must skip (SEC-PATCH-002).
        let code = x86_cmp_eax_ecx_then_jcc(0x320, 0x74);
        assert!(
            analyze_defpolicy_bits(&code, BASE, 32).is_none(),
            "x86 missing value-load must skip, not guess disp-4"
        );
    }

    // --- x86 direct JNZ: 0xEB lands on the jne, original rel8 preserved ---
    #[test]
    fn x86_direct_jnz_eb_on_jcc() {
        let mut code = x86_mov_eax_ecx(0x31c);
        code.extend(x86_cmp_eax_ecx_then_jcc(0x320, 0x75)); // cmp; jnz
        let p = analyze_defpolicy_bits(&code, BASE, 32).expect("x86 jnz");
        assert!(p.is_jnz);
        assert_eq!(p.write_disp, 0x31c);
        // load(6)+cmp(6) = 12 prefix; +1 for 0xEB.
        assert_eq!(p.bytes.len(), 13, "x86 JNZ region+1");
        assert_eq!(*p.bytes.last().expect("non-empty"), 0xEB);
        let jcc_ip = BASE + 12;
        let spliced = splice(&code, 0, &p.bytes);
        let off = (jcc_ip - BASE) as usize;
        let jmp = decode_one_bits(&spliced[off..], jcc_ip, 32);
        assert_eq!(jmp.mnemonic(), Mnemonic::Jmp, "0xEB → short JMP");
        assert_eq!(jmp.len(), 2);
        // 32-bit near-branch targets are computed modulo 2^32, so wrap the
        // expected (jcc_ip + 2 + rel8) into the 32-bit address space.
        let want = (jcc_ip + 2 + 0x10) & 0xFFFF_FFFF;
        assert_eq!(jmp.near_branch_target(), want, "rel8 preserved (mod 2^32)");
    }

    /// Decode the first instruction in `bytes` at `ip` with explicit bitness.
    fn decode_one_bits(bytes: &[u8], ip: u64, bits: u32) -> Instruction {
        let mut dec = Decoder::with_ip(bits, bytes, ip, DecoderOptions::NONE);
        let mut inst = Instruction::default();
        dec.decode_out(&mut inst);
        inst
    }
}
