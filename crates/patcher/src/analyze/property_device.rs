//! Pure, side-effect-free analysis core for the PropertyDevice patch.
//!
//! This module decodes the inner function reached from `GetConnectionProperty`
//! (the one that references the `IS_PNP_DISABLED` GUID) and produces a
//! [`PropertyDevicePatch`] descriptor. It does no memory writes and depends only
//! on `iced-x86` (plus [`crate::encode`] and [`crate::disasm`]), so it is
//! compiled and unit tested on every host (including the Linux sandbox) and is
//! reused by the Windows-only `property_device` wrapper that performs the actual
//! patch write.
//!
//! The struct-member displacement (`MOV reg, [mem + disp]`) is captured at
//! runtime because the offset shifts between Windows builds; the previous code
//! enumerated two observed offsets (`0x1f00` / `0x1f28`) and silently missed the
//! patch site on any build that used a third offset. The real structural
//! signature is the bit-extract that follows the load:
//!
//! * Primary form:   `MOV reg,[mem+disp]` -> `SHR reg, 0x0b` -> `AND reg, 1`
//! * Alternate form: a `Jcc` whose target is `SHR reg, 0x0c` -> `AND reg, 7`
//!
//! The shift amounts `0x0b` / `0x0c` are the bit position of the PnP /
//! redirection flag (semantic, kept) and `AND ...,1` / `AND ...,7` mask the
//! extracted flag. Whatever displacement the `MOV` uses is accepted, so any
//! build's offset works.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

/// How many bytes of the function body to disassemble while searching for the
/// PropertyDevice load/bit-extract site. Consumed only by the Windows
/// `property_device` wrapper; on hosts that do not use it it exists solely so the
/// core compiles for testing.
#[cfg_attr(all(not(windows), not(test)), allow(dead_code))]
pub const SCAN_LEN: usize = 256;

/// How many bytes to read at a `Jcc` target while checking for the alternate
/// `SHR reg, 0x0c` / `AND reg, 7` bit-extract sequence.
#[cfg_attr(all(not(windows), not(test)), allow(dead_code))]
pub const ALT_TARGET_SCAN_LEN: usize = 15;

/// Shift amount of the primary PnP-flag bit-extract (`SHR reg, 0x0b`). This is
/// the bit position of the flag inside the loaded DWORD — semantic, not a
/// build-dependent struct offset, so it stays hardcoded.
const PRIMARY_SHIFT: u8 = 0x0b;

/// Shift amount of the alternate flag bit-extract (`SHR reg, 0x0c`).
const ALT_SHIFT: u8 = 0x0c;

/// Mask applied after the primary shift (`AND reg, 1`). The genuine PnP-flag
/// extract isolates a single bit; requiring this mask (mirroring the alternate
/// path's [`ALT_AND_MASK`] check) prevents rewriting an unrelated `SHR;AND` that
/// happens to share the shift amount but masks a different width (SEC-PATCH-005).
const PRIMARY_AND_MASK: u8 = 1;

/// Mask applied after the alternate shift (`AND reg, 7`).
const ALT_AND_MASK: u8 = 7;

/// Which structural form of the PropertyDevice site was identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyDeviceForm {
    /// Primary: `MOV reg,[mem+disp]` -> `SHR reg, 0x0b` -> `AND reg, 1`.
    /// The patch forces `reg` to a caller-supplied value (PnP-not-disabled).
    Primary,
    /// Alternate: a `Jcc` target containing `SHR reg, 0x0c` -> `AND reg, 7`.
    /// The patch forces `reg` to a caller-supplied driver value.
    Alternate,
}

/// Result of analysing the PropertyDevice inner function for its patch site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyDevicePatch {
    /// Absolute address where `bytes` must be written.
    pub patch_addr: u64,
    /// Which structural form was matched.
    pub form: PropertyDeviceForm,
    /// Register written by the rewritten `mov reg, imm32`.
    pub value_reg: Register,
    /// Captured struct-member displacement of the originating `MOV reg,[mem+disp]`.
    /// Recorded for diagnostics / tests; it is intentionally NOT matched against
    /// any fixed value, which is the whole point of the de-hardcoding.
    pub mov_disp: i64,
    /// Total length (in bytes) of the original `SHR`+`AND` region being overwritten.
    pub patch_len: usize,
    /// Emitted patch bytes (`mov reg, value` + NOP padding to `patch_len`).
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

/// Read an 8-bit immediate value regardless of how iced-x86 classifies it.
///
/// The `83 /r ib` ALU form (`AND r/m32, imm8`) is reported as `Immediate8to32`
/// (the imm8 is sign-extended to 32 bits), while shift counts (`C1 /r ib`) are a
/// plain `Immediate8`. `immediate8()` returns the raw byte for both. Returns
/// `None` for any operand that is not one of those two 8-bit immediate kinds.
fn imm8_value(inst: &Instruction) -> Option<u8> {
    match inst.op1_kind() {
        OpKind::Immediate8 | OpKind::Immediate8to32 => Some(inst.immediate8()),
        _ => None,
    }
}

/// Whether `inst`'s memory operand is a plain `[base + disp]` (a real base
/// register, no RIP-relative addressing). Arch-aware: x64 excludes `RIP`, x86
/// requires a non-`None` base.
fn is_plain_base_memory(inst: &Instruction) -> bool {
    #[cfg(not(target_arch = "x86"))]
    {
        inst.memory_base() != Register::RIP && inst.memory_base() != Register::None
    }
    #[cfg(target_arch = "x86")]
    {
        inst.memory_base() != Register::None
    }
}

/// Decode `code` (loaded at `base_ip`) and return the patch descriptor, or
/// `None` if no PropertyDevice bit-extract site can be identified.
///
/// `primary_value` is the immediate forced into the register for the primary
/// (`SHR 0x0b` / `AND 1`) form — `0` to disable PnP filtering. `alt_value` is the
/// immediate forced for the alternate (`SHR 0x0c` / `AND 7`) form — the universal
/// printer-driver preference.
///
/// `patch_primary` controls whether the primary form is patched. The caller sets
/// it to `false` when PnP redirection is explicitly disabled in the registry, in
/// which case the primary store is left intact (matching the original behaviour
/// that bailed out of the primary path) while the alternate printer-driver form
/// can still be patched.
///
/// `alt_target_bytes` is a closure that, given an absolute jump target address,
/// returns up to [`ALT_TARGET_SCAN_LEN`] bytes loaded there (or `None` if it
/// cannot be read). Injecting the reader keeps this core free of `unsafe` raw
/// memory access while letting the Windows wrapper supply the real bytes and
/// tests supply synthetic ones.
///
/// This performs no memory writes and reads only the supplied slices, which makes
/// it directly unit-testable with hand-built byte sequences.
pub fn analyze_property_device<F>(
    code: &[u8],
    base_ip: u64,
    primary_value: u32,
    alt_value: u32,
    patch_primary: bool,
    mut alt_target_bytes: F,
) -> Option<PropertyDevicePatch>
where
    F: FnMut(u64) -> Option<Vec<u8>>,
{
    let mut decoder = Decoder::with_ip(arch_bits(), code, base_ip, DecoderOptions::NONE);
    let mut inst = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut inst);

        // Anchor: a 32-bit register load `MOV reg, [base + disp]` from a real
        // base register. The displacement is captured, never matched against a
        // fixed value (that was the build-dependent hardcoding being removed).
        if inst.mnemonic() != Mnemonic::Mov
            || inst.op0_kind() != OpKind::Register
            || inst.op0_register().size() != 4
            || inst.op1_kind() != OpKind::Memory
            || !is_plain_base_memory(&inst)
        {
            continue;
        }

        let reg = inst.op0_register();
        let mov_disp = inst.memory_displacement64() as i64;

        // Scan forward from the load for the bit-extract that confirms the site.
        if let Some(patch) = scan_bit_extract(
            &mut decoder,
            reg,
            mov_disp,
            primary_value,
            alt_value,
            patch_primary,
            &mut alt_target_bytes,
        ) {
            return Some(patch);
        }
    }

    None
}

/// Scan forward from a candidate load looking for either the primary
/// `SHR reg, 0x0b` + `AND reg, 1` sequence, or a `Jcc` whose target is the
/// alternate `SHR reg, 0x0c` + `AND reg, 7` sequence. Stops at the first `RET`
/// or `JMP`. Returns the patch descriptor on a confirmed match.
#[allow(clippy::too_many_arguments)]
fn scan_bit_extract<F>(
    decoder: &mut Decoder,
    reg: Register,
    mov_disp: i64,
    primary_value: u32,
    alt_value: u32,
    patch_primary: bool,
    alt_target_bytes: &mut F,
) -> Option<PropertyDevicePatch>
where
    F: FnMut(u64) -> Option<Vec<u8>>,
{
    let mut inst = Instruction::default();

    while decoder.can_decode() {
        let cur_ip = decoder.ip();
        decoder.decode_out(&mut inst);

        // --- Primary: SHR reg, 0x0b then AND reg, imm8 (len <= 3) ---
        if inst.mnemonic() == Mnemonic::Shr
            && inst.op0_kind() == OpKind::Register
            && inst.op0_register() == reg
            && imm8_value(&inst) == Some(PRIMARY_SHIFT)
        {
            let shr_ip = cur_ip;
            let shr_len = inst.len();

            if !decoder.can_decode() {
                return None;
            }
            decoder.decode_out(&mut inst);

            // Require `AND reg, 1`: the genuine single-bit PnP-flag extract. A
            // different mask (or a non-imm8 AND) means a different bit-field, so
            // it must not be rewritten (SEC-PATCH-005). This mirrors the
            // alternate path's `imm8_value(..) == Some(ALT_AND_MASK)` guard.
            if inst.mnemonic() != Mnemonic::And
                || inst.op0_kind() != OpKind::Register
                || inst.op0_register() != reg
                || imm8_value(&inst) != Some(PRIMARY_AND_MASK)
                || inst.len() > 3
            {
                return None;
            }

            // PnP redirection explicitly disabled in the registry: leave the
            // primary store intact (the original code bailed here) and keep
            // scanning so the alternate printer-driver form can still match.
            if !patch_primary {
                continue;
            }

            let patch_len = shr_len + inst.len();
            let bytes = emit_mov_value(reg, primary_value, patch_len)?;
            return Some(PropertyDevicePatch {
                patch_addr: shr_ip,
                form: PropertyDeviceForm::Primary,
                value_reg: reg,
                mov_disp,
                patch_len,
                bytes,
            });
        }

        // --- Alternate: Jcc -> SHR reg, 0x0c then AND reg, 7 ---
        if (inst.mnemonic() == Mnemonic::Jne || inst.mnemonic() == Mnemonic::Je)
            && crate::disasm::is_near_branch(&inst)
        {
            let target = inst.near_branch_target();
            if let Some(target_bytes) = alt_target_bytes(target) {
                if let Some(patch) =
                    analyze_alternate(&target_bytes, target, reg, mov_disp, alt_value)
                {
                    return Some(patch);
                }
            }
        }

        if inst.mnemonic() == Mnemonic::Ret || inst.mnemonic() == Mnemonic::Jmp {
            return None;
        }
    }

    None
}

/// Confirm an alternate `SHR reg, 0x0c` + `AND reg, 7` sequence at a `Jcc`
/// target and build the descriptor that rewrites it as `mov reg, alt_value`.
fn analyze_alternate(
    target_bytes: &[u8],
    target_ip: u64,
    reg: Register,
    mov_disp: i64,
    alt_value: u32,
) -> Option<PropertyDevicePatch> {
    let mut decoder = Decoder::with_ip(arch_bits(), target_bytes, target_ip, DecoderOptions::NONE);
    let mut inst = Instruction::default();

    if !decoder.can_decode() {
        return None;
    }
    decoder.decode_out(&mut inst);

    if inst.mnemonic() != Mnemonic::Shr
        || inst.op0_kind() != OpKind::Register
        || inst.op0_register() != reg
        || imm8_value(&inst) != Some(ALT_SHIFT)
    {
        return None;
    }
    let shr_len = inst.len();

    if !decoder.can_decode() {
        return None;
    }
    decoder.decode_out(&mut inst);

    if inst.mnemonic() != Mnemonic::And
        || inst.op0_kind() != OpKind::Register
        || inst.op0_register() != reg
        || imm8_value(&inst) != Some(ALT_AND_MASK)
    {
        return None;
    }

    let patch_len = shr_len + inst.len();
    let bytes = emit_mov_value(reg, alt_value, patch_len)?;
    Some(PropertyDevicePatch {
        patch_addr: target_ip,
        form: PropertyDeviceForm::Alternate,
        value_reg: reg,
        mov_disp,
        patch_len,
        bytes,
    })
}

/// Build `mov reg, value` via the parametric [`crate::encode`] encoder and pad
/// with NOPs to the original instruction footprint (`patch_len`).
///
/// The encoder handles REX/opcode selection for any 32-bit GP register the
/// compiler picked, so no per-register opcode table is needed here. Returns
/// `None` for a non-encodable register or when the encoded `mov` is already
/// longer than the region being overwritten (the caller then skips/logs rather
/// than corrupting following instructions).
fn emit_mov_value(reg: Register, value: u32, patch_len: usize) -> Option<Vec<u8>> {
    let mut bytes = crate::encode::mov_reg_imm32(reg, value)?;
    if bytes.len() > patch_len {
        return None;
    }
    while bytes.len() < patch_len {
        bytes.push(0x90); // nop
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x1_0000_0000;

    fn decode_one(bytes: &[u8], ip: u64) -> Instruction {
        let mut dec = Decoder::with_ip(arch_bits(), bytes, ip, DecoderOptions::NONE);
        let mut inst = Instruction::default();
        dec.decode_out(&mut inst);
        inst
    }

    /// `mov eax, [rcx+disp]` (32-bit load) with a full disp32, opcode 8B /r,
    /// ModRM mod=10 reg=EAX(000) rm=RCX(001). On x86 this decodes as
    /// `mov eax,[ecx+disp]` which is exactly the shape we want there too.
    fn mov_eax_mem(disp: i32) -> Vec<u8> {
        let d = disp.to_le_bytes();
        vec![0x8B, 0x81, d[0], d[1], d[2], d[3]]
    }

    /// `shr eax, imm8` = C1 E8 ib.
    fn shr_eax(imm: u8) -> Vec<u8> {
        vec![0xC1, 0xE8, imm]
    }

    /// `and eax, imm8` (sign-extended) = 83 E0 ib.
    fn and_eax(imm: u8) -> Vec<u8> {
        vec![0x83, 0xE0, imm]
    }

    /// No-op reader for tests that exercise only the primary path.
    fn no_alt(_addr: u64) -> Option<Vec<u8>> {
        None
    }

    // --- Primary form with the LEGACY 0x1f00 displacement still works ---
    #[test]
    fn primary_legacy_disp_0x1f00() {
        let mut code = mov_eax_mem(0x1f00);
        let shr_off = code.len();
        code.extend(shr_eax(PRIMARY_SHIFT));
        code.extend(and_eax(1));

        let p = analyze_property_device(&code, BASE, 0, 3, true, no_alt).expect("primary 0x1f00");
        assert_eq!(p.form, PropertyDeviceForm::Primary);
        assert_eq!(p.value_reg, Register::EAX);
        assert_eq!(p.mov_disp, 0x1f00);
        assert_eq!(p.patch_addr, BASE + shr_off as u64);
        assert_eq!(p.patch_len, 6); // shr(3) + and(3)
    }

    // --- Primary form with a NON-enumerated displacement (the whole point) ---
    #[test]
    fn primary_novel_disp_0x2a00_is_captured() {
        let mut code = mov_eax_mem(0x2a00); // never in the old 0x1f00/0x1f28 set
        let shr_off = code.len();
        code.extend(shr_eax(PRIMARY_SHIFT));
        code.extend(and_eax(1));

        let p =
            analyze_property_device(&code, BASE, 0, 3, true, no_alt).expect("novel disp captured");
        assert_eq!(p.form, PropertyDeviceForm::Primary);
        assert_eq!(p.mov_disp, 0x2a00, "novel displacement must be captured");
        assert_eq!(p.patch_addr, BASE + shr_off as u64);

        // Emitted patch is `mov eax, 0` then NOP padding to the shr+and length.
        let mov = decode_one(&p.bytes, BASE);
        assert_eq!(mov.mnemonic(), Mnemonic::Mov);
        assert_eq!(mov.op0_register(), Register::EAX);
        assert_eq!(mov.immediate32(), 0);
        assert_eq!(p.bytes.len(), p.patch_len);
        // mov eax,0 is 5 bytes (B8 00 00 00 00), so one trailing NOP.
        assert_eq!(*p.bytes.last().expect("non-empty"), 0x90);
    }

    // --- Primary form with another arbitrary displacement and ECX register ---
    #[test]
    fn primary_ecx_disp_0x3140() {
        // mov ecx,[rdx+0x3140] : 8B 8A 40 31 00 00 (reg=ECX(001) rm=RDX(010))
        let mut code = vec![0x8B, 0x8A, 0x40, 0x31, 0x00, 0x00];
        let shr_off = code.len();
        // shr ecx,0x0b : C1 E9 0B
        code.extend_from_slice(&[0xC1, 0xE9, PRIMARY_SHIFT]);
        // and ecx,1 : 83 E1 01
        code.extend_from_slice(&[0x83, 0xE1, 0x01]);

        let p = analyze_property_device(&code, BASE, 0, 3, true, no_alt).expect("ecx variant");
        assert_eq!(p.value_reg, Register::ECX);
        assert_eq!(p.mov_disp, 0x3140);
        assert_eq!(p.patch_addr, BASE + shr_off as u64);
        let mov = decode_one(&p.bytes, BASE);
        assert_eq!(mov.op0_register(), Register::ECX);
        assert_eq!(mov.immediate32(), 0);
    }

    // --- SHR with the wrong (non-0x0b) shift is rejected ---
    #[test]
    fn wrong_shift_amount_rejected() {
        let mut code = mov_eax_mem(0x1f00);
        code.extend(shr_eax(0x0a)); // not the PnP flag bit position
        code.extend(and_eax(1));
        assert!(analyze_property_device(&code, BASE, 0, 3, true, no_alt).is_none());
    }

    // --- SEC-PATCH-005: primary AND mask != 1 is rejected ---
    #[test]
    fn primary_and_mask_not_one_rejected() {
        // SHR 0x0b then AND eax, 3 (not 1) — same shift, different bit-field, so
        // it is NOT the genuine single-bit PnP-flag extract and must be skipped.
        let mut code = mov_eax_mem(0x1f00);
        code.extend(shr_eax(PRIMARY_SHIFT));
        code.extend(and_eax(3)); // wrong mask
        assert!(
            analyze_property_device(&code, BASE, 0, 3, true, no_alt).is_none(),
            "primary AND mask other than 1 must not be patched"
        );
        // Sanity: AND eax,1 with the same shift DOES match.
        let mut ok = mov_eax_mem(0x1f00);
        ok.extend(shr_eax(PRIMARY_SHIFT));
        ok.extend(and_eax(PRIMARY_AND_MASK));
        assert!(analyze_property_device(&ok, BASE, 0, 3, true, no_alt).is_some());
    }

    // --- SHR not followed by AND reg is rejected ---
    #[test]
    fn shr_without_and_rejected() {
        let mut code = mov_eax_mem(0x1f28);
        code.extend(shr_eax(PRIMARY_SHIFT));
        code.extend_from_slice(&[0x90]); // nop instead of and
        assert!(analyze_property_device(&code, BASE, 0, 3, true, no_alt).is_none());
    }

    // --- Alternate form via Jcc target: SHR 0x0c + AND 7 ---
    // x64-only: the synthetic body is x64 machine code and the analyzer decodes
    // with the host's `arch_bits()`, so this is gated off the x86 host target.
    #[cfg(not(target_arch = "x86"))]
    #[test]
    fn alternate_form_via_jcc_target() {
        // Primary scan must NOT match (use a different shift before the Jcc), so
        // the analyzer reaches the conditional jump and follows it.
        let mut code = mov_eax_mem(0x1f00);
        // jnz +0x20 : 0F 85 rel32 — keeps op0 as a near branch.
        let jcc_off = code.len();
        code.extend_from_slice(&[0x0F, 0x85, 0x20, 0x00, 0x00, 0x00]);
        let jcc_len = code.len() - jcc_off;
        let target_ip = BASE + jcc_off as u64 + jcc_len as u64 + 0x20;

        // Alternate target bytes: shr eax,0x0c ; and eax,7.
        let mut target_bytes = shr_eax(ALT_SHIFT);
        target_bytes.extend(and_eax(ALT_AND_MASK));
        let captured_target = target_ip;

        let reader = |addr: u64| -> Option<Vec<u8>> {
            if addr == captured_target {
                Some(target_bytes.clone())
            } else {
                None
            }
        };

        let p = analyze_property_device(&code, BASE, 0, 4, true, reader).expect("alternate form");
        assert_eq!(p.form, PropertyDeviceForm::Alternate);
        assert_eq!(p.value_reg, Register::EAX);
        assert_eq!(p.patch_addr, target_ip);
        assert_eq!(p.patch_len, 6);
        let mov = decode_one(&p.bytes, BASE);
        assert_eq!(mov.mnemonic(), Mnemonic::Mov);
        assert_eq!(mov.op0_register(), Register::EAX);
        assert_eq!(mov.immediate32(), 4); // alt_value forced
    }

    // --- Alternate target with wrong AND mask is rejected ---
    #[test]
    fn alternate_wrong_and_mask_rejected() {
        let mut code = mov_eax_mem(0x1f00);
        code.extend_from_slice(&[0x0F, 0x85, 0x20, 0x00, 0x00, 0x00]); // jnz rel32

        let mut target_bytes = shr_eax(ALT_SHIFT);
        target_bytes.extend(and_eax(3)); // not 7
        let reader = |_addr: u64| Some(target_bytes.clone());

        assert!(analyze_property_device(&code, BASE, 0, 4, true, reader).is_none());
    }

    // --- RET before any match stops the scan ---
    #[test]
    fn ret_terminates_scan() {
        let mut code = mov_eax_mem(0x1f00);
        code.push(0xC3); // ret
        code.extend(shr_eax(PRIMARY_SHIFT)); // would match but is past the ret
        code.extend(and_eax(1));
        assert!(analyze_property_device(&code, BASE, 0, 3, true, no_alt).is_none());
    }

    // --- No MOV anchor at all -> no match ---
    #[test]
    fn no_anchor_no_match() {
        let code = vec![0x90, 0x90, 0x90, 0xC3];
        assert!(analyze_property_device(&code, BASE, 0, 3, true, no_alt).is_none());
    }

    // --- patch_primary=false suppresses the primary form (fDisablePNPRedir=1) ---
    #[test]
    fn primary_suppressed_when_pnp_disabled() {
        let mut code = mov_eax_mem(0x1f00);
        code.extend(shr_eax(PRIMARY_SHIFT));
        code.extend(and_eax(1));
        code.push(0xC3); // ret so the scan terminates cleanly

        // With patch_primary=false the primary store is left intact and, with no
        // alternate form present, nothing is patched.
        assert!(
            analyze_property_device(&code, BASE, 0, 3, false, no_alt).is_none(),
            "primary must be suppressed when PnP redirection is disabled"
        );
        // Sanity: the same bytes DO match when primary patching is enabled.
        assert!(analyze_property_device(&code, BASE, 0, 3, true, no_alt).is_some());
    }

    // --- patch_primary=false still lets the alternate form patch ---
    // x64-only: synthetic x64 body decoded with the host `arch_bits()`.
    #[cfg(not(target_arch = "x86"))]
    #[test]
    fn alternate_still_applies_when_primary_suppressed() {
        // Primary SHR(0x0b)+AND first, then a Jcc to an alternate site. With
        // patch_primary=false the primary is skipped, scanning continues, and the
        // alternate is patched.
        let mut code = mov_eax_mem(0x1f00);
        code.extend(shr_eax(PRIMARY_SHIFT));
        code.extend(and_eax(1));
        let jcc_off = code.len();
        code.extend_from_slice(&[0x0F, 0x85, 0x20, 0x00, 0x00, 0x00]); // jnz rel32
        let jcc_len = code.len() - jcc_off;
        let target_ip = BASE + jcc_off as u64 + jcc_len as u64 + 0x20;

        let mut target_bytes = shr_eax(ALT_SHIFT);
        target_bytes.extend(and_eax(ALT_AND_MASK));
        let reader = move |addr: u64| -> Option<Vec<u8>> {
            if addr == target_ip {
                Some(target_bytes.clone())
            } else {
                None
            }
        };

        let p = analyze_property_device(&code, BASE, 0, 4, false, reader)
            .expect("alternate applies despite suppressed primary");
        assert_eq!(p.form, PropertyDeviceForm::Alternate);
        assert_eq!(p.patch_addr, target_ip);
        let mov = decode_one(&p.bytes, BASE);
        assert_eq!(mov.immediate32(), 4);
    }
}
