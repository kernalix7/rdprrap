//! Pure, parametric x86/x64 instruction encoder.
//!
//! This module emits a small, fixed set of instruction shapes needed by the
//! termsrv patches (`mov r32, imm32` and `mov [base + disp32], r32`) for *any*
//! register/displacement combination the compiler may have produced — replacing
//! the per-build, per-register `bytecodes::DEFPOLICY_*` templates with on-the-fly
//! encoding.
//!
//! It is intentionally dependency-light: only `iced_x86::Register` is used (for
//! type-safe register identity). No Windows APIs, no `unsafe`, so it builds and
//! unit-tests on any host. All encoding is done by hand against the Intel SDM
//! opcode tables; the test module round-trips every sequence back through an
//! `iced_x86::Decoder` and also asserts byte-for-byte parity with the legacy
//! `bytecodes` templates.

use iced_x86::Register;

/// Register width / class, derived from an `iced_x86::Register`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegClass {
    /// 32-bit general purpose (EAX..R15D).
    Gp32,
    /// 64-bit general purpose (RAX..R15).
    Gp64,
}

/// Decode a general-purpose register into its (class, 4-bit encoding number).
///
/// The encoding number is the raw 0..=15 value used in ModRM.reg / ModRM.rm /
/// the `B8+rd` opcode field, with REX bits supplying the high bit (8..=15).
///
/// Returns `None` for any register that is not a 32-bit or 64-bit GP register
/// (e.g. RIP, segment, XMM, 8/16-bit), so callers fail safely instead of
/// emitting nonsense.
fn gp_reg_info(reg: Register) -> Option<(RegClass, u8)> {
    // Glob-import the register variants for the match arms below. This also
    // brings `Register::None` into scope, which shadows `Option::None`, so the
    // fall-through arm explicitly returns `Option::None`.
    use iced_x86::Register::*;
    let info = match reg {
        // 32-bit GP
        EAX => (RegClass::Gp32, 0),
        ECX => (RegClass::Gp32, 1),
        EDX => (RegClass::Gp32, 2),
        EBX => (RegClass::Gp32, 3),
        ESP => (RegClass::Gp32, 4),
        EBP => (RegClass::Gp32, 5),
        ESI => (RegClass::Gp32, 6),
        EDI => (RegClass::Gp32, 7),
        R8D => (RegClass::Gp32, 8),
        R9D => (RegClass::Gp32, 9),
        R10D => (RegClass::Gp32, 10),
        R11D => (RegClass::Gp32, 11),
        R12D => (RegClass::Gp32, 12),
        R13D => (RegClass::Gp32, 13),
        R14D => (RegClass::Gp32, 14),
        R15D => (RegClass::Gp32, 15),
        // 64-bit GP
        RAX => (RegClass::Gp64, 0),
        RCX => (RegClass::Gp64, 1),
        RDX => (RegClass::Gp64, 2),
        RBX => (RegClass::Gp64, 3),
        RSP => (RegClass::Gp64, 4),
        RBP => (RegClass::Gp64, 5),
        RSI => (RegClass::Gp64, 6),
        RDI => (RegClass::Gp64, 7),
        R8 => (RegClass::Gp64, 8),
        R9 => (RegClass::Gp64, 9),
        R10 => (RegClass::Gp64, 10),
        R11 => (RegClass::Gp64, 11),
        R12 => (RegClass::Gp64, 12),
        R13 => (RegClass::Gp64, 13),
        R14 => (RegClass::Gp64, 14),
        R15 => (RegClass::Gp64, 15),
        _ => return Option::None,
    };
    Some(info)
}

/// REX prefix base (0100 WRXB pattern with all extension bits clear).
const REX_BASE: u8 = 0x40;
const REX_R: u8 = 0x04; // extends ModRM.reg
const REX_B: u8 = 0x01; // extends ModRM.rm / opcode reg / SIB.base

/// SIB byte selecting `[base]` with no index (index=100 == "none", scale=1).
/// Used when the base register is RSP/R12 (x64) or ESP (x86), which the ModRM
/// rm=100 escape would otherwise interpret as "SIB follows".
fn sib_no_index(base_enc: u8) -> u8 {
    // scale=00, index=100 (no index), base = low 3 bits of base encoding.
    0b00_100_000 | (base_enc & 0x07)
}

/// Encode `mov r32, imm32` (opcode `B8+rd`, immediate is 32-bit little-endian).
///
/// Accepts any 32-bit GP register (EAX..R15D). For extended registers
/// (R8D..R15D) a REX.B prefix (`0x41`) is emitted. Returns `None` for any
/// non-32-bit-GP register (including 64-bit registers — this is the 32-bit mov
/// form only).
pub fn mov_reg_imm32(reg: Register, imm: u32) -> Option<Vec<u8>> {
    let (class, enc) = gp_reg_info(reg)?;
    if class != RegClass::Gp32 {
        return None;
    }

    let mut out = Vec::with_capacity(6);
    if enc >= 8 {
        // REX.B extends the opcode register field for R8D..R15D.
        out.push(REX_BASE | REX_B);
    }
    // B8 + low 3 bits of the destination register.
    out.push(0xB8 | (enc & 0x07));
    out.extend_from_slice(&imm.to_le_bytes());
    Some(out)
}

/// Encode a 32-bit store `mov [base + disp32], src` (opcode `89 /r`).
///
/// The displacement is always emitted as a full 4-byte little-endian disp32
/// (ModRM mod=10), even when zero or small, so callers get a fixed-shape store.
///
/// Arch selection is driven by the `base` register class:
/// * 64-bit `base` (RAX..R15)  -> x64 form. `src` must be a 32-bit GP register.
///   REX.R extends `src` (R8D..R15D), REX.B extends `base` (R8..R15). A SIB byte
///   is emitted when `base` is RSP or R12 (rm field would otherwise mean "SIB
///   follows"). RBP/R13 need no SIB here because mod=10 always carries a disp32.
/// * 32-bit `base` (EAX..EDI)  -> x86 form. `src` must be a 32-bit GP register.
///   No REX, no address-size (0x67) prefix. A SIB byte is emitted when `base`
///   is ESP. Extended (R8D..R15D) bases/sources are rejected in 32-bit form.
///
/// Returns `None` for non-GP registers, a `src` that is not 32-bit GP, or an
/// extended register used in the x86 form.
pub fn mov_mem_base_disp32_reg(base: Register, disp: i32, src: Register) -> Option<Vec<u8>> {
    let (base_class, base_enc) = gp_reg_info(base)?;
    let (src_class, src_enc) = gp_reg_info(src)?;

    // The stored value is always 32 bits (opcode 89 stores r32 into m32).
    if src_class != RegClass::Gp32 {
        return None;
    }

    let mut out = Vec::with_capacity(8);

    match base_class {
        RegClass::Gp64 => {
            // x64 form. Build REX only if any extension bit is required.
            let mut rex = REX_BASE;
            if src_enc >= 8 {
                rex |= REX_R;
            }
            if base_enc >= 8 {
                rex |= REX_B;
            }
            if rex != REX_BASE {
                out.push(rex);
            }
        }
        RegClass::Gp32 => {
            // x86 form. Extended registers cannot be encoded without REX, which
            // does not exist in 32-bit mode.
            if base_enc >= 8 || src_enc >= 8 {
                return None;
            }
        }
    }

    // Opcode: 89 = MOV r/m32, r32.
    out.push(0x89);

    // ModRM: mod=10 (disp32), reg=src low 3 bits, rm=base low 3 bits.
    let rm = base_enc & 0x07;
    let modrm = 0b10_000_000 | ((src_enc & 0x07) << 3) | rm;
    out.push(modrm);

    // rm==100 is the "SIB follows" escape; emit a no-index SIB for RSP/R12/ESP.
    if rm == 0b100 {
        out.push(sib_no_index(base_enc));
    }

    out.extend_from_slice(&disp.to_le_bytes());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::{decode_at, Arch};
    use iced_x86::{Mnemonic, OpKind};

    /// Decode the single instruction in `code` and return it.
    fn decode(arch: Arch, code: &[u8]) -> iced_x86::Instruction {
        let mut decoder = decode_at(arch, code, 0x1000);
        decoder.decode()
    }

    // ---- mov r32, imm32 -------------------------------------------------

    #[test]
    fn mov_eax_imm_reference_bytes() {
        let bytes = mov_reg_imm32(Register::EAX, 0x100).expect("eax encodable");
        assert_eq!(bytes, vec![0xB8, 0x00, 0x01, 0x00, 0x00]);

        let inst = decode(Arch::X64, &bytes);
        assert_eq!(inst.mnemonic(), Mnemonic::Mov);
        assert_eq!(inst.op0_kind(), OpKind::Register);
        assert_eq!(inst.op0_register(), Register::EAX);
        assert_eq!(inst.op1_kind(), OpKind::Immediate32);
        assert_eq!(inst.immediate32(), 0x100);
    }

    #[test]
    fn mov_edi_imm_reference_bytes() {
        let bytes = mov_reg_imm32(Register::EDI, 0x100).expect("edi encodable");
        assert_eq!(bytes, vec![0xBF, 0x00, 0x01, 0x00, 0x00]);

        let inst = decode(Arch::X64, &bytes);
        assert_eq!(inst.mnemonic(), Mnemonic::Mov);
        assert_eq!(inst.op0_register(), Register::EDI);
        assert_eq!(inst.immediate32(), 0x100);
    }

    #[test]
    fn mov_r9d_imm_reference_bytes_rex_b() {
        let bytes = mov_reg_imm32(Register::R9D, 0x100).expect("r9d encodable");
        // REX.B (0x41) + B9 (B8 + 1) + imm32.
        assert_eq!(bytes, vec![0x41, 0xB9, 0x00, 0x01, 0x00, 0x00]);

        let inst = decode(Arch::X64, &bytes);
        assert_eq!(inst.mnemonic(), Mnemonic::Mov);
        assert_eq!(inst.op0_register(), Register::R9D);
        assert_eq!(inst.immediate32(), 0x100);
    }

    #[test]
    fn mov_reg_imm32_rejects_non_gp32() {
        // 64-bit register is not the 32-bit mov form.
        assert!(mov_reg_imm32(Register::RAX, 1).is_none());
        // Non-GP registers.
        assert!(mov_reg_imm32(Register::RIP, 1).is_none());
        assert!(mov_reg_imm32(Register::XMM0, 1).is_none());
        assert!(mov_reg_imm32(Register::AL, 1).is_none());
        assert!(mov_reg_imm32(Register::AX, 1).is_none());
        assert!(mov_reg_imm32(Register::None, 1).is_none());
    }

    // ---- mov [base + disp32], src (x64) --------------------------------

    /// Round-trip helper: assert a store decodes to mov [base+disp], src.
    fn assert_store(arch: Arch, bytes: &[u8], base: Register, disp: i64, src: Register) {
        let inst = decode(arch, bytes);
        assert_eq!(inst.mnemonic(), Mnemonic::Mov, "mnemonic");
        assert_eq!(inst.op0_kind(), OpKind::Memory, "dst is memory");
        assert_eq!(inst.memory_base(), base, "memory base");
        assert_eq!(inst.memory_index(), Register::None, "no index");
        assert_eq!(inst.memory_displacement64() as i64, disp, "displacement");
        assert_eq!(inst.op1_kind(), OpKind::Register, "src is register");
        assert_eq!(inst.op1_register(), src, "src register");
        // Whole input consumed by a single instruction.
        assert_eq!(inst.len(), bytes.len(), "instruction length");
    }

    #[test]
    fn store_rcx_disp_eax_reference_bytes() {
        let bytes =
            mov_mem_base_disp32_reg(Register::RCX, 0x638, Register::EAX).expect("encodable");
        assert_eq!(bytes, vec![0x89, 0x81, 0x38, 0x06, 0x00, 0x00]);
        assert_store(Arch::X64, &bytes, Register::RCX, 0x638, Register::EAX);
    }

    #[test]
    fn store_rdi_disp_eax_reference_bytes() {
        let bytes =
            mov_mem_base_disp32_reg(Register::RDI, 0x638, Register::EAX).expect("encodable");
        assert_eq!(bytes, vec![0x89, 0x87, 0x38, 0x06, 0x00, 0x00]);
        assert_store(Arch::X64, &bytes, Register::RDI, 0x638, Register::EAX);
    }

    #[test]
    fn store_rcx_disp_edi_reference_bytes() {
        let bytes =
            mov_mem_base_disp32_reg(Register::RCX, 0x638, Register::EDI).expect("encodable");
        assert_eq!(bytes, vec![0x89, 0xB9, 0x38, 0x06, 0x00, 0x00]);
        assert_store(Arch::X64, &bytes, Register::RCX, 0x638, Register::EDI);
    }

    #[test]
    fn store_rcx_disp_esi_reference_bytes() {
        let bytes =
            mov_mem_base_disp32_reg(Register::RCX, 0x638, Register::ESI).expect("encodable");
        assert_eq!(bytes, vec![0x89, 0xB1, 0x38, 0x06, 0x00, 0x00]);
        assert_store(Arch::X64, &bytes, Register::RCX, 0x638, Register::ESI);
    }

    #[test]
    fn store_rdi_disp_r9d_reference_bytes_rex_r() {
        // Extended source register requires REX.R (0x44).
        let bytes =
            mov_mem_base_disp32_reg(Register::RDI, 0x638, Register::R9D).expect("encodable");
        assert_eq!(bytes, vec![0x44, 0x89, 0x8F, 0x38, 0x06, 0x00, 0x00]);
        assert_store(Arch::X64, &bytes, Register::RDI, 0x638, Register::R9D);
    }

    #[test]
    fn store_rsp_disp_eax_sib_reference_bytes() {
        // RSP base forces a SIB byte (0x24 = no-index, base=RSP).
        let bytes =
            mov_mem_base_disp32_reg(Register::RSP, 0x638, Register::EAX).expect("encodable");
        assert_eq!(bytes, vec![0x89, 0x84, 0x24, 0x38, 0x06, 0x00, 0x00]);
        assert_store(Arch::X64, &bytes, Register::RSP, 0x638, Register::EAX);
    }

    #[test]
    fn store_r12_disp_eax_extended_base_sib() {
        // R12 is the extended analogue of RSP: needs both REX.B and a SIB byte.
        let bytes = mov_mem_base_disp32_reg(Register::R12, 0x10, Register::EAX).expect("encodable");
        // 41 (REX.B) 89 84 24 (SIB) 10 00 00 00.
        assert_eq!(bytes, vec![0x41, 0x89, 0x84, 0x24, 0x10, 0x00, 0x00, 0x00]);
        assert_store(Arch::X64, &bytes, Register::R12, 0x10, Register::EAX);
    }

    #[test]
    fn store_r13_disp_eax_no_sib() {
        // R13 is the extended analogue of RBP. Under mod=10 the disp32 is always
        // present, so no SIB is required — only REX.B.
        let bytes = mov_mem_base_disp32_reg(Register::R13, 0x10, Register::EAX).expect("encodable");
        // 41 (REX.B) 89 85 (mod=10, reg=000, rm=101) 10 00 00 00.
        assert_eq!(bytes, vec![0x41, 0x89, 0x85, 0x10, 0x00, 0x00, 0x00]);
        assert_store(Arch::X64, &bytes, Register::R13, 0x10, Register::EAX);
    }

    #[test]
    fn store_extended_both_base_and_src() {
        // R14 base + R10D src: REX.R | REX.B (0x45).
        let bytes =
            mov_mem_base_disp32_reg(Register::R14, 0x20, Register::R10D).expect("encodable");
        // 45 (REX.R|REX.B) 89 (modrm reg=010, rm=110) ...
        assert_eq!(bytes, vec![0x45, 0x89, 0x96, 0x20, 0x00, 0x00, 0x00]);
        assert_store(Arch::X64, &bytes, Register::R14, 0x20, Register::R10D);
    }

    #[test]
    fn store_negative_disp_le_splice() {
        // disp = -4 must splice as FC FF FF FF (i32 little-endian).
        let bytes = mov_mem_base_disp32_reg(Register::RCX, -4, Register::EAX).expect("encodable");
        assert_eq!(bytes, vec![0x89, 0x81, 0xFC, 0xFF, 0xFF, 0xFF]);
        assert_store(Arch::X64, &bytes, Register::RCX, -4, Register::EAX);
    }

    // ---- mov [base + disp32], src (x86) --------------------------------

    #[test]
    fn store_ecx_disp_eax_x86_reference_bytes() {
        let bytes =
            mov_mem_base_disp32_reg(Register::ECX, 0x638, Register::EAX).expect("encodable");
        assert_eq!(bytes, vec![0x89, 0x81, 0x38, 0x06, 0x00, 0x00]);
        assert_store(Arch::X86, &bytes, Register::ECX, 0x638, Register::EAX);
    }

    #[test]
    fn store_esi_disp_eax_x86_reference_bytes() {
        let bytes =
            mov_mem_base_disp32_reg(Register::ESI, 0x638, Register::EAX).expect("encodable");
        assert_eq!(bytes, vec![0x89, 0x86, 0x38, 0x06, 0x00, 0x00]);
        assert_store(Arch::X86, &bytes, Register::ESI, 0x638, Register::EAX);
    }

    #[test]
    fn store_esp_disp_eax_x86_sib() {
        // ESP base forces a SIB byte in 32-bit form as well.
        let bytes =
            mov_mem_base_disp32_reg(Register::ESP, 0x638, Register::EAX).expect("encodable");
        assert_eq!(bytes, vec![0x89, 0x84, 0x24, 0x38, 0x06, 0x00, 0x00]);
        assert_store(Arch::X86, &bytes, Register::ESP, 0x638, Register::EAX);
    }

    // ---- rejection cases -----------------------------------------------

    #[test]
    fn store_rejects_64bit_src() {
        // Storing a 64-bit register via the 89 r32 form is not supported.
        assert!(mov_mem_base_disp32_reg(Register::RCX, 0, Register::RAX).is_none());
    }

    #[test]
    fn store_rejects_non_gp_registers() {
        assert!(mov_mem_base_disp32_reg(Register::RIP, 0, Register::EAX).is_none());
        assert!(mov_mem_base_disp32_reg(Register::XMM0, 0, Register::EAX).is_none());
        assert!(mov_mem_base_disp32_reg(Register::RCX, 0, Register::XMM0).is_none());
        assert!(mov_mem_base_disp32_reg(Register::None, 0, Register::EAX).is_none());
    }

    #[test]
    fn store_rejects_extended_in_x86_form() {
        // A 32-bit base implies x86 form, where extended regs cannot be encoded.
        assert!(mov_mem_base_disp32_reg(Register::R8D, 0, Register::EAX).is_none());
        assert!(mov_mem_base_disp32_reg(Register::ECX, 0, Register::R9D).is_none());
    }

    // ---- byte-for-byte parity with legacy bytecodes templates ----------

    #[test]
    fn parity_with_legacy_defpolicy_templates() {
        use crate::patch::bytecodes;

        // DEFPOLICY_X64_RCX = mov eax,0x100 ; mov [rcx+0x638],eax ; nop
        let mut rcx = mov_reg_imm32(Register::EAX, 0x100).unwrap();
        rcx.extend(mov_mem_base_disp32_reg(Register::RCX, 0x638, Register::EAX).unwrap());
        rcx.push(0x90); // nop
        assert_eq!(rcx.as_slice(), bytecodes::DEFPOLICY_X64_RCX);

        // DEFPOLICY_X64_RDI = mov eax,0x100 ; mov [rdi+0x638],eax ; nop
        let mut rdi = mov_reg_imm32(Register::EAX, 0x100).unwrap();
        rdi.extend(mov_mem_base_disp32_reg(Register::RDI, 0x638, Register::EAX).unwrap());
        rdi.push(0x90);
        assert_eq!(rdi.as_slice(), bytecodes::DEFPOLICY_X64_RDI);
    }
}
