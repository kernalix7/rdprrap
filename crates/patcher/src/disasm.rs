use crate::error::PatcherError;
use crate::pe::{LoadedPe, RuntimeFunction};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

/// Architecture-specific decoder configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X64,
    X86,
}

impl Arch {
    pub fn bitness(self) -> u32 {
        match self {
            Arch::X64 => 64,
            Arch::X86 => 32,
        }
    }

    pub fn ip_register(self) -> Register {
        match self {
            Arch::X64 => Register::RIP,
            Arch::X86 => Register::EIP,
        }
    }
}

/// Decode instructions from a code buffer starting at a given RVA.
pub fn decode_at(arch: Arch, code: &[u8], rva: u64) -> Decoder<'_> {
    Decoder::with_ip(arch.bitness(), code, rva, DecoderOptions::NONE)
}

/// Search for an xref (LEA reg, [rip+disp]) that points to target_rva.
/// Used on x64 to find which function references a known string.
/// Returns the RVA right after the LEA instruction.
pub fn search_xref_in_function(
    pe: &LoadedPe,
    func: &RuntimeFunction,
    target_rva: u64,
) -> Option<u64> {
    let begin = func.begin_address as usize;
    let length = (func.end_address - func.begin_address) as usize;

    // SAFETY: function range is within the loaded PE
    let code = unsafe { pe.read_bytes(begin, length) };
    let base_addr = pe.rva_to_ptr(begin) as u64;
    let mut decoder = decode_at(Arch::X64, code, base_addr);
    let target_abs = target_rva + pe.base as u64;

    let mut instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);

        if instruction.mnemonic() == Mnemonic::Lea
            && instruction.op1_kind() == OpKind::Memory
            && instruction.memory_base() == Register::RIP
            && instruction.op0_kind() == OpKind::Register
        {
            // LEA reg, [rip + disp] — iced-x86 resolves to absolute address
            let lea_target = instruction.memory_displacement64();
            if lea_target == target_abs {
                return Some(instruction.next_ip() - pe.base as u64);
            }
        }
    }

    None
}

/// Decode a single instruction at the given absolute pointer.
///
/// # Safety
/// `ptr` must point to valid code memory with at least 15 bytes readable.
pub unsafe fn decode_one(arch: Arch, ptr: usize) -> Result<Instruction, PatcherError> {
    let code = std::slice::from_raw_parts(ptr as *const u8, 15);
    let mut decoder = decode_at(arch, code, ptr as u64);
    let mut instruction = Instruction::default();

    if decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        Ok(instruction)
    } else {
        Err(PatcherError::DisassemblyFailed(ptr as u64))
    }
}

/// Helper to check if an instruction is a CALL to a given import thunk address.
/// On x64: `call [rip+disp]` where the resolved address matches target.
/// On x86: `call [disp]` where disp matches target.
pub fn is_call_to_import(
    inst: &Instruction,
    arch: Arch,
    base: usize,
    import_thunk_rva: usize,
) -> bool {
    if inst.mnemonic() != Mnemonic::Call {
        return false;
    }

    match arch {
        Arch::X64 => {
            if inst.op0_kind() == OpKind::Memory && inst.memory_base() == Register::RIP {
                let target = inst.memory_displacement64();
                target == (base + import_thunk_rva) as u64
            } else {
                false
            }
        }
        Arch::X86 => {
            if inst.op0_kind() == OpKind::Memory
                && inst.memory_base() == Register::None
                && inst.memory_segment() == Register::DS
            {
                inst.memory_displacement64() == (base + import_thunk_rva) as u64
            } else {
                false
            }
        }
    }
}

/// Check if instruction is a relative CALL to a given absolute address.
pub fn is_relative_call_to(inst: &Instruction, target_abs: u64) -> bool {
    inst.mnemonic() == Mnemonic::Call
        && is_near_branch(inst)
        && inst.near_branch_target() == target_abs
}

/// Check if an instruction's first operand is a near branch (works for both 32-bit and 64-bit).
/// In iced-x86, 32-bit mode uses NearBranch32, 64-bit mode uses NearBranch64.
pub fn is_near_branch(inst: &Instruction) -> bool {
    matches!(
        inst.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
}
