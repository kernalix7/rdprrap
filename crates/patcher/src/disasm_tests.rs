#[cfg(test)]
mod tests {
    use crate::disasm::{decode_at, Arch};
    use iced_x86::Mnemonic;

    #[test]
    fn test_decode_nop() {
        let code = [0x90]; // NOP
        let mut decoder = decode_at(Arch::X64, &code, 0x1000);
        let inst = decoder.decode();
        assert_eq!(inst.mnemonic(), Mnemonic::Nop);
        assert_eq!(inst.len(), 1);
    }

    #[test]
    fn test_decode_mov_eax_1() {
        let code = [0xB8, 0x01, 0x00, 0x00, 0x00]; // mov eax, 1
        let mut decoder = decode_at(Arch::X64, &code, 0x1000);
        let inst = decoder.decode();
        assert_eq!(inst.mnemonic(), Mnemonic::Mov);
        assert_eq!(inst.len(), 5);
    }

    #[test]
    fn test_decode_x86_push() {
        let code = [0x68, 0x78, 0x56, 0x34, 0x12]; // push 0x12345678
        let mut decoder = decode_at(Arch::X86, &code, 0x1000);
        let inst = decoder.decode();
        assert_eq!(inst.mnemonic(), Mnemonic::Push);
        assert_eq!(inst.len(), 5);
    }

    #[test]
    fn test_decode_call_relative() {
        // call +5 (E8 00 00 00 00)
        let code = [0xE8, 0x00, 0x00, 0x00, 0x00];
        let mut decoder = decode_at(Arch::X64, &code, 0x1000);
        let inst = decoder.decode();
        assert_eq!(inst.mnemonic(), Mnemonic::Call);
        assert_eq!(inst.near_branch_target(), 0x1005);
    }

    #[test]
    fn test_decode_lea_rip_relative() {
        // lea rax, [rip+0x12345678]
        let code = [0x48, 0x8D, 0x05, 0x78, 0x56, 0x34, 0x12];
        let mut decoder = decode_at(Arch::X64, &code, 0x1000);
        let inst = decoder.decode();
        assert_eq!(inst.mnemonic(), Mnemonic::Lea);
        // iced-x86 resolves RIP-relative: memory_displacement64() = next_ip + raw_disp
        // So it already IS the absolute target address. Do NOT add next_ip() again.
        assert_eq!(inst.next_ip(), 0x1007);
        assert_eq!(inst.memory_displacement64(), 0x1234667F); // 0x1007 + 0x12345678
    }

    #[test]
    fn test_arch_bitness() {
        assert_eq!(Arch::X64.bitness(), 64);
        assert_eq!(Arch::X86.bitness(), 32);
    }

    #[test]
    fn test_is_near_branch_x64_jz() {
        use crate::disasm::is_near_branch;
        // JZ near (0F 84 xx xx xx xx) — 6 bytes, x64 NearBranch64
        let code = [0x0F, 0x84, 0x10, 0x00, 0x00, 0x00];
        let mut decoder = decode_at(Arch::X64, &code, 0x1000);
        let inst = decoder.decode();
        assert_eq!(inst.mnemonic(), Mnemonic::Je);
        assert!(is_near_branch(&inst));
        assert_eq!(inst.near_branch_target(), 0x1016); // 0x1006 + 0x10
    }

    #[test]
    fn test_is_near_branch_x86_jz_short() {
        use crate::disasm::is_near_branch;
        // JZ short (74 xx) — 2 bytes, x86 NearBranch32
        let code = [0x74, 0x08];
        let mut decoder = decode_at(Arch::X86, &code, 0x1000);
        let inst = decoder.decode();
        assert_eq!(inst.mnemonic(), Mnemonic::Je);
        assert!(is_near_branch(&inst));
        assert_eq!(inst.near_branch_target(), 0x100A); // 0x1002 + 0x08
    }

    #[test]
    fn test_is_near_branch_false_for_register() {
        use crate::disasm::is_near_branch;
        // JMP rax (FF E0) — register operand, NOT a near branch
        let code = [0xFF, 0xE0];
        let mut decoder = decode_at(Arch::X64, &code, 0x1000);
        let inst = decoder.decode();
        assert_eq!(inst.mnemonic(), Mnemonic::Jmp);
        assert!(!is_near_branch(&inst));
    }

    #[test]
    fn test_is_call_to_import_x64() {
        use crate::disasm::is_call_to_import;
        // CALL [rip+0x100] at IP=0x2000 → target = 0x2106 (next_ip=0x2006, disp=0x100)
        let code = [0xFF, 0x15, 0x00, 0x01, 0x00, 0x00]; // call [rip+0x100]
        let mut decoder = decode_at(Arch::X64, &code, 0x2000);
        let inst = decoder.decode();
        assert_eq!(inst.mnemonic(), Mnemonic::Call);
        // memory_displacement64() returns resolved: 0x2006 + 0x100 = 0x2106
        let import_thunk_rva = 0x2106 - 0x1000; // base=0x1000, thunk_rva=0x1106
        assert!(is_call_to_import(
            &inst,
            Arch::X64,
            0x1000,
            import_thunk_rva
        ));
        assert!(!is_call_to_import(&inst, Arch::X64, 0x1000, 0x9999));
    }

    #[test]
    fn test_is_call_to_import_x86() {
        use crate::disasm::is_call_to_import;
        // CALL [0x12345678] — x86 ds:absolute
        let code = [0xFF, 0x15, 0x78, 0x56, 0x34, 0x12];
        let mut decoder = decode_at(Arch::X86, &code, 0x1000);
        let inst = decoder.decode();
        assert_eq!(inst.mnemonic(), Mnemonic::Call);
        // base=0x10000000, thunk at absolute 0x12345678 → rva = 0x02345678
        assert!(is_call_to_import(&inst, Arch::X86, 0x10000000, 0x02345678));
        assert!(!is_call_to_import(&inst, Arch::X86, 0x10000000, 0xFFFF));
    }

    #[test]
    fn test_is_relative_call_to() {
        use crate::disasm::is_relative_call_to;
        // CALL rel32 (E8 xx xx xx xx) → target = 0x1005 + 0x200 = 0x1205
        let code = [0xE8, 0x00, 0x02, 0x00, 0x00];
        let mut decoder = decode_at(Arch::X64, &code, 0x1000);
        let inst = decoder.decode();
        assert!(is_relative_call_to(&inst, 0x1205));
        assert!(!is_relative_call_to(&inst, 0x9999));
    }

    #[test]
    fn test_x86_memory_displacement_register_base() {
        // CMP [ecx+0x320], eax — x86, register base, displacement = raw value
        let code = [0x39, 0x81, 0x20, 0x03, 0x00, 0x00]; // cmp [ecx+0x320], eax
        let mut decoder = decode_at(Arch::X86, &code, 0x1000);
        let inst = decoder.decode();
        assert_eq!(inst.mnemonic(), Mnemonic::Cmp);
        // For register-based memory: displacement is raw, not resolved
        assert_eq!(inst.memory_displacement64(), 0x320);
    }
}
