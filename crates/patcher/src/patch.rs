use crate::error::PatcherError;

/// Write a patch (byte sequence) to the current process's memory.
///
/// Uses WriteProcessMemory to write to the current process, which handles
/// memory protection changes internally (unlike VirtualProtect + memcpy).
///
/// # Safety
/// - `addr` must be a valid memory address within the current process
/// - `bytes` must represent valid machine code for the target architecture
/// - Caller must ensure no other thread is executing the code being patched
///   (use thread suspension)
#[cfg(windows)]
pub unsafe fn write_patch(addr: usize, bytes: &[u8]) -> Result<usize, PatcherError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Threading::GetCurrentProcess;

    let mut written = 0usize;

    // SAFETY: Caller guarantees addr is valid and threads are suspended
    unsafe {
        WriteProcessMemory(
            GetCurrentProcess(),
            addr as *const std::ffi::c_void,
            bytes.as_ptr() as *const std::ffi::c_void,
            bytes.len(),
            Some(&mut written),
        )?;
    }

    Ok(written)
}

/// Stub for non-Windows (testing/development only)
///
/// # Safety
/// No-op on non-Windows; exists for cross-compilation only.
#[cfg(not(windows))]
pub unsafe fn write_patch(_addr: usize, bytes: &[u8]) -> Result<usize, PatcherError> {
    // On non-Windows, just return success with byte count for testing
    Ok(bytes.len())
}

/// NOP sled: fill `len` bytes at `addr` with NOP (0x90)
///
/// # Safety
/// Same as `write_patch`
pub unsafe fn nop_fill(addr: usize, len: usize) -> Result<usize, PatcherError> {
    let nops = vec![0x90u8; len];
    write_patch(addr, &nops)
}

/// Common x86/x64 patch bytecodes used in termsrv.dll patching
pub mod bytecodes {
    /// `mov eax, 1` (5 bytes) — replaces call to return true
    pub const MOV_EAX_1: &[u8] = &[0xB8, 0x01, 0x00, 0x00, 0x00];

    /// x86 DefPolicy JNZ: `mov eax, 0x100` + `mov [ecx+0x320], eax` + `jmp +0x0E` (13 bytes)
    pub const DEFPOLICY_X86_ECX_JNZ: &[u8] = &[
        0xB8, 0x00, 0x01, 0x00, 0x00, // mov eax, 0x100
        0x89, 0x81, 0x20, 0x03, 0x00, 0x00, // mov [ecx+0x320], eax
        0xEB, 0x0E, // jmp short +14
    ];

    /// `mov eax, 0x100` + `mov [esi+0x320], eax` (x86 DefPolicy patch)
    pub const DEFPOLICY_X86_ESI: &[u8] = &[
        0xB8, 0x00, 0x01, 0x00, 0x00, // mov eax, 0x100
        0x89, 0x86, 0x20, 0x03, 0x00, 0x00, // mov [esi+0x320], eax
        0x90, // nop
    ];

    /// `mov eax, 0x100` + `mov [ecx+0x320], eax` + `nop` (x86 DefPolicy JZ variant, 12 bytes)
    pub const DEFPOLICY_X86_ECX_JZ: &[u8] = &[
        0xB8, 0x00, 0x01, 0x00, 0x00, // mov eax, 0x100
        0x89, 0x81, 0x20, 0x03, 0x00, 0x00, // mov [ecx+0x320], eax
        0x90, // nop
    ];

    /// `mov edx, 0x100` + `mov [ecx+0x320], edx` + `pop esi; nop`
    pub const DEFPOLICY_X86_EDX_ECX: &[u8] = &[
        0xBA, 0x00, 0x01, 0x00, 0x00, // mov edx, 0x100
        0x89, 0x91, 0x20, 0x03, 0x00, 0x00, // mov [ecx+0x320], edx
        0x5E, // pop esi
        0x90, // nop
    ];

    /// x64 DefPolicy: `mov eax, 0x100` + `mov [rcx+0x638], eax` + nop (12 bytes)
    pub const DEFPOLICY_X64_RCX: &[u8] = &[
        0xB8, 0x00, 0x01, 0x00, 0x00, // mov eax, 0x100
        0x89, 0x81, 0x38, 0x06, 0x00, 0x00, // mov [rcx+0x638], eax
        0x90, // nop
    ];

    /// x64 DefPolicy: `mov eax, 0x100` + `mov [rdi+0x638], eax` + nop (12 bytes)
    pub const DEFPOLICY_X64_RDI: &[u8] = &[
        0xB8, 0x00, 0x01, 0x00, 0x00, // mov eax, 0x100
        0x89, 0x87, 0x38, 0x06, 0x00, 0x00, // mov [rdi+0x638], eax
        0x90, // nop
    ];

    /// x64 DefPolicy JNZ: `mov eax, 0x100` + `mov [rcx+0x638], eax` + `nop; jmp` (13 bytes)
    pub const DEFPOLICY_X64_RCX_JMP: &[u8] = &[
        0xB8, 0x00, 0x01, 0x00, 0x00, // mov eax, 0x100
        0x89, 0x81, 0x38, 0x06, 0x00, 0x00, // mov [rcx+0x638], eax
        0x90, // nop
        0xEB, // jmp (short)
    ];

    /// x64 DefPolicy JNZ: `mov eax, 0x100` + `mov [rdi+0x638], eax` + `nop; jmp` (13 bytes)
    pub const DEFPOLICY_X64_RDI_JMP: &[u8] = &[
        0xB8, 0x00, 0x01, 0x00, 0x00, // mov eax, 0x100
        0x89, 0x87, 0x38, 0x06, 0x00, 0x00, // mov [rdi+0x638], eax
        0x90, // nop
        0xEB, // jmp (short)
    ];

    /// x86 SingleUser: `pop eax; add esp, 12` — replaces call VerifyVersionInfoW
    pub const SINGLEUSER_X86_POP: &[u8] = &[
        0x58, // pop eax
        0x83, 0xC4, 0x0C, // add esp, 12
        0x90, 0x90, 0x90, // nop padding
    ];

    /// JMP short unconditional (EB) — replaces JZ in LocalOnlyPatch
    pub const JMP_SHORT: &[u8] = &[0xEB];

    /// NOP + JMP near (90 E9) — replaces 6-byte JZ in LocalOnlyPatch
    pub const NOP_JMP_NEAR: &[u8] = &[0x90, 0xE9];

    /// NonRDP patch: `inc dword ptr [ecx/rcx]; xor eax, eax; nop` (5 bytes)
    pub const NONRDP_PATCH: &[u8] = &[
        0xFF, 0x01, // inc dword ptr [ecx]
        0x31, 0xC0, // xor eax, eax
        0x90, // nop
    ];

    /// `xor eax, eax; inc eax; ret` — used for UmWrap PnP redirect
    pub const XOR_EAX_INC_RET: &[u8] = &[
        0x31, 0xC0, // xor eax, eax
        0xFF, 0xC0, // inc eax
        0xC3, // ret
    ];
}

/// Debug output helper (uses OutputDebugStringA on Windows)
#[cfg(windows)]
pub fn debug_log(msg: &str) {
    use std::ffi::CString;
    if let Ok(c_msg) = CString::new(msg) {
        // SAFETY: CString is null-terminated, OutputDebugStringA is safe to call
        unsafe {
            windows::Win32::System::Diagnostics::Debug::OutputDebugStringA(windows::core::PCSTR(
                c_msg.as_ptr() as *const u8,
            ));
        }
    }
}

#[cfg(not(windows))]
pub fn debug_log(msg: &str) {
    eprintln!("[debug] {msg}");
}
