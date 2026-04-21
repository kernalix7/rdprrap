use patcher::patch::{debug_log, write_patch};
use patcher::pattern::find_pattern_in_section;
use patcher::pe::LoadedPe;
use windows::Win32::Foundation::HMODULE;

/// Wide string: "TerminalServices-DeviceRedirection-Licenses-TSAudioCaptureAllowed"
const ALLOW_AUDIO_CAPTURE_BYTES: &[u8] =
    b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0D\0e\0v\0i\0c\0e\0R\0e\0d\0i\0r\0e\0c\0t\0i\0o\0n\0-\0L\0i\0c\0e\0n\0s\0e\0s\0-\0T\0S\0A\0u\0d\0i\0o\0C\0a\0p\0t\0u\0r\0e\0A\0l\0l\0o\0w\0e\0d\0\0\0";

/// `mov eax, 1; ret` — 6 bytes, patches function start to always return TRUE
const MOV_EAX_1_RET: &[u8] = &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];

/// Apply rdpendp.dll patches for audio recording redirection.
///
/// # Safety
/// `hmod` must be a valid handle to loaded rdpendp.dll; all other threads suspended.
pub unsafe fn apply_patches(hmod: HMODULE) {
    let base = hmod.0 as usize;

    let pe = match unsafe { LoadedPe::from_base(base) } {
        Ok(pe) => pe,
        Err(e) => {
            debug_log(&format!("EndpWrap: Failed to parse PE: {e}"));
            return;
        }
    };

    let rdata = match pe.find_rdata_section() {
        Ok(s) => s,
        Err(e) => {
            debug_log(&format!("EndpWrap: Failed to find .rdata: {e}"));
            return;
        }
    };

    let audio_capture_rva = match find_pattern_in_section(&pe, &rdata, ALLOW_AUDIO_CAPTURE_BYTES) {
        Ok(rva) => rva,
        Err(_) => {
            debug_log("EndpWrap: TSAudioCaptureAllowed not found\n");
            return;
        }
    };

    #[cfg(target_arch = "x86_64")]
    // SAFETY: `pe` wraps a loaded rdpendp.dll; threads suspended by caller.
    unsafe {
        x64::apply(&pe, audio_capture_rva);
    }

    #[cfg(target_arch = "x86")]
    // SAFETY: `pe` wraps a loaded rdpendp.dll; threads suspended by caller.
    unsafe {
        x86_apply::apply(&pe, audio_capture_rva);
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        let _ = (&pe, audio_capture_rva);
    }
}

// =====================================================================
// x64 path — exception-table driven (RIP-relative LEA)
// =====================================================================
#[cfg(target_arch = "x86_64")]
mod x64 {
    use super::{debug_log, write_patch, MOV_EAX_1_RET};
    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
    use patcher::pe::LoadedPe;

    /// Apply rdpendp.dll audio-capture patch on x64.
    ///
    /// # Safety
    /// `pe` wraps a loaded rdpendp.dll; threads suspended.
    pub(super) unsafe fn apply(pe: &LoadedPe, audio_capture_rva: usize) {
        let func_table = match pe.get_exception_table() {
            Some(t) => t,
            None => {
                debug_log("EndpWrap: no exception table\n");
                return;
            }
        };

        let adjusted = pe.adjusted_base;

        for func in &func_table {
            let begin = func.begin_address as usize;
            let length = (func.end_address - func.begin_address) as usize;
            if length == 0 {
                continue;
            }

            // SAFETY: begin/length describe a function mapped inside the loaded PE.
            let code =
                unsafe { std::slice::from_raw_parts((adjusted + begin) as *const u8, length) };
            let mut decoder =
                Decoder::with_ip(64, code, (adjusted + begin) as u64, DecoderOptions::NONE);
            let mut inst = Instruction::default();

            while decoder.can_decode() {
                decoder.decode_out(&mut inst);

                // Look for LEA reg, [rip+disp] pointing to TSAudioCaptureAllowed
                if inst.mnemonic() == Mnemonic::Lea
                    && inst.op1_kind() == OpKind::Memory
                    && inst.memory_base() == Register::RIP
                    && inst.op0_kind() == OpKind::Register
                {
                    let lea_target = inst.memory_displacement64();
                    if lea_target == (adjusted + audio_capture_rva) as u64 {
                        let bt = pe.backtrace_function(func);
                        let func_addr = adjusted + bt.begin_address as usize;
                        // SAFETY: func_addr inside loaded PE; threads suspended.
                        if let Err(e) = unsafe { write_patch(func_addr, MOV_EAX_1_RET) } {
                            debug_log(&format!("EndpWrap: patch write failed: {e}\n"));
                        }
                        return;
                    }
                }
            }
        }

        debug_log("EndpWrap: AllowAudioCapture not found\n");
    }
}

// =====================================================================
// x86 path — prologue walker
// =====================================================================
#[cfg(target_arch = "x86")]
mod x86_apply {
    use super::{debug_log, write_patch, MOV_EAX_1_RET};
    use crate::x86_walk::{function_references_rva, PROLOGUE};
    use patcher::pe::LoadedPe;

    /// Apply rdpendp.dll audio-capture patch on x86.
    ///
    /// Scans `.text` for function prologues, BFS-walks each candidate function
    /// for a PUSH/MOV imm32 referencing `base + audio_capture_rva`, and on the
    /// first match overwrites the prologue with `mov eax, 1; ret`.
    ///
    /// # Safety
    /// `pe` wraps a currently-loaded rdpendp.dll; caller has suspended all
    /// other threads before invoking.
    pub(super) unsafe fn apply(pe: &LoadedPe, audio_capture_rva: usize) {
        let text = match pe.find_section(".text") {
            Ok(s) => s,
            Err(_) => {
                debug_log("EndpWrap: .text section not found\n");
                return;
            }
        };

        let base = pe.adjusted_base;
        let text_start = base + text.virtual_address as usize;
        let text_size = text.raw_data_size as usize;
        if text_size == 0 {
            debug_log("EndpWrap: empty .text section\n");
            return;
        }

        // SAFETY: the .text section of a loaded PE is readable for `text_size` bytes.
        let text_slice = unsafe { std::slice::from_raw_parts(text_start as *const u8, text_size) };

        let mut offset = 0usize;
        while offset + PROLOGUE.len() <= text_slice.len() {
            if &text_slice[offset..offset + PROLOGUE.len()] != PROLOGUE {
                offset += 1;
                continue;
            }

            let func_ip = text_start + offset;
            if function_references_rva(text_slice, text_start, func_ip, base, audio_capture_rva) {
                // SAFETY: func_ip is the address of a prologue inside the
                // loaded PE .text; threads are suspended.
                if let Err(e) = unsafe { write_patch(func_ip, MOV_EAX_1_RET) } {
                    debug_log(&format!("EndpWrap: x86 patch write failed: {e}\n"));
                }
                return;
            }

            offset += PROLOGUE.len();
        }

        debug_log("EndpWrap: x86 AllowAudioCapture not found\n");
    }
}
