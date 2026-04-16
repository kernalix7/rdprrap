use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
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
/// Finds the function that references TSAudioCaptureAllowed and patches
/// its entry point with `mov eax, 1; ret` to always allow audio capture.
///
/// # Safety
/// `hmod` must be a valid handle to loaded rdpendp.dll
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

        let code = unsafe { std::slice::from_raw_parts((adjusted + begin) as *const u8, length) };
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
                    // Found it — patch the function start with `mov eax, 1; ret`
                    let bt = pe.backtrace_function(func);
                    let func_addr = adjusted + bt.begin_address as usize;
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
