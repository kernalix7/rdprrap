use patcher::patch::debug_log;
use patcher::pattern::find_pattern_in_section;
use patcher::pe::LoadedPe;
use windows::Win32::Foundation::HMODULE;

/// Wide string: "TerminalServices-DeviceRedirection-Licenses-PnpRedirectionAllowed"
const ALLOW_PNP_BYTES: &[u8] =
    b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0D\0e\0v\0i\0c\0e\0R\0e\0d\0i\0r\0e\0c\0t\0i\0o\0n\0-\0L\0i\0c\0e\0n\0s\0e\0s\0-\0P\0n\0p\0R\0e\0d\0i\0r\0e\0c\0t\0i\0o\0n\0A\0l\0l\0o\0w\0e\0d\0\0\0";

/// Wide string: "TerminalServices-DeviceRedirection-Licenses-CameraRedirectionAllowed"
const ALLOW_CAMERA_BYTES: &[u8] =
    b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0D\0e\0v\0i\0c\0e\0R\0e\0d\0i\0r\0e\0c\0t\0i\0o\0n\0-\0L\0i\0c\0e\0n\0s\0e\0s\0-\0C\0a\0m\0e\0r\0a\0R\0e\0d\0i\0r\0e\0c\0t\0i\0o\0n\0A\0l\0l\0o\0w\0e\0d\0\0\0";

/// Apply umrdp.dll patches for PnP and camera redirection.
///
/// # Safety
/// `hmod` must be a valid handle to the loaded umrdp.dll; all other threads suspended.
pub unsafe fn apply_patches(hmod: HMODULE) {
    let base = hmod.0 as usize;

    let pe = match unsafe { LoadedPe::from_base(base) } {
        Ok(pe) => pe,
        Err(e) => {
            debug_log(&format!("UmWrap: Failed to parse PE: {e}"));
            return;
        }
    };

    let rdata = match pe.find_rdata_section() {
        Ok(s) => s,
        Err(e) => {
            debug_log(&format!("UmWrap: Failed to find .rdata: {e}"));
            return;
        }
    };

    let pnp_rva = match find_pattern_in_section(&pe, &rdata, ALLOW_PNP_BYTES) {
        Ok(rva) => rva,
        Err(_) => {
            debug_log("PnpRedirectionAllowed not found\n");
            return;
        }
    };
    let camera_rva = find_pattern_in_section(&pe, &rdata, ALLOW_CAMERA_BYTES).ok();

    // Legacy mode: umrdp.dll imports slc.dll (older SKUs / build paths).
    let legacy = pe.find_import_image("slc.dll").is_some();

    #[cfg(target_arch = "x86_64")]
    // SAFETY: `pe` wraps a loaded umrdp.dll; caller suspended other threads.
    unsafe {
        x64::apply(&pe, pnp_rva, camera_rva, legacy);
    }

    #[cfg(target_arch = "x86")]
    // SAFETY: `pe` wraps a loaded umrdp.dll; caller suspended other threads.
    unsafe {
        x86_apply::apply(&pe, pnp_rva, camera_rva, legacy);
    }

    // Silence unused warnings on non-x86 host targets when building for
    // neither architecture (e.g. a cross-compile stub). Neither arm here
    // is reachable in normal use, but this keeps `cargo check` quiet.
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        let _ = (&pe, pnp_rva, camera_rva, legacy);
    }
}

// =====================================================================
// x64 path — exception-table driven (RIP-relative LEA -> CALL rel32)
// =====================================================================
#[cfg(target_arch = "x86_64")]
mod x64 {
    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
    use patcher::patch::{bytecodes, debug_log, write_patch};
    use patcher::pe::{LoadedPe, RuntimeFunction};

    /// Apply umrdp.dll patches on x64.
    ///
    /// # Safety
    /// `pe` wraps a currently-loaded umrdp.dll; threads are suspended.
    pub(super) unsafe fn apply(
        pe: &LoadedPe,
        pnp_rva: usize,
        camera_rva: Option<usize>,
        legacy: bool,
    ) {
        let func_table = match pe.get_exception_table() {
            Some(t) => t,
            None => {
                debug_log("UmWrap: no exception table\n");
                return;
            }
        };

        let adjusted = pe.adjusted_base;

        for func in func_table.iter() {
            let begin = func.begin_address as usize;
            let length = (func.end_address - func.begin_address) as usize;
            // SAFETY: begin/length describe a function mapped inside the loaded PE.
            let code =
                unsafe { std::slice::from_raw_parts((adjusted + begin) as *const u8, length) };
            let mut decoder =
                Decoder::with_ip(64, code, (adjusted + begin) as u64, DecoderOptions::NONE);
            let mut inst = Instruction::default();

            while decoder.can_decode() {
                decoder.decode_out(&mut inst);

                // Look for LEA reg, [rip+disp] pointing to PnpRedirectionAllowed
                if inst.mnemonic() == Mnemonic::Lea
                    && inst.op1_kind() == OpKind::Memory
                    && inst.memory_base() == Register::RIP
                    && inst.op0_kind() == OpKind::Register
                {
                    let lea_target = inst.memory_displacement64();
                    if lea_target != (adjusted + pnp_rva) as u64 {
                        continue;
                    }

                    let remaining_len =
                        length.saturating_sub((decoder.ip() as usize) - (adjusted + begin));

                    // Short-circuit: large function without camera string and not legacy
                    if remaining_len > 0x1000 && camera_rva.is_none() && !legacy {
                        let bt = pe.backtrace_function(func);
                        let func_addr = adjusted + bt.begin_address as usize;
                        // SAFETY: func_addr is inside the loaded PE; threads suspended.
                        if let Err(e) =
                            unsafe { write_patch(func_addr, bytecodes::XOR_EAX_INC_RET) }
                        {
                            debug_log(&format!("UmWrap: PnP shortcut write failed: {e}\n"));
                        }
                        return;
                    }

                    // SAFETY: decoder.ip() points into this function body.
                    let search_code = unsafe {
                        std::slice::from_raw_parts(
                            decoder.ip() as usize as *const u8,
                            16.min(remaining_len),
                        )
                    };
                    let mut search_decoder =
                        Decoder::with_ip(64, search_code, decoder.ip(), DecoderOptions::NONE);
                    let mut search_inst = Instruction::default();

                    while search_decoder.can_decode() {
                        let call_ip = search_decoder.ip() as usize;
                        search_decoder.decode_out(&mut search_inst);

                        if search_inst.mnemonic() == Mnemonic::Call && search_inst.len() == 5 {
                            if !legacy {
                                // SAFETY: call_ip inside loaded PE; threads suspended.
                                if let Err(e) =
                                    unsafe { write_patch(call_ip, bytecodes::MOV_EAX_1) }
                                {
                                    debug_log(&format!("UmWrap: PnP patch write failed: {e}\n"));
                                }

                                if let Some(cam_rva) = camera_rva {
                                    // SAFETY: same invariants as PnP patch above.
                                    if !unsafe { search_and_patch_camera(pe, func, cam_rva) } {
                                        debug_log("CameraRedirection patch not found\n");
                                    }
                                }
                            } else {
                                // Legacy x64: look for TEST after CALL
                                if search_decoder.can_decode() {
                                    search_decoder.decode_out(&mut search_inst);
                                    if search_inst.mnemonic() == Mnemonic::Test
                                        && search_inst.len() == 2
                                    {
                                        // or dword ptr [rsp+0x40], 1; xor eax, eax
                                        let legacy_patch: &[u8] =
                                            &[0x83, 0x4C, 0x24, 0x40, 0x01, 0x31, 0xC0];
                                        // SAFETY: call_ip inside loaded PE; threads suspended.
                                        if let Err(e) =
                                            unsafe { write_patch(call_ip, legacy_patch) }
                                        {
                                            debug_log(&format!(
                                                "UmWrap: legacy PnP patch failed: {e}\n"
                                            ));
                                        }
                                    } else {
                                        continue;
                                    }
                                }
                            }
                            return;
                        }
                    }

                    debug_log("PnpRedirection patch not found\n");
                    return;
                }
            }
        }

        debug_log("Found nothing to patch\n");
    }

    /// Search within a function for a LEA to camera RVA, then patch the CALL
    /// following it.
    ///
    /// # Safety
    /// Threads must be suspended and `pe` must wrap a loaded module.
    unsafe fn search_and_patch_camera(
        pe: &LoadedPe,
        func: &RuntimeFunction,
        camera_rva: usize,
    ) -> bool {
        let adjusted = pe.adjusted_base;
        let begin = func.begin_address as usize;
        let length = (func.end_address - func.begin_address) as usize;
        // SAFETY: begin/length describe a function mapped inside the loaded PE.
        let code = unsafe { std::slice::from_raw_parts((adjusted + begin) as *const u8, length) };
        let mut decoder =
            Decoder::with_ip(64, code, (adjusted + begin) as u64, DecoderOptions::NONE);
        let mut inst = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut inst);

            if inst.mnemonic() == Mnemonic::Lea
                && inst.op1_kind() == OpKind::Memory
                && inst.memory_base() == Register::RIP
                && inst.op0_kind() == OpKind::Register
            {
                let lea_target = inst.memory_displacement64();
                if lea_target != (adjusted + camera_rva) as u64 {
                    continue;
                }

                let remaining = 16usize;
                // SAFETY: decoder.ip() points into the same function body.
                let search_code = unsafe {
                    std::slice::from_raw_parts(decoder.ip() as usize as *const u8, remaining)
                };
                let mut search =
                    Decoder::with_ip(64, search_code, decoder.ip(), DecoderOptions::NONE);
                let mut search_inst = Instruction::default();

                while search.can_decode() {
                    let call_ip = search.ip() as usize;
                    search.decode_out(&mut search_inst);

                    if search_inst.mnemonic() == Mnemonic::Call && search_inst.len() == 5 {
                        // SAFETY: call_ip inside loaded PE; threads suspended.
                        if let Err(e) = unsafe { write_patch(call_ip, bytecodes::MOV_EAX_1) } {
                            debug_log(&format!("CameraRedirection write failed: {e}\n"));
                            return false;
                        }
                        return true;
                    }
                }
                return false;
            }
        }

        false
    }
}

// =====================================================================
// x86 path — prologue walker (PUSH/MOV imm32 -> CALL rel32)
// =====================================================================
#[cfg(target_arch = "x86")]
mod x86_apply {
    use crate::x86_walk::{walk_function, PROLOGUE};
    use patcher::patch::{bytecodes, debug_log, write_patch};
    use patcher::pe::LoadedPe;

    /// Apply umrdp.dll patches on x86.
    ///
    /// # Safety
    /// `pe` wraps a currently-loaded umrdp.dll; caller has suspended all other
    /// threads before invoking this function.
    pub(super) unsafe fn apply(
        pe: &LoadedPe,
        pnp_rva: usize,
        camera_rva: Option<usize>,
        legacy: bool,
    ) {
        let text = match pe.find_section(".text") {
            Ok(s) => s,
            Err(_) => {
                debug_log("UmWrap: .text section not found\n");
                return;
            }
        };

        let base = pe.adjusted_base;
        let text_start = base + text.virtual_address as usize;
        let text_size = text.raw_data_size as usize;
        if text_size == 0 {
            debug_log("UmWrap: empty .text section\n");
            return;
        }

        // SAFETY: the .text section of a loaded PE is readable for `text_size` bytes.
        let text_slice = unsafe { std::slice::from_raw_parts(text_start as *const u8, text_size) };

        let mut patched_pnp = false;
        // If we never found the camera string in .rdata we have nothing to patch.
        let mut patched_camera = camera_rva.is_none();

        let mut offset = 0usize;
        while offset + PROLOGUE.len() <= text_slice.len() {
            if &text_slice[offset..offset + PROLOGUE.len()] != PROLOGUE {
                offset += 1;
                continue;
            }

            let func_ip = text_start + offset;
            let hits = walk_function(text_slice, text_start, func_ip, base, pnp_rva, camera_rva);

            if !patched_pnp {
                if let Some(&call_ip) = hits.pnp_calls.first() {
                    if legacy {
                        // TODO: authoritative x86 byte sequence for the
                        // umrdp.dll legacy slc.dll path is not available in
                        // upstream references. The x64 path writes
                        // `or [rsp+0x40], 1; xor eax, eax`, but translating
                        // that to `[esp+N]` requires the real N from a
                        // disassembled x86 umrdp.dll. Writing a guessed
                        // sequence would corrupt the stack, so we log and
                        // leave the original (unpatched) behaviour in place.
                        debug_log(
                            "UmWrap: x86 legacy (slc.dll) PnP patch not implemented; skipping\n",
                        );
                    } else {
                        // SAFETY: call_ip inside loaded PE .text; threads suspended.
                        if let Err(e) = unsafe { write_patch(call_ip, bytecodes::MOV_EAX_1) } {
                            debug_log(&format!("UmWrap: x86 PnP patch write failed: {e}\n"));
                        }
                    }
                    patched_pnp = true;
                }
            }

            if !patched_camera {
                if let Some(&call_ip) = hits.camera_calls.first() {
                    // SAFETY: call_ip inside loaded PE .text; threads suspended.
                    if let Err(e) = unsafe { write_patch(call_ip, bytecodes::MOV_EAX_1) } {
                        debug_log(&format!("UmWrap: x86 camera patch write failed: {e}\n"));
                    }
                    patched_camera = true;
                }
            }

            if patched_pnp && patched_camera {
                return;
            }

            offset += PROLOGUE.len();
        }

        if !patched_pnp {
            debug_log("UmWrap: x86 PnpRedirection patch not found\n");
        }
        if camera_rva.is_some() && !patched_camera {
            debug_log("UmWrap: x86 CameraRedirection patch not found\n");
        }
    }
}
