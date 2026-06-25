use patcher::patch::debug_log;
#[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64"))]
use patcher::pattern::find_pattern_in_section;
#[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64"))]
use patcher::pe::LoadedPe;
use windows::Win32::Foundation::HMODULE;

/// Wide string: "TerminalServices-DeviceRedirection-Licenses-PnpRedirectionAllowed"
#[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64"))]
const ALLOW_PNP_BYTES: &[u8] =
    b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0D\0e\0v\0i\0c\0e\0R\0e\0d\0i\0r\0e\0c\0t\0i\0o\0n\0-\0L\0i\0c\0e\0n\0s\0e\0s\0-\0P\0n\0p\0R\0e\0d\0i\0r\0e\0c\0t\0i\0o\0n\0A\0l\0l\0o\0w\0e\0d\0\0\0";

/// Wide string: "TerminalServices-DeviceRedirection-Licenses-CameraRedirectionAllowed"
#[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64"))]
const ALLOW_CAMERA_BYTES: &[u8] =
    b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0D\0e\0v\0i\0c\0e\0R\0e\0d\0i\0r\0e\0c\0t\0i\0o\0n\0-\0L\0i\0c\0e\0n\0s\0e\0s\0-\0C\0a\0m\0e\0r\0a\0R\0e\0d\0i\0r\0e\0c\0t\0i\0o\0n\0A\0l\0l\0o\0w\0e\0d\0\0\0";

/// Clamp a read length so `[addr, addr + len)` stays within the loaded image
/// extent `[img_lo, img_hi)`.
///
/// Returns 0 when `addr` is outside the image, otherwise the smaller of `len`
/// and the bytes mapped after `addr`. This bounds the exception-table-driven
/// function-body reads on x64 so a malformed RUNTIME_FUNCTION (length running
/// off the mapping, or a function near the end of the image) cannot read past
/// the mapping and fault the svchost (SEC-CU-01).
#[cfg(target_arch = "x86_64")]
fn clamp_read_len(addr: usize, len: usize, img_lo: usize, img_hi: usize) -> usize {
    if addr < img_lo || addr >= img_hi {
        return 0;
    }
    len.min(img_hi.saturating_sub(addr))
}

/// Apply umrdp.dll patches for PnP and camera redirection.
///
/// # Safety
/// `hmod` must be a valid handle to the loaded umrdp.dll; all other threads suspended.
#[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64"))]
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

    #[cfg(target_arch = "aarch64")]
    // SAFETY: `pe` wraps a loaded umrdp.dll; caller suspended other threads.
    unsafe {
        arm64_apply::apply(&pe, pnp_rva, camera_rva, legacy);
    }
}

/// Unsupported CPU architecture fallback.
///
/// Other Windows architectures may load and forward umrdp.dll exports, but
/// PnP/camera redirection patching is disabled unless an architecture-specific
/// patcher exists.
///
/// # Safety
/// `hmod` must be a valid handle to the loaded umrdp.dll.
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
pub unsafe fn apply_patches(_hmod: HMODULE) {
    debug_log(
        "UmWrap: CPU architecture is not supported for runtime patching; \
         forwarding original umrdp.dll without modifications\n",
    );
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
        // In-memory extent of the loaded umrdp.dll image. A RUNTIME_FUNCTION's
        // begin/length comes from the exception table and is normally inside
        // `.text`, but a malformed entry can report end < begin or a length
        // that runs off the mapping; the read below is clamped to this span so
        // an unbounded read cannot fault and crash the svchost (SEC-CU-01).
        let (img_lo, img_hi) = pe.image_extent();

        for func in func_table.iter() {
            let begin = func.begin_address as usize;
            // `saturating_sub`: a malformed exception entry could report
            // end < begin; clamp to 0 rather than wrapping (debug panic /
            // release OOB length).
            let length = func.end_address.saturating_sub(func.begin_address) as usize;
            let func_start = adjusted + begin;
            // Clamp the read window to the bytes mapped after `func_start` so a
            // function near the end of the image (or a malformed length) cannot
            // read past the mapping.
            let length = super::clamp_read_len(func_start, length, img_lo, img_hi);
            // SAFETY: `func_start` is `adjusted_base + begin` for an exception
            // table entry, and `length` is clamped to the bytes mapped after it
            // within `[img_lo, img_hi)`, so the read stays inside the image.
            let code = unsafe { std::slice::from_raw_parts(func_start as *const u8, length) };
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
                        let bt = pe.resolve_chained_unwind_in_image(func);
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
                                // Legacy x64 (umrdp.dll importing slc.dll): the
                                // CALL is followed by a 2-byte register-form TEST.
                                if search_decoder.can_decode() {
                                    search_decoder.decode_out(&mut search_inst);
                                    if search_inst.mnemonic() == Mnemonic::Test
                                        && search_inst.len() == 2
                                    {
                                        // The previous implementation overwrote
                                        // CALL+TEST with a hardcoded
                                        // `or dword ptr [rsp+0x40], 1; xor eax,eax`.
                                        // That `0x40` is a build-dependent stack
                                        // slot displacement: it is the offset of a
                                        // local the legacy gate reads later, and it
                                        // shifts between Windows builds. It is *not*
                                        // recoverable from the matched 2-byte
                                        // register TEST (which carries no
                                        // displacement), so writing a fixed `0x40`
                                        // is a guess that corrupts an unrelated
                                        // stack slot on any build whose layout
                                        // differs. Mirroring the x86 legacy posture
                                        // (and WORK_STATUS known limitations), we
                                        // refuse to invent a displacement and leave
                                        // the original behaviour in place.
                                        debug_log(
                                            "UmWrap: x64 legacy (slc.dll) PnP patch \
                                             needs a build-specific stack slot that \
                                             cannot be recovered dynamically; \
                                             skipping\n",
                                        );
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
        let (img_lo, img_hi) = pe.image_extent();
        let begin = func.begin_address as usize;
        // `saturating_sub`: a malformed exception entry could report end < begin.
        let length = func.end_address.saturating_sub(func.begin_address) as usize;
        let func_start = adjusted + begin;
        // Clamp the read window to the bytes mapped after `func_start`.
        let length = super::clamp_read_len(func_start, length, img_lo, img_hi);
        // SAFETY: `func_start` is `adjusted_base + begin` for an exception table
        // entry, and `length` is clamped to the bytes mapped after it within
        // `[img_lo, img_hi)`, so the read stays inside the loaded image.
        let code = unsafe { std::slice::from_raw_parts(func_start as *const u8, length) };
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

                // Bytes left in the (already image-clamped) function body after
                // the current instruction, matching the sibling PnP path so the
                // read below cannot run past the mapping when the LEA sits near
                // the end of the function/image (SEC-CU-01).
                let remaining_len =
                    length.saturating_sub((decoder.ip() as usize) - (adjusted + begin));
                // SAFETY: `decoder.ip()` points into the same function body, and
                // the read length is clamped to `remaining_len` (bytes mapped
                // after it within `[img_lo, img_hi)`), so the read stays inside
                // the loaded image.
                let search_code = unsafe {
                    std::slice::from_raw_parts(
                        decoder.ip() as usize as *const u8,
                        16.min(remaining_len),
                    )
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

// =====================================================================
// ARM64 path — .pdata function scan + ADRP/ADD string reference -> BL patch
// =====================================================================
#[cfg(target_arch = "aarch64")]
mod arm64_apply {
    use patcher::arm64;
    use patcher::patch::{bytecodes, write_patch};
    use patcher::pe::LoadedPe;

    use super::debug_log;

    const CALL_SEARCH_WINDOW: usize = 96;

    /// Apply umrdp.dll PnP/camera patches on ARM64.
    ///
    /// # Safety
    /// `pe` wraps a currently-loaded umrdp.dll; threads are suspended.
    pub(super) unsafe fn apply(
        pe: &LoadedPe,
        pnp_rva: usize,
        camera_rva: Option<usize>,
        legacy: bool,
    ) {
        if legacy {
            debug_log("UmWrap: ARM64 legacy slc.dll import detected; using generic BL patch\n");
        }

        patch_call_after_policy_string(pe, pnp_rva, "PnP");

        if let Some(camera_rva) = camera_rva {
            patch_call_after_policy_string(pe, camera_rva, "Camera");
        }
    }

    fn patch_call_after_policy_string(pe: &LoadedPe, policy_rva: usize, label: &str) {
        let site = match arm64::find_bl_after_reference_rva(pe, policy_rva, CALL_SEARCH_WINDOW) {
            Some(site) => site,
            None => {
                debug_log(&format!("UmWrap: ARM64 {label} patch site not found\n"));
                return;
            }
        };

        let call_addr = pe.adjusted_base + site.call_rva as usize;
        // SAFETY: call_addr is a BL instruction inside loaded PE .text; threads
        // are suspended by the caller.
        match unsafe { write_patch(call_addr, bytecodes::ARM64_MOV_W0_1) } {
            Ok(_) => debug_log(&format!("UmWrap: ARM64 {label} patch applied\n")),
            Err(e) => debug_log(&format!("UmWrap: ARM64 {label} patch write failed: {e}\n")),
        }
    }
}
