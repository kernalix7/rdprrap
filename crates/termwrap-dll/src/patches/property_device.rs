use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use patcher::analyze::property_device::{analyze_property_device, ALT_TARGET_SCAN_LEN, SCAN_LEN};
// `Register` is only referenced by the x64 branch of `find_property_device_addr`
// (RIP/DS-relative resolution); the x86 branch matches an absolute immediate.
#[cfg(target_arch = "x86_64")]
use iced_x86::Register;
use patcher::patch::{debug_log, write_patch};
use patcher::pe::LoadedPe;

use super::util::read_image_bytes;

/// GUID for IS_PNP_DISABLED: {93D359D5-831F-47B4-90BE-8383AF8F1B0E}
pub const IS_PNP_DISABLED: [u8; 16] = [
    0xD5, 0x59, 0xD3, 0x93, 0x1F, 0x83, 0xB4, 0x47, 0x90, 0xBE, 0x83, 0x83, 0xAF, 0x8F, 0x1B, 0x0E,
];

/// Find the address of the inner function called from GetConnectionProperty
/// that references the IS_PNP_DISABLED GUID.
///
/// # Safety
/// PE must be valid and loaded
pub unsafe fn find_property_device_addr(
    pe: &LoadedPe,
    func_rva: usize,
    pnp_disabled_rva: usize,
) -> Option<usize> {
    let base = pe.adjusted_base;
    let ip_start = base + func_rva;
    let target_abs = (base + pnp_disabled_rva) as u64;

    // In-memory extent of the loaded image, as absolute addresses. Every raw
    // read below (the 256-byte function start and the followed-branch targets)
    // is bounded against this span so a mis-decoded address cannot read outside
    // the mapping (SEC-UNSAFE-001 / SEC-PATCH-004 / BF-3).
    let (img_lo, img_hi) = pe.image_extent();

    // SAFETY: bounded by `read_image_bytes`, which validates `ip_start` lies in
    // `[img_lo, img_hi)` and clamps the length to the bytes mapped after it.
    let code = read_image_bytes("PropertyDevice", ip_start, 256, img_lo, img_hi)?;

    let bits = if cfg!(target_arch = "x86_64") { 64 } else { 32 };
    let mut decoder = Decoder::with_ip(bits, code, ip_start as u64, DecoderOptions::NONE);
    let mut inst = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut inst);

        #[cfg(target_arch = "x86_64")]
        {
            // Look for MOV reg, [rip+disp] pointing to IS_PNP_DISABLED
            if inst.mnemonic() == Mnemonic::Mov
                && inst.op0_kind() == OpKind::Register
                && inst.op1_kind() == OpKind::Memory
            {
                // Two resolution paths (RIP-relative vs DS-absolute) are kept
                // distinct for readability even though iced-x86 returns an
                // already-resolved address in both cases.
                #[allow(clippy::if_same_then_else)]
                let resolved = if inst.memory_base() == Register::RIP {
                    inst.memory_displacement64() // iced-x86: already resolved for RIP-relative
                } else if inst.memory_segment() == Register::DS
                    && inst.memory_base() == Register::None
                {
                    inst.memory_displacement64() // DS absolute address — already resolved
                } else {
                    continue;
                };

                if resolved == target_abs {
                    // Follow through JZ/JMP and find the CALL
                    while decoder.can_decode() {
                        decoder.decode_out(&mut inst);
                        if inst.mnemonic() == Mnemonic::Je || inst.mnemonic() == Mnemonic::Jmp {
                            // Jump to target
                            let new_ip = inst.near_branch_target() as usize;
                            // SAFETY: bounded by `read_image_bytes`, which
                            // validates `new_ip` lies within the loaded image
                            // and clamps the read length to the mapped bytes.
                            let remaining =
                                read_image_bytes("PropertyDevice", new_ip, 64, img_lo, img_hi)?;
                            let mut inner = Decoder::with_ip(
                                64,
                                remaining,
                                new_ip as u64,
                                DecoderOptions::NONE,
                            );
                            while inner.can_decode() {
                                inner.decode_out(&mut inst);
                                if inst.mnemonic() == Mnemonic::Call
                                    && patcher::disasm::is_near_branch(&inst)
                                {
                                    return Some(inst.near_branch_target() as usize - base);
                                }
                            }
                            return None;
                        }
                        if inst.mnemonic() == Mnemonic::Call
                            && patcher::disasm::is_near_branch(&inst)
                        {
                            return Some(inst.near_branch_target() as usize - base);
                        }
                    }
                    return None;
                }
            }

            // LEA rcx, [rip+disp] pointing to IS_PNP_DISABLED
            if inst.mnemonic() == Mnemonic::Lea
                && inst.op0_kind() == OpKind::Register
                && inst.op0_register() == Register::RCX
                && inst.op1_kind() == OpKind::Memory
            {
                #[allow(clippy::if_same_then_else)]
                let resolved = if inst.memory_base() == Register::RIP {
                    inst.memory_displacement64() // iced-x86: already resolved for RIP-relative
                } else if inst.memory_segment() == Register::DS
                    && inst.memory_base() == Register::None
                {
                    inst.memory_displacement64() // DS absolute address — already resolved
                } else {
                    continue;
                };

                if resolved == target_abs {
                    let mut found_jnz = false;
                    while decoder.can_decode() {
                        decoder.decode_out(&mut inst);
                        if !found_jnz && inst.mnemonic() == Mnemonic::Jne {
                            // Follow JNZ
                            let new_ip = inst.near_branch_target() as usize;
                            // SAFETY: bounded by `read_image_bytes`, which
                            // validates `new_ip` lies within the loaded image
                            // and clamps the read length to the mapped bytes.
                            let remaining =
                                read_image_bytes("PropertyDevice", new_ip, 64, img_lo, img_hi)?;
                            decoder = Decoder::with_ip(
                                64,
                                remaining,
                                new_ip as u64,
                                DecoderOptions::NONE,
                            );
                            found_jnz = true;
                        }
                        if found_jnz
                            && inst.mnemonic() == Mnemonic::Call
                            && patcher::disasm::is_near_branch(&inst)
                        {
                            return Some(inst.near_branch_target() as usize - base);
                        }
                    }
                    return None;
                }
            }
        }

        #[cfg(target_arch = "x86")]
        {
            if inst.mnemonic() == Mnemonic::Mov
                && inst.op0_kind() == OpKind::Register
                && inst.op1_kind() == OpKind::Immediate32
                && inst.immediate32() as u64 == target_abs
            {
                let mut found_jnz = false;
                while decoder.can_decode() {
                    decoder.decode_out(&mut inst);
                    if !found_jnz && inst.mnemonic() == Mnemonic::Jne {
                        let new_ip = inst.near_branch_target() as usize;
                        // SAFETY: bounded by `read_image_bytes`, which validates
                        // `new_ip` lies within the loaded image and clamps the
                        // read length to the mapped bytes.
                        let remaining =
                            read_image_bytes("PropertyDevice", new_ip, 64, img_lo, img_hi)?;
                        decoder =
                            Decoder::with_ip(32, remaining, new_ip as u64, DecoderOptions::NONE);
                        found_jnz = true;
                    }
                    if found_jnz
                        && inst.mnemonic() == Mnemonic::Call
                        && inst.op0_kind() == OpKind::NearBranch32
                    {
                        return Some(inst.near_branch_target() as usize - base);
                    }
                }
                return None;
            }
        }
    }

    None
}

/// Apply PropertyDevicePatch — patches the PnP device property check.
///
/// The patch site is found structurally by the pure `analyze_property_device`
/// core: a 32-bit struct-member load whose result is bit-extracted by
/// `SHR reg, 0x0b` + `AND reg, 1` (primary form), or whose `Jcc` target is
/// `SHR reg, 0x0c` + `AND reg, 7` (alternate form). The originating `MOV`'s
/// displacement is captured dynamically (it shifts between Windows builds), so
/// this survives struct-layout changes that broke the previous hardcoded
/// `0x1f00` / `0x1f28` scan. The forced register value is emitted via the
/// parametric `patcher::encode::mov_reg_imm32`, replacing the old per-register
/// opcode table.
///
/// # Safety
/// All threads must be suspended
pub unsafe fn apply(pe: &LoadedPe, func_rva: usize) {
    let base = pe.adjusted_base;
    let ip_start = base + func_rva;

    // In-memory extent of the loaded termsrv.dll image, as absolute addresses.
    // Both the SCAN_LEN function-start read and the alternate-form `Jcc` target
    // read are bounded against this `[img_lo, img_hi)` span; on a layout-shifted
    // or mis-decoded build a decoded address can point outside the mapping, so
    // the reads are bounded rather than trusting the decoded value
    // (BF-1 / SEC-UNSAFE-002).
    let (img_lo, img_hi) = pe.image_extent();

    // SAFETY: bounded by `read_image_bytes`, which validates `ip_start` lies in
    // `[img_lo, img_hi)` and clamps the read length to the bytes mapped after
    // it; an out-of-image function RVA degrades to "patch not found".
    let code = match read_image_bytes("PropertyPatch", ip_start, SCAN_LEN, img_lo, img_hi) {
        Some(c) => c,
        None => {
            debug_log("PropertyPatch function start outside image\n");
            return;
        }
    };

    // Primary form forces the PnP flag register to 0 (PnP not disabled). When
    // PnP redirection is explicitly disabled in the registry the primary store
    // is left intact, but the alternate UseUniversalPrinterDriverFirst form
    // (default 3, registry can raise to 4) is still applied.
    let primary_value = 0u32;
    let alt_value = read_setting("UseUniversalPrinterDriverFirst", 3);
    let patch_primary = read_setting("fDisablePNPRedir", 0) != 1;

    // Reader for the alternate-form `Jcc` target: hand the core up to
    // ALT_TARGET_SCAN_LEN bytes at the absolute jump destination. Returning
    // `None` is treated by `analyze_property_device` as "no alternate site", so
    // an out-of-image target degrades safely to "primary form only".
    let alt_reader = |target: u64| -> Option<Vec<u8>> {
        let target = target as usize;
        // Reject targets outside the loaded image: a mis-decoded branch could
        // resolve anywhere, and an unbounded read there can fault outside the
        // mapping and crash the Terminal Services svchost.
        if target < img_lo || target >= img_hi {
            return None;
        }
        // Clamp the read window to the bytes actually mapped after `target`, so a
        // target near the end of the image cannot read past the mapping.
        let avail = img_hi.saturating_sub(target);
        if avail == 0 {
            return None;
        }
        let n = avail.min(ALT_TARGET_SCAN_LEN);
        // SAFETY: `target` has been confirmed to lie within `[img_lo, img_hi)`
        // (the loaded termsrv.dll image extent from `pe.image_extent()`), and
        // `n` is clamped to `img_hi - target`, so the `n` bytes read here are
        // entirely within the mapped image.
        let bytes = unsafe { std::slice::from_raw_parts(target as *const u8, n) };
        Some(bytes.to_vec())
    };

    match analyze_property_device(
        code,
        ip_start as u64,
        primary_value,
        alt_value,
        patch_primary,
        alt_reader,
    ) {
        Some(patch) => {
            // SAFETY: `patch.patch_addr` lies within the disassembled function
            // body (primary form) or at a near-branch target inside the same
            // loaded image (alternate form); threads are suspended by the caller.
            if let Err(e) = unsafe { write_patch(patch.patch_addr as usize, &patch.bytes) } {
                debug_log(&format!("PropertyPatch write failed: {e}\n"));
            }
        }
        None => debug_log("PropertyPatch not found\n"),
    }
}

/// Read a DWORD registry setting value.
#[cfg(windows)]
pub fn read_setting(name: &str, default: u32) -> u32 {
    use std::ffi::CString;
    use windows::Win32::System::Registry::*;

    let mut val = default;
    let c_name = match CString::new(name) {
        Ok(s) => s,
        Err(_) => return default,
    };

    let keys = [
        "System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
        "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services",
    ];

    for key_path in &keys {
        let c_path = match CString::new(*key_path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut hkey = HKEY::default();
        // SAFETY: valid registry key path
        let result = unsafe {
            RegOpenKeyExA(
                HKEY_LOCAL_MACHINE,
                windows::core::PCSTR(c_path.as_ptr() as *const u8),
                0,
                KEY_READ,
                &mut hkey,
            )
        };

        if result.is_ok() {
            let mut data: u32 = 0;
            let mut cb_data: u32 = 4;
            // SAFETY: reading a DWORD from registry
            let query_result = unsafe {
                RegQueryValueExA(
                    hkey,
                    windows::core::PCSTR(c_name.as_ptr() as *const u8),
                    None,
                    None,
                    Some(&mut data as *mut u32 as *mut u8),
                    Some(&mut cb_data),
                )
            };
            if query_result.is_ok() {
                val = data;
            }
            let _ = unsafe { RegCloseKey(hkey) };
        }
    }

    val
}

#[cfg(not(windows))]
pub fn read_setting(_name: &str, default: u32) -> u32 {
    default
}
