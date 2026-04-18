use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use patcher::patch::{debug_log, write_patch};
use patcher::pe::LoadedPe;

/// Apply CSLQuery::Initialize SL policy variable patching.
///
/// Scans CSLQuery::Initialize and sets the following static variables to 1:
/// - bRemoteConnAllowed (after AllowRemoteConnections query)
/// - bFUSEnabled (after AllowMultipleSessions query)
/// - bAppServerAllowed (after AllowAppServerMode query)
/// - bMultimonAllowed (after AllowMultimon query)
/// - bInitialized
///
/// The logic walks through the function looking for MOV [mem], reg patterns
/// that store query results. When a SL policy string reference is found,
/// the next store is marked as a "query result" and overwritten with 1.
///
/// # Safety
/// All threads must be suspended
#[cfg(target_arch = "x86_64")]
pub unsafe fn apply(
    pe: &LoadedPe,
    cslquery_init_rva: usize,
    cslquery_init_len: usize,
    allow_remote_rva: Option<usize>,
    allow_multiple_rva: Option<usize>,
    allow_appserver_rva: Option<usize>,
    allow_multimon_rva: Option<usize>,
) {
    let base = pe.adjusted_base;
    let ip_start = base + cslquery_init_rva;
    let length = cslquery_init_len;

    let policy_rvas: Vec<usize> = [
        allow_remote_rva,
        allow_multiple_rva,
        allow_appserver_rva,
        allow_multimon_rva,
    ]
    .iter()
    .filter_map(|r| *r)
    .collect();

    let code = unsafe { std::slice::from_raw_parts(ip_start as *const u8, length) };

    let mut b_initialized_addr: Option<usize> = None;
    let mut found = false;

    if length > 0x100 {
        // Normal-length function path
        let mut decoder = Decoder::with_ip(64, code, ip_start as u64, DecoderOptions::NONE);
        let mut inst = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut inst);

            // MOV [rip+disp], eax — store query result
            if !found
                && inst.mnemonic() == Mnemonic::Mov
                && inst.op0_kind() == OpKind::Memory
                && inst.memory_base() == Register::RIP
                && inst.memory_displ_size() != 0
                && inst.op1_kind() == OpKind::Register
                && inst.op1_register() == Register::EAX
            {
                found = true;
                // Write 1 directly to the resolved address
                let target_addr = inst.memory_displacement64() as usize;
                let one: u32 = 1;
                if let Err(e) = unsafe { write_patch(target_addr, &one.to_le_bytes()) } {
                    debug_log(&format!(
                        "SLPolicy: write_patch failed at {target_addr:#x}: {e}"
                    ));
                }
            }
            // LEA rcx, [rip+disp] — loading a policy string
            else if inst.mnemonic() == Mnemonic::Lea
                && inst.op1_kind() == OpKind::Memory
                && inst.memory_base() == Register::RIP
                && inst.memory_displ_size() != 0
                && inst.op0_kind() == OpKind::Register
                && inst.op0_register() == Register::RCX
            {
                let target = inst.memory_displacement64() as usize - base;
                if policy_rvas.contains(&target) {
                    found = false; // Reset: next store will be the query result
                }
            }
            // MOV [rip+disp], imm(1) — bInitialized
            else if inst.mnemonic() == Mnemonic::Mov
                && inst.op0_kind() == OpKind::Memory
                && inst.memory_base() == Register::RIP
                && inst.memory_displ_size() != 0
                && inst.op1_kind() == OpKind::Immediate32
                && inst.immediate32() == 1
            {
                b_initialized_addr = Some(inst.memory_displacement64() as usize);
                break;
            }
        }
    } else {
        // Short function — different scanning pattern (inlined)
        // Use 0x11000 as scan range (not clamped to stub length) since the real
        // function body is at the JMP target, well within the loaded DLL image.
        let scan_len = 0x11000usize;
        let scan_code = unsafe { std::slice::from_raw_parts(ip_start as *const u8, scan_len) };
        let mut decoder = Decoder::with_ip(64, scan_code, ip_start as u64, DecoderOptions::NONE);
        let mut inst = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut inst);

            // Follow JMP
            if inst.mnemonic() == Mnemonic::Jmp && patcher::disasm::is_near_branch(&inst) {
                let target = inst.near_branch_target() as usize;
                let remaining_code =
                    unsafe { std::slice::from_raw_parts(target as *const u8, scan_len) };
                decoder = Decoder::with_ip(64, remaining_code, target as u64, DecoderOptions::NONE);
                continue;
            }

            // MOV [rip+disp], reg — store result
            if !found
                && inst.mnemonic() == Mnemonic::Mov
                && inst.op0_kind() == OpKind::Memory
                && inst.memory_base() == Register::RIP
                && inst.memory_displ_size() != 0
                && inst.op1_kind() == OpKind::Register
            {
                found = true;
                let target_addr = inst.memory_displacement64() as usize;
                let one: u32 = 1;
                if let Err(e) = unsafe { write_patch(target_addr, &one.to_le_bytes()) } {
                    debug_log(&format!(
                        "SLPolicy: write_patch failed at {target_addr:#x}: {e}"
                    ));
                }
            }
            // LEA rdx, [rip+disp] — policy string (note: RDX in short path)
            else if inst.mnemonic() == Mnemonic::Lea
                && inst.op1_kind() == OpKind::Memory
                && inst.memory_base() == Register::RIP
                && inst.memory_displ_size() != 0
                && inst.op0_kind() == OpKind::Register
                && inst.op0_register() == Register::RDX
            {
                let target = inst.memory_displacement64() as usize - base;
                if policy_rvas.contains(&target) {
                    found = false;
                }
            }
            // MOV [rip+disp], eax/ecx — bInitialized candidate
            else if inst.mnemonic() == Mnemonic::Mov
                && inst.op0_kind() == OpKind::Memory
                && inst.memory_base() == Register::RIP
                && inst.memory_displ_size() != 0
                && inst.op1_kind() == OpKind::Register
                && (inst.op1_register() == Register::EAX || inst.op1_register() == Register::ECX)
            {
                b_initialized_addr = Some(inst.memory_displacement64() as usize);
            }
            // RET — end
            else if inst.mnemonic() == Mnemonic::Ret {
                break;
            }
        }
    }

    // Set bInitialized = 1
    if let Some(addr) = b_initialized_addr {
        let one: u32 = 1;
        if let Err(e) = unsafe { write_patch(addr, &one.to_le_bytes()) } {
            debug_log(&format!(
                "SLPolicy: write bInitialized failed at {addr:#x}: {e}"
            ));
        }
    } else {
        debug_log("bInitialized not found\n");
    }
}

/// x86 version of CSLQuery::Initialize SL policy patching
#[cfg(target_arch = "x86")]
pub unsafe fn apply(
    pe: &LoadedPe,
    cslquery_init_rva: usize,
    cslquery_init_len: usize,
    allow_remote_rva: Option<usize>,
    allow_multiple_rva: Option<usize>,
    allow_appserver_rva: Option<usize>,
    allow_multimon_rva: Option<usize>,
) {
    let base = pe.adjusted_base;
    let ip_start = base + cslquery_init_rva;
    let length = cslquery_init_len;

    let policy_rvas: Vec<usize> = [
        allow_remote_rva,
        allow_multiple_rva,
        allow_appserver_rva,
        allow_multimon_rva,
    ]
    .iter()
    .filter_map(|r| *r)
    .collect();

    let code = unsafe { std::slice::from_raw_parts(ip_start as *const u8, length) };
    let mut decoder = Decoder::with_ip(32, code, ip_start as u64, DecoderOptions::NONE);
    let mut inst = Instruction::default();

    let mut found = false;
    let mut b_initialized_addr: Option<usize> = None;

    while decoder.can_decode() {
        decoder.decode_out(&mut inst);

        // MOV [ds:disp], reg (eax/edi/esi) — store query result
        if !found
            && inst.mnemonic() == Mnemonic::Mov
            && inst.op0_kind() == OpKind::Memory
            && inst.memory_segment() == Register::DS
            && inst.memory_base() == Register::None
            && inst.memory_displ_size() != 0
            && inst.op1_kind() == OpKind::Register
            && (inst.op1_register() == Register::EAX
                || inst.op1_register() == Register::EDI
                || inst.op1_register() == Register::ESI)
        {
            found = true;
            let target_addr = inst.memory_displacement64() as usize;
            let one: u32 = 1;
            if let Err(e) = unsafe { write_patch(target_addr, &one.to_le_bytes()) } {
                debug_log(&format!(
                    "SLPolicy x86: write_patch failed at {target_addr:#x}: {e}"
                ));
            }
        }
        // MOV [ds:disp], 1 — bInitialized
        else if inst.mnemonic() == Mnemonic::Mov
            && inst.op0_kind() == OpKind::Memory
            && inst.memory_segment() == Register::DS
            && inst.memory_base() == Register::None
            && inst.memory_displ_size() != 0
            && inst.op1_kind() == OpKind::Immediate32
            && inst.immediate32() == 1
        {
            b_initialized_addr = Some(inst.memory_displacement64() as usize);
            break;
        }
        // PUSH imm32 / MOV reg, imm32 — check for policy string reference
        else if inst.len() == 5 {
            let is_push_imm32 =
                inst.mnemonic() == Mnemonic::Push && inst.op0_kind() == OpKind::Immediate32;
            let is_mov_reg_imm32 = inst.mnemonic() == Mnemonic::Mov
                && inst.op0_kind() == OpKind::Register
                && inst.op1_kind() == OpKind::Immediate32;
            let target_val = if is_push_imm32 || is_mov_reg_imm32 {
                Some((inst.immediate32() as usize).wrapping_sub(base))
            } else {
                None
            };

            if let Some(tv) = target_val {
                if policy_rvas.contains(&tv) {
                    found = false;
                }
            }
        }
    }

    if let Some(addr) = b_initialized_addr {
        let one: u32 = 1;
        if let Err(e) = unsafe { write_patch(addr, &one.to_le_bytes()) } {
            debug_log(&format!(
                "SLPolicy x86: write bInitialized failed at {addr:#x}: {e}"
            ));
        }
    } else {
        debug_log("bInitialized not found\n");
    }
}
