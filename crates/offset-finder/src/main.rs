use anyhow::{bail, Context, Result};
use std::env;
use std::path::PathBuf;

mod xref_x86;

const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
const IMAGE_FILE_MACHINE_ARM64EC: u16 = 0xa641;
const IMAGE_FILE_MACHINE_ARM64X: u16 = 0xa64e;

#[derive(Default)]
struct Args {
    dll_path: Option<String>,
    assert_all: bool,
    dry_run: bool,
}

fn parse_args() -> Result<Args> {
    let mut out = Args::default();
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--assert-all" | "-a" => out.assert_all = true,
            "--dry-run" | "-d" => out.dry_run = true,
            "--help" | "-h" => {
                println!(
                    "offset-finder — scan termsrv.dll for rdprrap patch targets\n\
                     \n\
                     USAGE:\n    offset-finder [--assert-all] [--dry-run] [<path-to-termsrv.dll>]\n\
                     \n\
                     FLAGS:\n\
                     \t-a, --assert-all   Exit non-zero if any required pattern is missing\n\
                     \t-d, --dry-run      For each patch, report the site found and the bytes\n\
                     \t                   that would be written (or NOT FOUND). Implied by\n\
                     \t                   --assert-all.\n\
                     \t-h, --help         Print this message\n\
                     \n\
                     When <path> is omitted on Windows, %SystemRoot%\\System32\\termsrv.dll is used."
                );
                std::process::exit(0);
            }
            s if !s.starts_with('-') && out.dll_path.is_none() => out.dll_path = Some(arg),
            _ => bail!("Unknown or duplicate argument: {arg}"),
        }
    }
    // --assert-all checks the patch sites too, so it implies the dry-run.
    if out.assert_all {
        out.dry_run = true;
    }
    Ok(out)
}

fn main() -> Result<()> {
    let args = parse_args()?;

    let dll_path = match args.dll_path {
        Some(p) => PathBuf::from(p),
        None => {
            #[cfg(windows)]
            {
                let mut sys_dir = vec![0u8; 260];
                let len = unsafe {
                    windows::Win32::System::SystemInformation::GetSystemDirectoryA(Some(
                        &mut sys_dir,
                    ))
                };
                let path = String::from_utf8_lossy(&sys_dir[..len as usize]).to_string();
                PathBuf::from(path).join("termsrv.dll")
            }
            #[cfg(not(windows))]
            {
                bail!("Usage: offset-finder [--assert-all] <path-to-termsrv.dll>");
            }
        }
    };

    if !dll_path.exists() {
        bail!("File not found: {}", dll_path.display());
    }

    eprintln!("Loading: {}", dll_path.display());
    find_offsets_file(&dll_path, args.assert_all, args.dry_run)
}

/// Load termsrv.dll as a file and parse PE to find offsets
fn find_offsets_file(path: &std::path::Path, assert_all: bool, dry_run: bool) -> Result<()> {
    use pelite::pe32::Pe as Pe32;
    use pelite::pe64::Pe as Pe64;

    let data = std::fs::read(path).context("Failed to read file")?;
    eprintln!("File size: {} bytes", data.len());

    // Try PE64 first, then PE32
    if let Ok(pe64) = pelite::pe64::PeFile::from_bytes(&data) {
        let machine = pe64.file_header().Machine;
        match machine {
            IMAGE_FILE_MACHINE_AMD64 => {
                eprintln!("Architecture: x64");
                find_offsets_pe64(&pe64, assert_all, dry_run)
            }
            IMAGE_FILE_MACHINE_ARM64 | IMAGE_FILE_MACHINE_ARM64EC | IMAGE_FILE_MACHINE_ARM64X => {
                if machine == IMAGE_FILE_MACHINE_ARM64 {
                    eprintln!("Architecture: ARM64");
                    find_offsets_pe64_arm64(&pe64, assert_all)
                } else {
                    report_unsupported_arch(machine)
                }
            }
            other => bail!(
                "Unsupported PE32+ machine type: 0x{other:04X} ({})",
                machine_name(other)
            ),
        }
    } else if let Ok(pe32) = pelite::pe32::PeFile::from_bytes(&data) {
        let machine = pe32.file_header().Machine;
        match machine {
            IMAGE_FILE_MACHINE_I386 => {
                eprintln!("Architecture: x86");
                find_offsets_pe32(&pe32, assert_all)
            }
            other => bail!(
                "Unsupported PE32 machine type: 0x{other:04X} ({})",
                machine_name(other)
            ),
        }
    } else {
        bail!("Failed to parse PE file");
    }
}

fn report_unsupported_arch(machine: u16) -> Result<()> {
    println!("[Offset Report]");
    println!("Arch={}", machine_name(machine));
    println!("Machine=0x{machine:04X}");
    println!("Status=UNSUPPORTED");
    println!();
    bail!(
        "{} offset discovery is not implemented. Pure ARM64 images are supported; \
         ARM64EC/ARM64X hybrid images need separate validation.",
        machine_name(machine)
    )
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        IMAGE_FILE_MACHINE_I386 => "x86",
        IMAGE_FILE_MACHINE_AMD64 => "x64",
        IMAGE_FILE_MACHINE_ARM64 => "arm64",
        IMAGE_FILE_MACHINE_ARM64EC => "arm64ec",
        IMAGE_FILE_MACHINE_ARM64X => "arm64x",
        _ => "unknown",
    }
}

fn find_offsets_pe64(pe: &pelite::pe64::PeFile<'_>, assert_all: bool, dry_run: bool) -> Result<()> {
    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
    use patcher::pe::{resolve_chained_unwind, RuntimeFunction};
    use pelite::pe64::Pe;

    let image_base = pe.optional_header().ImageBase;

    let rdata = pe
        .section_headers()
        .iter()
        .find(|s| s.name().ok() == Some(".rdata"))
        .or_else(|| {
            pe.section_headers()
                .iter()
                .find(|s| s.name().ok() == Some(".text"))
        })
        .context(".rdata not found")?;

    let rdata_data = pe
        .get_section_bytes(rdata)
        .context("Failed to read .rdata")?;
    let rdata_va = rdata.VirtualAddress;

    let text = pe
        .section_headers()
        .iter()
        .find(|s| s.name().ok() == Some(".text"))
        .context(".text not found")?;
    let text_data = pe.get_section_bytes(text).context("Failed to read .text")?;
    let text_va = text.VirtualAddress;

    let patterns: &[(&str, &[u8])] = &[
        ("CDefPolicy_Query", b"CDefPolicy::Query"),
        (
            "GetInstanceOfTSLicense",
            b"CEnforcementCore::GetInstanceOfTSLicense ",
        ),
        (
            "IsSingleSessionPerUserEnabled",
            b"CSessionArbitrationHelper::IsSingleSessionPerUserEnabled",
        ),
        (
            "IsTerminalTypeLocalOnly",
            b"CSLQuery::IsTerminalTypeLocalOnly",
        ),
        (
            "IsAllowNonRDPStack",
            b"CRemoteConnectionManager::IsAllowNonRDPStack\0",
        ),
        ("IsAppServerInstalled", b"CSLQuery::IsAppServerInstalled\0"),
        (
            "GetConnectionProperty",
            b"CConnectionEx::GetConnectionProperty\0",
        ),
    ];

    println!("[Offset Report]");
    println!("ImageBase=0x{image_base:X}");
    println!("Arch=x64");
    println!();

    // Find string RVAs + track which ones were found for --assert-all.
    let mut str_rvas: Vec<(&str, Option<usize>)> = Vec::with_capacity(patterns.len());
    for (name, pattern) in patterns {
        let rva = find_in_section(rdata_data, rdata_va, pattern);
        match rva {
            Some(r) => println!("{name}_str=0x{r:X}"),
            None => println!("{name}_str=NOT_FOUND"),
        }
        str_rvas.push((name, rva));
    }

    // Find function addresses via exception table xref.
    let mut func_found: std::collections::HashSet<&str> = std::collections::HashSet::new();
    // Records the owning function range (begin RVA, end RVA) for each resolved
    // name so the patch-site dry-run can re-slice and analyze the body afterward.
    let mut func_ranges: std::collections::HashMap<&str, (usize, usize)> =
        std::collections::HashMap::new();
    if let Ok(exception_dir) = pe.exception() {
        println!();
        for entry in exception_dir.functions() {
            let image = entry.image();
            let begin = image.BeginAddress as usize;
            let end = image.EndAddress as usize;

            if begin < text_va as usize || end <= begin {
                continue;
            }
            let func_offset = begin - text_va as usize;
            let func_len = end - begin;
            if func_offset + func_len > text_data.len() {
                continue;
            }

            let code = &text_data[func_offset..func_offset + func_len];
            let mut decoder =
                Decoder::with_ip(64, code, image_base + begin as u64, DecoderOptions::NONE);
            let mut inst = Instruction::default();

            while decoder.can_decode() {
                decoder.decode_out(&mut inst);
                if inst.mnemonic() == Mnemonic::Lea
                    && inst.op1_kind() == OpKind::Memory
                    && inst.memory_base() == Register::RIP
                    && inst.op0_kind() == OpKind::Register
                {
                    let target = inst.memory_displacement64() - image_base;

                    for (name, str_rva_opt) in &str_rvas {
                        if let Some(str_rva) = str_rva_opt {
                            if target == *str_rva as u64 {
                                // The string xref lands in whatever RUNTIME_FUNCTION
                                // contains the LEA. With PGO hot/cold splitting that
                                // may be a COLD outlined fragment (e.g. the deny path
                                // of CDefPolicy::Query on Server 2022 20348.587) whose
                                // UNWIND_INFO chains back to the HOT function holding
                                // the actual gate. Resolve through the chain so we
                                // report — and later slice/analyze — the hot body.
                                // No-op when the entry is not chained (deny path
                                // inlined into the hot function, as on 26100/26200).
                                let cold = RuntimeFunction {
                                    begin_address: image.BeginAddress,
                                    end_address: image.EndAddress,
                                    unwind_data: image.UnwindData,
                                };
                                // SEC-CU-03: self-validate the resolved primary
                                // against the `.text` RVA window so a bogus/
                                // malformed chain hands back the original cold
                                // entry instead of a garbage hot address.
                                let text_window =
                                    (text_va, text_va.saturating_add(text_data.len() as u32));
                                let primary = resolve_chained_unwind(
                                    cold,
                                    |rva| pe.slice_bytes(rva).ok().and_then(|s| s.first().copied()),
                                    Some(text_window),
                                );
                                let (hot_begin, hot_end) =
                                    (primary.begin_address as usize, primary.end_address as usize);
                                // SEC-DISC-003: re-apply the pre-chain validity
                                // guard (begin in .text / end > begin / fits in
                                // section bytes) to the POST-chain primary before
                                // recording it. The cold entry already passed at
                                // the table loop above, but the chained primary is
                                // a fresh address that must clear the same bar.
                                let hot_in_text = hot_begin >= text_va as usize
                                    && hot_end > hot_begin
                                    && hot_end - text_va as usize <= text_data.len();
                                if !hot_in_text {
                                    continue;
                                }
                                println!(
                                    "{name}_func=0x{hot_begin:X} (xref at 0x{:X})",
                                    inst.ip() - image_base
                                );
                                func_found.insert(name);
                                func_ranges.entry(name).or_insert((hot_begin, hot_end));
                            }
                        }
                    }
                }
            }
        }
    }

    // --- Patch-site dry-run -------------------------------------------------
    // For each patch, slice the resolved function body out of .text and run the
    // pure patcher analyzer, reporting the site found and the bytes that would
    // be written (or NOT FOUND). This is purely informational and never changes
    // the offset report above; --assert-all incorporates it (see below).
    let mut dry_run_failed: Vec<&str> = Vec::new();
    if dry_run {
        println!();
        println!("[Patch Dry-Run]");

        // def_policy: analyze CDefPolicy::Query for the compare/store site.
        match func_ranges.get("CDefPolicy_Query") {
            Some(&(begin, end)) => {
                // SEC-DISC-003: `saturating_sub` throughout so a malformed input
                // DLL (begin < text_va, end < begin, or func_off past the
                // section) can never underflow-panic this diagnostic path.
                let func_off = begin.saturating_sub(text_va as usize);
                // Bound the analyzer window to SCAN_LEN, but never past the
                // resolved function end or the section data.
                let avail = end
                    .saturating_sub(begin)
                    .min(patcher::analyze::def_policy::SCAN_LEN)
                    .min(text_data.len().saturating_sub(func_off));
                let code = &text_data[func_off..func_off + avail];
                match patcher::analyze::def_policy::analyze_defpolicy(
                    code,
                    image_base + begin as u64,
                ) {
                    Some(p) => {
                        let bytes_hex = hex_join(&p.bytes);
                        println!(
                            "def_policy: base={:?} value={:?} write_disp=0x{:X} is_jnz={} \
                             patch_rva=0x{:X} bytes=[{}]",
                            p.base_reg,
                            p.value_reg,
                            p.write_disp,
                            p.is_jnz,
                            p.patch_addr - image_base,
                            bytes_hex,
                        );
                    }
                    None => {
                        println!("def_policy: NOT FOUND");
                        dry_run_failed.push("def_policy");
                    }
                }
            }
            None => {
                println!("def_policy: NOT FOUND (CDefPolicy::Query function unresolved)");
                dry_run_failed.push("def_policy");
            }
        }

        // property_device: the patch site is reached by a runtime GUID-walk
        // (GetConnectionProperty -> IS_PNP_DISABLED xref -> CALL into the inner
        // function), which resolves RIP-relative targets against the live image
        // and hops across functions. That walk lives in the wrapper crate and
        // reads process memory; porting it to file bytes would be a large,
        // fragile addition for little dry-run value, so it is honestly skipped
        // here. The pure `patcher::analyze::property_device` core is still
        // available for callers that already hold the inner function bytes.
        println!("property_device dry-run: needs runtime walk — skipped");
    }

    if assert_all {
        let missing_strings: Vec<&str> = str_rvas
            .iter()
            .filter_map(|(n, rva)| rva.is_none().then_some(*n))
            .collect();
        let missing_funcs: Vec<&str> = str_rvas
            .iter()
            .filter_map(|(n, rva)| (rva.is_some() && !func_found.contains(n)).then_some(*n))
            .collect();

        println!();
        println!(
            "[Assert] strings: {}/{} found, functions: {}/{} resolved",
            patterns.len() - missing_strings.len(),
            patterns.len(),
            func_found.len(),
            patterns.len()
        );

        if !missing_strings.is_empty() || !missing_funcs.is_empty() || !dry_run_failed.is_empty() {
            if !missing_strings.is_empty() {
                eprintln!("[Assert] MISSING strings: {missing_strings:?}");
            }
            if !missing_funcs.is_empty() {
                eprintln!("[Assert] MISSING function xrefs: {missing_funcs:?}");
            }
            if !dry_run_failed.is_empty() {
                eprintln!("[Assert] MISSING patch sites: {dry_run_failed:?}");
            }
            bail!("--assert-all: required patterns not all resolved");
        }
    }

    Ok(())
}

/// Format bytes as space-separated two-digit uppercase hex (e.g. "B8 00 01").
fn hex_join(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn find_offsets_pe64_arm64(pe: &pelite::pe64::PeFile<'_>, assert_all: bool) -> Result<()> {
    use patcher::arm64;
    use pelite::pe64::Pe;

    let image_base = pe.optional_header().ImageBase;

    let rdata = pe
        .section_headers()
        .iter()
        .find(|s| s.name().ok() == Some(".rdata"))
        .or_else(|| {
            pe.section_headers()
                .iter()
                .find(|s| s.name().ok() == Some(".text"))
        })
        .context(".rdata not found")?;
    let rdata_data = pe
        .get_section_bytes(rdata)
        .context("Failed to read .rdata")?;
    let rdata_va = rdata.VirtualAddress;

    let text = pe
        .section_headers()
        .iter()
        .find(|s| s.name().ok() == Some(".text"))
        .context(".text not found")?;
    let text_data = pe.get_section_bytes(text).context("Failed to read .text")?;
    let text_va = text.VirtualAddress;

    let pdata = pe
        .section_headers()
        .iter()
        .find(|s| s.name().ok() == Some(".pdata"))
        .context(".pdata not found")?;
    let pdata_data = pe
        .get_section_bytes(pdata)
        .context("Failed to read .pdata")?;

    let patterns: &[(&str, &[u8])] = &[
        ("CDefPolicy_Query", b"CDefPolicy::Query"),
        (
            "IsSingleSessionPerUserEnabled",
            b"CSessionArbitrationHelper::IsSingleSessionPerUserEnabled",
        ),
        (
            "IsTerminalTypeLocalOnly",
            b"CSLQuery::IsTerminalTypeLocalOnly",
        ),
        (
            "IsAllowNonRDPStack",
            b"CRemoteConnectionManager::IsAllowNonRDPStack\0",
        ),
        ("IsAppServerInstalled", b"CSLQuery::IsAppServerInstalled\0"),
        ("IsSingleSessionPerUser", b"IsSingleSessionPerUser\0"),
        (
            "AllowRemoteConnections",
            b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0R\0e\0m\0o\0t\0e\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0M\0a\0n\0a\0g\0e\0r\0-\0A\0l\0l\0o\0w\0R\0e\0m\0o\0t\0e\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\0\0",
        ),
        (
            "AllowMultipleSessions",
            b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0R\0e\0m\0o\0t\0e\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0M\0a\0n\0a\0g\0e\0r\0-\0A\0l\0l\0o\0w\0M\0u\0l\0t\0i\0p\0l\0e\0S\0e\0s\0s\0i\0o\0n\0s\0\0\0",
        ),
        (
            "AllowAppServerMode",
            b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0R\0e\0m\0o\0t\0e\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0M\0a\0n\0a\0g\0e\0r\0-\0A\0l\0l\0o\0w\0A\0p\0p\0S\0e\0r\0v\0e\0r\0M\0o\0d\0e\0\0\0",
        ),
        (
            "AllowMultimon",
            b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0R\0e\0m\0o\0t\0e\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0M\0a\0n\0a\0g\0e\0r\0-\0A\0l\0l\0o\0w\0M\0u\0l\0t\0i\0m\0o\0n\0\0\0",
        ),
        (
            "PropertyDeviceGuid",
            &[
                0xD5, 0x59, 0xD3, 0x93, 0x1F, 0x83, 0xB4, 0x47, 0x90, 0xBE, 0x83, 0x83, 0xAF,
                0x8F, 0x1B, 0x0E,
            ],
        ),
    ];

    println!("[Offset Report]");
    println!("ImageBase=0x{image_base:X}");
    println!("Arch=arm64");
    println!();

    let mut str_rvas: Vec<(&str, Option<usize>)> = Vec::with_capacity(patterns.len());
    for (name, pattern) in patterns {
        let rva = find_in_section(rdata_data, rdata_va, pattern);
        match rva {
            Some(r) => println!("{name}_str=0x{r:X}"),
            None => println!("{name}_str=NOT_FOUND"),
        }
        str_rvas.push((name, rva));
    }

    let functions = arm64::functions_from_pdata(pdata_data, text_va, text_data.len());
    let mut func_found: std::collections::HashSet<&str> = std::collections::HashSet::new();

    println!();
    for (name, str_rva_opt) in &str_rvas {
        let Some(str_rva) = str_rva_opt else {
            continue;
        };

        let target_va = image_base + *str_rva as u64;
        let mut found = false;
        for func in &functions {
            let begin = func.begin_address as usize;
            if begin < text_va as usize {
                continue;
            }
            let offset = begin - text_va as usize;
            let len = (func.end_address - func.begin_address) as usize;
            if offset >= text_data.len() {
                continue;
            }
            let end = offset.saturating_add(len).min(text_data.len());
            if end <= offset {
                continue;
            }

            let code = &text_data[offset..end];
            let code_va = image_base + begin as u64;
            if let Some(ref_va) = arm64::code_references_addr(code, code_va, target_va) {
                println!(
                    "{name}_func=0x{begin:X} (xref at 0x{:X})",
                    ref_va - image_base
                );
                if let Some(bl_va) = arm64::find_bl_after_addr(code, code_va, ref_va, 96) {
                    println!("{name}_bl_patch=0x{:X}", bl_va - image_base);
                }
                func_found.insert(name);
                found = true;
                break;
            }
        }

        if !found {
            println!("{name}_func=NOT_FOUND");
        }
    }

    if assert_all {
        let missing_strings: Vec<&str> = str_rvas
            .iter()
            .filter_map(|(n, rva)| rva.is_none().then_some(*n))
            .collect();
        let missing_funcs: Vec<&str> = str_rvas
            .iter()
            .filter_map(|(n, rva)| (rva.is_some() && !func_found.contains(n)).then_some(*n))
            .collect();

        println!();
        println!(
            "[Assert] strings: {}/{} found, functions: {}/{} resolved",
            patterns.len() - missing_strings.len(),
            patterns.len(),
            func_found.len(),
            patterns.len()
        );

        if !missing_strings.is_empty() || !missing_funcs.is_empty() {
            if !missing_strings.is_empty() {
                eprintln!("[Assert] MISSING strings: {missing_strings:?}");
            }
            if !missing_funcs.is_empty() {
                eprintln!("[Assert] MISSING function xrefs: {missing_funcs:?}");
            }
            bail!("--assert-all: required ARM64 patterns not all resolved");
        }
    }

    Ok(())
}

fn find_offsets_pe32(pe: &pelite::pe32::PeFile<'_>, assert_all: bool) -> Result<()> {
    use pelite::pe32::Pe;

    let image_base = pe.optional_header().ImageBase;

    let rdata = pe
        .section_headers()
        .iter()
        .find(|s| s.name().ok() == Some(".rdata"))
        .or_else(|| {
            pe.section_headers()
                .iter()
                .find(|s| s.name().ok() == Some(".text"))
        })
        .context(".rdata not found")?;

    let rdata_data = pe
        .get_section_bytes(rdata)
        .context("Failed to read .rdata")?;
    let rdata_va = rdata.VirtualAddress;

    let text = pe
        .section_headers()
        .iter()
        .find(|s| s.name().ok() == Some(".text"))
        .context(".text not found")?;
    let text_data = pe.get_section_bytes(text).context("Failed to read .text")?;
    let text_va = text.VirtualAddress;

    // Strings we will resolve to function RVAs. This matches termwrap-dll's
    // `resolve_functions_x86` target set. `AllowRemoteConnections` (wide) is
    // intentionally included — its owning function (CSLQuery::Initialize) is
    // the anchor the sl_policy patch needs, and x86 has no exception table,
    // so the xref walk is the only way to locate it.
    let patterns: &[(&str, &[u8])] = &[
        ("CDefPolicy_Query", b"CDefPolicy::Query"),
        (
            "GetInstanceOfTSLicense",
            b"CEnforcementCore::GetInstanceOfTSLicense ",
        ),
        (
            "IsSingleSessionPerUserEnabled",
            b"CSessionArbitrationHelper::IsSingleSessionPerUserEnabled",
        ),
        (
            "IsTerminalTypeLocalOnly",
            b"CSLQuery::IsTerminalTypeLocalOnly",
        ),
        (
            "IsAllowNonRDPStack",
            b"CRemoteConnectionManager::IsAllowNonRDPStack\0",
        ),
        ("IsAppServerInstalled", b"CSLQuery::IsAppServerInstalled\0"),
        (
            "GetConnectionProperty",
            b"CConnectionEx::GetConnectionProperty\0",
        ),
        ("IsSingleSessionPerUser", b"IsSingleSessionPerUser\0"),
        (
            "AllowRemoteConnections",
            // UTF-16LE "TerminalServices-RemoteConnectionManager-AllowRemoteConnections\0"
            b"T\0e\0r\0m\0i\0n\0a\0l\0S\0e\0r\0v\0i\0c\0e\0s\0-\0R\0e\0m\0o\0t\0e\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0M\0a\0n\0a\0g\0e\0r\0-\0A\0l\0l\0o\0w\0R\0e\0m\0o\0t\0e\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\0\0",
        ),
    ];

    println!("[Offset Report]");
    println!("ImageBase=0x{image_base:X}");
    println!("Arch=x86");
    println!();

    // Phase 1: locate strings in .rdata.
    let mut str_rvas: Vec<(&str, Option<u32>)> = Vec::with_capacity(patterns.len());
    for (name, pattern) in patterns {
        let rva = find_in_section(rdata_data, rdata_va, pattern).map(|r| r as u32);
        match rva {
            Some(r) => println!("{name}_str=0x{r:X}"),
            None => println!("{name}_str=NOT_FOUND"),
        }
        str_rvas.push((name, rva));
    }

    // Phase 2: build absolute-VA targets and walk .text prologues to find the
    // owning function for each string.
    let targets: Vec<(&str, u32)> = str_rvas
        .iter()
        .filter_map(|(n, rva)| rva.map(|r| (*n, image_base.wrapping_add(r))))
        .collect();

    let func_rvas = xref_x86::find_xref_functions(text_data, text_va, &targets);

    println!();
    for (name, _) in patterns {
        match func_rvas.get(*name) {
            Some(rva) => println!("{name}_func=0x{rva:X}"),
            None => {
                // Only report missing functions for strings that WERE found —
                // a missing string is already reported above.
                if str_rvas.iter().any(|(n, rva)| n == name && rva.is_some()) {
                    println!("{name}_func=NOT_FOUND");
                }
            }
        }
    }

    if assert_all {
        let missing_strings: Vec<&str> = str_rvas
            .iter()
            .filter_map(|(n, rva)| rva.is_none().then_some(*n))
            .collect();
        let missing_funcs: Vec<&str> = str_rvas
            .iter()
            .filter_map(|(n, rva)| (rva.is_some() && !func_rvas.contains_key(n)).then_some(*n))
            .collect();

        println!();
        println!(
            "[Assert] strings: {}/{} found, functions: {}/{} resolved",
            patterns.len() - missing_strings.len(),
            patterns.len(),
            func_rvas.len(),
            patterns.len()
        );

        if !missing_strings.is_empty() || !missing_funcs.is_empty() {
            if !missing_strings.is_empty() {
                eprintln!("[Assert] MISSING strings: {missing_strings:?}");
            }
            if !missing_funcs.is_empty() {
                eprintln!("[Assert] MISSING function xrefs: {missing_funcs:?}");
            }
            bail!("--assert-all: required patterns not all resolved");
        }
    }

    Ok(())
}

/// Find pattern in section data at 4-byte aligned offsets
fn find_in_section(data: &[u8], section_va: u32, pattern: &[u8]) -> Option<usize> {
    if pattern.len() > data.len() {
        return None;
    }
    for offset in (0..=data.len().saturating_sub(pattern.len())).step_by(4) {
        if &data[offset..offset + pattern.len()] == pattern {
            return Some(section_va as usize + offset);
        }
    }
    None
}
