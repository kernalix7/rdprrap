use anyhow::{bail, Context, Result};
use std::env;
use std::path::PathBuf;

#[derive(Default)]
struct Args {
    dll_path: Option<String>,
    assert_all: bool,
}

fn parse_args() -> Result<Args> {
    let mut out = Args::default();
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--assert-all" | "-a" => out.assert_all = true,
            "--help" | "-h" => {
                println!(
                    "offset-finder — scan termsrv.dll for rdprrap patch targets\n\
                     \n\
                     USAGE:\n    offset-finder [--assert-all] [<path-to-termsrv.dll>]\n\
                     \n\
                     FLAGS:\n\
                     \t-a, --assert-all   Exit non-zero if any required pattern is missing\n\
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
    find_offsets_file(&dll_path, args.assert_all)
}

/// Load termsrv.dll as a file and parse PE to find offsets
fn find_offsets_file(path: &std::path::Path, assert_all: bool) -> Result<()> {
    let data = std::fs::read(path).context("Failed to read file")?;
    eprintln!("File size: {} bytes", data.len());

    // Try PE64 first, then PE32
    if let Ok(pe64) = pelite::pe64::PeFile::from_bytes(&data) {
        eprintln!("Architecture: x64");
        find_offsets_pe64(&pe64, assert_all)
    } else if let Ok(pe32) = pelite::pe32::PeFile::from_bytes(&data) {
        eprintln!("Architecture: x86");
        find_offsets_pe32(&pe32, assert_all)
    } else {
        bail!("Failed to parse PE file");
    }
}

fn find_offsets_pe64(pe: &pelite::pe64::PeFile<'_>, assert_all: bool) -> Result<()> {
    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
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
                                println!(
                                    "{name}_func=0x{begin:X} (xref at 0x{:X})",
                                    inst.ip() - image_base
                                );
                                func_found.insert(name);
                            }
                        }
                    }
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
            bail!("--assert-all: required patterns not all resolved");
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
    ];

    println!("[Offset Report]");
    println!("ImageBase=0x{image_base:X}");
    println!("Arch=x86");
    println!();

    let mut missing: Vec<&str> = Vec::new();
    for (name, pattern) in patterns {
        match find_in_section(rdata_data, rdata_va, pattern) {
            Some(rva) => println!("{name}_str=0x{rva:X}"),
            None => {
                println!("{name}_str=NOT_FOUND");
                missing.push(name);
            }
        }
    }

    if assert_all && !missing.is_empty() {
        eprintln!("[Assert] MISSING strings: {missing:?}");
        bail!("--assert-all: required patterns not all resolved");
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
