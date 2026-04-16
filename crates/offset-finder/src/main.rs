use anyhow::{bail, Context, Result};
use std::env;
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let dll_path = if args.len() >= 2 {
        PathBuf::from(&args[1])
    } else {
        #[cfg(windows)]
        {
            let mut sys_dir = vec![0u8; 260];
            let len = unsafe {
                windows::Win32::System::SystemInformation::GetSystemDirectoryA(Some(&mut sys_dir))
            };
            let path = String::from_utf8_lossy(&sys_dir[..len as usize]).to_string();
            PathBuf::from(path).join("termsrv.dll")
        }
        #[cfg(not(windows))]
        {
            bail!("Usage: offset-finder <path-to-termsrv.dll>");
        }
    };

    if !dll_path.exists() {
        bail!("File not found: {}", dll_path.display());
    }

    eprintln!("Loading: {}", dll_path.display());
    find_offsets_file(&dll_path)
}

/// Load termsrv.dll as a file and parse PE to find offsets
fn find_offsets_file(path: &std::path::Path) -> Result<()> {
    let data = std::fs::read(path).context("Failed to read file")?;
    eprintln!("File size: {} bytes", data.len());

    // Try PE64 first, then PE32
    if let Ok(pe64) = pelite::pe64::PeFile::from_bytes(&data) {
        eprintln!("Architecture: x64");
        find_offsets_pe64(&pe64)
    } else if let Ok(pe32) = pelite::pe32::PeFile::from_bytes(&data) {
        eprintln!("Architecture: x86");
        find_offsets_pe32(&pe32)
    } else {
        bail!("Failed to parse PE file");
    }
}

fn find_offsets_pe64(pe: &pelite::pe64::PeFile<'_>) -> Result<()> {
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

    // Find string RVAs
    for (name, pattern) in patterns {
        match find_in_section(rdata_data, rdata_va, pattern) {
            Some(rva) => println!("{name}_str=0x{rva:X}"),
            None => println!("{name}_str=NOT_FOUND"),
        }
    }

    // Find function addresses via exception table xref
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

                    for (name, pattern) in patterns {
                        if let Some(str_rva) = find_in_section(rdata_data, rdata_va, pattern) {
                            if target == str_rva as u64 {
                                println!(
                                    "{name}_func=0x{begin:X} (xref at 0x{:X})",
                                    inst.ip() - image_base
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn find_offsets_pe32(pe: &pelite::pe32::PeFile<'_>) -> Result<()> {
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

    for (name, pattern) in patterns {
        match find_in_section(rdata_data, rdata_va, pattern) {
            Some(rva) => println!("{name}_str=0x{rva:X}"),
            None => println!("{name}_str=NOT_FOUND"),
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
