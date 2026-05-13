use crate::error::PatcherError;
use crate::pe::LoadedPe;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arm64Function {
    pub begin_address: u32,
    pub end_address: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arm64Reference {
    pub function: Arm64Function,
    pub instruction_rva: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arm64CallPatchSite {
    pub function: Arm64Function,
    pub reference_rva: u32,
    pub call_rva: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arm64LoadStoreUnsigned {
    pub rt: u8,
    pub rn: u8,
    pub offset: u32,
}

pub fn loaded_functions(pe: &LoadedPe) -> Result<Vec<Arm64Function>, PatcherError> {
    let text = pe.find_section(".text")?;
    let pdata = pe.find_section(".pdata")?;

    // SAFETY: `.pdata` is a section inside the loaded PE image.
    let pdata_bytes =
        unsafe { pe.read_bytes(pdata.virtual_address as usize, pdata.raw_data_size as usize) };

    Ok(functions_from_pdata(
        pdata_bytes,
        text.virtual_address,
        text.raw_data_size as usize,
    ))
}

pub fn functions_from_pdata(pdata: &[u8], text_rva: u32, text_size: usize) -> Vec<Arm64Function> {
    let text_start = text_rva;
    let text_end = text_rva.saturating_add(text_size as u32);
    let mut begins = Vec::new();

    for entry in pdata.chunks_exact(8) {
        let begin = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        if begin >= text_start && begin < text_end {
            begins.push(begin);
        }
    }

    begins.sort_unstable();
    begins.dedup();

    let mut out = Vec::with_capacity(begins.len());
    for (idx, begin) in begins.iter().copied().enumerate() {
        let end = begins.get(idx + 1).copied().unwrap_or(text_end);
        if end > begin {
            out.push(Arm64Function {
                begin_address: begin,
                end_address: end,
            });
        }
    }

    out
}

pub fn find_function_referencing_rva(pe: &LoadedPe, target_rva: usize) -> Option<Arm64Function> {
    find_reference_to_rva(pe, target_rva).map(|reference| reference.function)
}

pub fn find_reference_to_rva(pe: &LoadedPe, target_rva: usize) -> Option<Arm64Reference> {
    let funcs = loaded_functions(pe).ok()?;
    let target_va = pe.adjusted_base as u64 + target_rva as u64;

    for func in funcs {
        let begin = func.begin_address as usize;
        let len = (func.end_address - func.begin_address) as usize;
        if len == 0 {
            continue;
        }

        // SAFETY: function bounds come from `.pdata` and are clamped to `.text`.
        let code = unsafe { pe.read_bytes(begin, len) };
        if let Some(instruction_va) =
            code_references_addr(code, pe.adjusted_base as u64 + begin as u64, target_va)
        {
            return Some(Arm64Reference {
                function: func,
                instruction_rva: instruction_va.saturating_sub(pe.adjusted_base as u64) as u32,
            });
        }
    }

    None
}

pub fn find_bl_after_reference_rva(
    pe: &LoadedPe,
    target_rva: usize,
    max_bytes_after_reference: usize,
) -> Option<Arm64CallPatchSite> {
    let reference = find_reference_to_rva(pe, target_rva)?;
    let begin = reference.function.begin_address as usize;
    let len = (reference.function.end_address - reference.function.begin_address) as usize;
    if len == 0 {
        return None;
    }

    // SAFETY: function bounds come from `.pdata` and are clamped to `.text`.
    let code = unsafe { pe.read_bytes(begin, len) };
    let code_va = pe.adjusted_base as u64 + begin as u64;
    let reference_va = pe.adjusted_base as u64 + reference.instruction_rva as u64;
    let call_va = find_bl_after_addr(code, code_va, reference_va, max_bytes_after_reference)?;

    Some(Arm64CallPatchSite {
        function: reference.function,
        reference_rva: reference.instruction_rva,
        call_rva: call_va.saturating_sub(pe.adjusted_base as u64) as u32,
    })
}

pub fn code_references_addr(code: &[u8], code_va: u64, target_va: u64) -> Option<u64> {
    let mut reg_pages = [None; 32];

    for (idx, chunk) in code.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let ip = code_va + (idx as u64 * 4);

        if let Some((reg, addr, page_ref)) = decode_adr(word, ip) {
            if addr == target_va {
                return Some(ip);
            }
            reg_pages[reg as usize] = page_ref.then_some(addr);
            continue;
        }

        if let Some((rd, rn, imm)) = decode_add_imm(word) {
            if let Some(page) = reg_pages[rn as usize] {
                if page + imm as u64 == target_va {
                    return Some(ip);
                }
            }
            reg_pages[rd as usize] = None;
            continue;
        }

        if let Some((reg, literal_va)) = decode_ldr_literal(word, ip) {
            if literal_va == target_va {
                return Some(ip);
            }
            reg_pages[reg as usize] = None;
        }
    }

    None
}

pub fn find_bl_after_addr(
    code: &[u8],
    code_va: u64,
    reference_va: u64,
    max_bytes_after_reference: usize,
) -> Option<u64> {
    if reference_va < code_va {
        return None;
    }

    let reference_offset = (reference_va - code_va) as usize;
    if reference_offset >= code.len() {
        return None;
    }

    let start = reference_offset.saturating_add(4);
    let end = start
        .saturating_add(max_bytes_after_reference)
        .min(code.len());
    if start >= end {
        return None;
    }

    for (idx, chunk) in code[start..end].chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if is_bl(word) {
            return Some(code_va + start as u64 + idx as u64 * 4);
        }
    }

    None
}

fn decode_adr(word: u32, ip: u64) -> Option<(u8, u64, bool)> {
    let is_adr = (word & 0x9f00_0000) == 0x1000_0000;
    let is_adrp = (word & 0x9f00_0000) == 0x9000_0000;
    if !is_adr && !is_adrp {
        return None;
    }

    let rd = (word & 0x1f) as u8;
    if rd == 31 {
        return None;
    }

    let immlo = ((word >> 29) & 0x3) as i64;
    let immhi = ((word >> 5) & 0x7ffff) as i64;
    let imm = sign_extend((immhi << 2) | immlo, 21);

    let addr = if is_adrp {
        let page = (ip & !0xfff) as i64;
        (page + (imm << 12)) as u64
    } else {
        (ip as i64 + imm) as u64
    };

    Some((rd, addr, is_adrp))
}

fn decode_add_imm(word: u32) -> Option<(u8, u8, u32)> {
    if (word & 0x7f00_0000) != 0x1100_0000 {
        return None;
    }

    let rd = (word & 0x1f) as u8;
    let rn = ((word >> 5) & 0x1f) as u8;
    if rd == 31 || rn == 31 {
        return None;
    }

    let shift = (word >> 22) & 0x3;
    if shift > 1 {
        return None;
    }

    let imm12 = (word >> 10) & 0xfff;
    let imm = if shift == 1 { imm12 << 12 } else { imm12 };
    Some((rd, rn, imm))
}

fn decode_ldr_literal(word: u32, ip: u64) -> Option<(u8, u64)> {
    if (word & 0x3b00_0000) != 0x1800_0000 {
        return None;
    }

    let rt = (word & 0x1f) as u8;
    if rt == 31 {
        return None;
    }

    let imm19 = ((word >> 5) & 0x7ffff) as i64;
    let offset = sign_extend(imm19, 19) << 2;
    Some((rt, (ip as i64 + offset) as u64))
}

pub fn decode_ldr_w_unsigned(word: u32) -> Option<Arm64LoadStoreUnsigned> {
    decode_load_store_w_unsigned(word, 0xb940_0000)
}

pub fn decode_str_w_unsigned(word: u32) -> Option<Arm64LoadStoreUnsigned> {
    decode_load_store_w_unsigned(word, 0xb900_0000)
}

fn decode_load_store_w_unsigned(word: u32, opcode: u32) -> Option<Arm64LoadStoreUnsigned> {
    if (word & 0xffc0_0000) != opcode {
        return None;
    }

    let rt = (word & 0x1f) as u8;
    let rn = ((word >> 5) & 0x1f) as u8;
    if rt == 31 || rn == 31 {
        return None;
    }

    let imm12 = (word >> 10) & 0xfff;
    Some(Arm64LoadStoreUnsigned {
        rt,
        rn,
        offset: imm12 * 4,
    })
}

pub fn encode_movz_w(rd: u8, imm16: u16) -> Option<u32> {
    if rd >= 31 {
        return None;
    }

    Some(0x5280_0000 | ((imm16 as u32) << 5) | rd as u32)
}

pub fn encode_str_w_unsigned(rt: u8, rn: u8, offset: u32) -> Option<u32> {
    if rt >= 31 || rn >= 31 || !offset.is_multiple_of(4) {
        return None;
    }

    let imm12 = offset / 4;
    if imm12 > 0xfff {
        return None;
    }

    Some(0xb900_0000 | (imm12 << 10) | ((rn as u32) << 5) | rt as u32)
}

pub fn is_cond_branch(word: u32) -> bool {
    (word & 0xff00_0010) == 0x5400_0000
}

fn is_bl(word: u32) -> bool {
    (word & 0xfc00_0000) == 0x9400_0000
}

fn sign_extend(value: i64, bits: u32) -> i64 {
    let shift = 64 - bits;
    (value << shift) >> shift
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_word(out: &mut Vec<u8>, word: u32) {
        out.extend_from_slice(&word.to_le_bytes());
    }

    fn encode_adrp(rd: u8, pc: u64, target: u64) -> u32 {
        let pc_page = (pc & !0xfff) as i64;
        let target_page = (target & !0xfff) as i64;
        let imm = (target_page - pc_page) >> 12;
        let imm_u = imm as u32;
        let immlo = imm_u & 0x3;
        let immhi = (imm_u >> 2) & 0x7ffff;
        0x9000_0000 | (immlo << 29) | (immhi << 5) | rd as u32
    }

    fn encode_add(rd: u8, rn: u8, imm: u32) -> u32 {
        0x9100_0000 | ((imm & 0xfff) << 10) | ((rn as u32) << 5) | rd as u32
    }

    fn encode_bl(imm26: u32) -> u32 {
        0x9400_0000 | (imm26 & 0x03ff_ffff)
    }

    fn encode_ldr_w(rt: u8, rn: u8, offset: u32) -> u32 {
        0xb940_0000 | ((offset / 4) << 10) | ((rn as u32) << 5) | rt as u32
    }

    #[test]
    fn detects_adrp_add_reference() {
        let code_va = 0x0001_8010_0000;
        let target = 0x0001_8022_0340;
        let mut code = Vec::new();
        push_word(&mut code, encode_adrp(0, code_va, target));
        push_word(&mut code, encode_add(0, 0, 0x340));

        assert_eq!(
            code_references_addr(&code, code_va, target),
            Some(code_va + 4)
        );
    }

    #[test]
    fn ignores_wrong_page_reference() {
        let code_va = 0x0001_8010_0000;
        let target = 0x0001_8022_0340;
        let wrong = 0x0001_8023_0340;
        let mut code = Vec::new();
        push_word(&mut code, encode_adrp(0, code_va, wrong));
        push_word(&mut code, encode_add(0, 0, 0x340));

        assert_eq!(code_references_addr(&code, code_va, target), None);
    }

    #[test]
    fn finds_bl_after_reference() {
        let code_va = 0x0001_8010_0000;
        let target = 0x0001_8022_0340;
        let mut code = Vec::new();
        push_word(&mut code, encode_adrp(0, code_va, target));
        push_word(&mut code, encode_add(0, 0, 0x340));
        push_word(&mut code, 0xd503_201f); // nop
        push_word(&mut code, encode_bl(0x20));

        let reference = code_references_addr(&code, code_va, target).unwrap();
        assert_eq!(
            find_bl_after_addr(&code, code_va, reference, 32),
            Some(code_va + 12)
        );
    }

    #[test]
    fn bl_search_honors_window() {
        let code_va = 0x0001_8010_0000;
        let target = 0x0001_8022_0340;
        let mut code = Vec::new();
        push_word(&mut code, encode_adrp(0, code_va, target));
        push_word(&mut code, encode_add(0, 0, 0x340));
        push_word(&mut code, 0xd503_201f);
        push_word(&mut code, encode_bl(0x20));

        let reference = code_references_addr(&code, code_va, target).unwrap();
        assert_eq!(find_bl_after_addr(&code, code_va, reference, 4), None);
    }

    #[test]
    fn decodes_and_encodes_w_load_store_unsigned() {
        let ldr = encode_ldr_w(9, 0, 0x63c);
        assert_eq!(
            decode_ldr_w_unsigned(ldr),
            Some(Arm64LoadStoreUnsigned {
                rt: 9,
                rn: 0,
                offset: 0x63c,
            })
        );

        let str_word = encode_str_w_unsigned(9, 0, 0x638).unwrap();
        assert_eq!(
            decode_str_w_unsigned(str_word),
            Some(Arm64LoadStoreUnsigned {
                rt: 9,
                rn: 0,
                offset: 0x638,
            })
        );
    }

    #[test]
    fn encodes_movz_w() {
        assert_eq!(encode_movz_w(9, 0x100), Some(0x5280_2009));
        assert_eq!(encode_movz_w(31, 1), None);
    }

    #[test]
    fn detects_conditional_branch() {
        assert!(is_cond_branch(0x5400_0020));
        assert!(!is_cond_branch(encode_bl(0x20)));
    }

    #[test]
    fn builds_function_ranges_from_pdata() {
        let mut pdata = Vec::new();
        pdata.extend_from_slice(&0x1000u32.to_le_bytes());
        pdata.extend_from_slice(&0u32.to_le_bytes());
        pdata.extend_from_slice(&0x1080u32.to_le_bytes());
        pdata.extend_from_slice(&0u32.to_le_bytes());

        let funcs = functions_from_pdata(&pdata, 0x1000, 0x100);
        assert_eq!(
            funcs,
            vec![
                Arm64Function {
                    begin_address: 0x1000,
                    end_address: 0x1080,
                },
                Arm64Function {
                    begin_address: 0x1080,
                    end_address: 0x1100,
                },
            ]
        );
    }
}
