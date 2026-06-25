use crate::error::PatcherError;

/// Parsed PE image loaded in memory.
///
/// Wraps a base address of a loaded PE (via LoadLibraryEx) and provides
/// safe accessors for headers, sections, imports, and exception tables.
pub struct LoadedPe {
    /// Base address of the loaded module (with low bits masked off)
    pub base: usize,
    /// Whether this is a 64-bit PE
    pub is_64bit: bool,
    /// Adjusted base for RVA-to-pointer conversion
    /// (base + section.PointerToRawData - section.VirtualAddress for first section)
    pub adjusted_base: usize,
}

/// Section header info extracted from PE
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_offset: u32,
    pub raw_data_size: u32,
}

/// Import descriptor info
#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub dll_name: String,
    pub original_first_thunk: u32,
    pub first_thunk: u32,
}

/// Runtime function entry (x64 exception table)
#[derive(Debug, Clone, Copy)]
pub struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_data: u32,
}

/// File version extracted from VS_VERSIONINFO resource
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileVersion {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
}

impl std::fmt::Display for FileVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision
        )
    }
}

impl LoadedPe {
    /// Create a LoadedPe from a module loaded via LoadLibraryEx (mapped image).
    ///
    /// For normally-loaded DLLs (not LOAD_LIBRARY_AS_DATAFILE), sections are
    /// mapped at base + VirtualAddress, so adjusted_base == base.
    ///
    /// # Safety
    /// - `base_addr` must be a valid pointer to a PE image loaded in memory
    /// - The PE image must remain valid for the lifetime of this struct
    pub unsafe fn from_base(base_addr: usize) -> Result<Self, PatcherError> {
        // SAFETY: Caller guarantees base_addr points to valid PE image
        let base = base_addr & !3; // mask off low bits (LOAD_LIBRARY_AS_DATAFILE sets them)

        let dos_magic = unsafe { *(base as *const u16) };
        if dos_magic != 0x5A4D {
            return Err(PatcherError::InvalidPe("invalid DOS signature".into()));
        }

        let e_lfanew = unsafe { *((base + 0x3C) as *const u32) } as usize;
        let nt_signature = unsafe { *((base + e_lfanew) as *const u32) };
        if nt_signature != 0x00004550 {
            return Err(PatcherError::InvalidPe("invalid NT signature".into()));
        }

        let optional_magic = unsafe { *((base + e_lfanew + 0x18) as *const u16) };
        let is_64bit = optional_magic == 0x20B; // IMAGE_NT_OPTIONAL_HDR64_MAGIC

        // For normally-loaded DLLs (mapped images), sections are at base + VA,
        // so adjusted_base == base. This matches TermWrap C++ behavior which
        // uses `(size_t)hMod` directly as the base for all address calculations.
        //
        // Note: Only LOAD_LIBRARY_AS_DATAFILE needs the PointerToRawData adjustment.
        // The DLL wrapper crates all use LOAD_LIBRARY_SEARCH_SYSTEM32 (normal load).
        let adjusted_base = base;

        Ok(Self {
            base,
            is_64bit,
            adjusted_base,
        })
    }

    /// Create a LoadedPe from a data-file loaded PE (LOAD_LIBRARY_AS_DATAFILE).
    ///
    /// In this mode, sections are at file offsets, not virtual addresses,
    /// so adjusted_base = base + PointerToRawData - VirtualAddress.
    ///
    /// # Safety
    /// Same as `from_base`
    pub unsafe fn from_data_file(base_addr: usize) -> Result<Self, PatcherError> {
        let base = base_addr & !3;

        let dos_magic = unsafe { *(base as *const u16) };
        if dos_magic != 0x5A4D {
            return Err(PatcherError::InvalidPe("invalid DOS signature".into()));
        }

        let e_lfanew = unsafe { *((base + 0x3C) as *const u32) } as usize;
        let nt_signature = unsafe { *((base + e_lfanew) as *const u32) };
        if nt_signature != 0x00004550 {
            return Err(PatcherError::InvalidPe("invalid NT signature".into()));
        }

        let optional_magic = unsafe { *((base + e_lfanew + 0x18) as *const u16) };
        let is_64bit = optional_magic == 0x20B;

        let file_header_offset = base + e_lfanew + 4;
        let size_of_optional = unsafe { *((file_header_offset + 16) as *const u16) } as usize;
        let first_section_offset = file_header_offset + 20 + size_of_optional;

        let section_va = unsafe { *((first_section_offset + 12) as *const u32) };
        let section_raw = unsafe { *((first_section_offset + 20) as *const u32) };
        let adjusted_base = base + section_raw as usize - section_va as usize;

        Ok(Self {
            base,
            is_64bit,
            adjusted_base,
        })
    }

    /// Get offset to NT headers from base
    fn nt_offset(&self) -> usize {
        // SAFETY: PE validity guaranteed by from_base
        unsafe { *((self.base + 0x3C) as *const u32) as usize }
    }

    /// Get the number of sections
    pub fn section_count(&self) -> u16 {
        // SAFETY: PE validity guaranteed by from_base
        unsafe { *((self.base + self.nt_offset() + 4 + 2) as *const u16) }
    }

    /// Find a section by name
    pub fn find_section(&self, name: &str) -> Result<SectionInfo, PatcherError> {
        let nt = self.nt_offset();
        let file_header_offset = self.base + nt + 4;
        let num_sections = unsafe { *((file_header_offset + 2) as *const u16) } as usize;
        let size_of_optional = unsafe { *((file_header_offset + 16) as *const u16) } as usize;
        let first_section = file_header_offset + 20 + size_of_optional;

        for i in 0..num_sections {
            let section_ptr = first_section + i * 40;
            // SAFETY: section_ptr is within the PE headers
            let section_name = unsafe {
                let name_bytes = std::slice::from_raw_parts(section_ptr as *const u8, 8);
                let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
                String::from_utf8_lossy(&name_bytes[..end])
            };

            if section_name == name {
                return Ok(SectionInfo {
                    name: section_name.to_string(),
                    virtual_address: unsafe { *((section_ptr + 12) as *const u32) },
                    virtual_size: unsafe { *((section_ptr + 8) as *const u32) },
                    raw_data_offset: unsafe { *((section_ptr + 20) as *const u32) },
                    raw_data_size: unsafe { *((section_ptr + 16) as *const u32) },
                });
            }
        }

        Err(PatcherError::SectionNotFound(name.to_string()))
    }

    /// Find .rdata section (fall back to .text if not found)
    pub fn find_rdata_section(&self) -> Result<SectionInfo, PatcherError> {
        self.find_section(".rdata")
            .or_else(|_| self.find_section(".text"))
    }

    /// Get import descriptor entries
    pub fn get_imports(&self) -> Vec<ImportInfo> {
        let nt = self.nt_offset();
        let import_dir_offset = if self.is_64bit {
            self.base + nt + 0x18 + 0x70 + 8 // OptionalHeader + 0x70 (import dir) for PE32+
        } else {
            self.base + nt + 0x18 + 0x60 + 8 // OptionalHeader + 0x60 for PE32
        };

        let import_rva = unsafe { *((import_dir_offset) as *const u32) };
        if import_rva == 0 {
            return Vec::new();
        }

        let mut imports = Vec::new();
        let mut desc_ptr = self.base + import_rva as usize;

        loop {
            // SAFETY: we're walking the import directory within the PE
            let name_rva = unsafe { *((desc_ptr + 12) as *const u32) };
            if name_rva == 0 {
                break;
            }

            let dll_name = unsafe {
                let name_ptr = (self.base + name_rva as usize) as *const u8;
                let mut len = 0;
                while *name_ptr.add(len) != 0 && len < 256 {
                    len += 1;
                }
                let bytes = std::slice::from_raw_parts(name_ptr, len);
                String::from_utf8_lossy(bytes).to_string()
            };

            let original_first_thunk = unsafe { *(desc_ptr as *const u32) };
            let first_thunk = unsafe { *((desc_ptr + 16) as *const u32) };

            imports.push(ImportInfo {
                dll_name,
                original_first_thunk,
                first_thunk,
            });

            desc_ptr += 20; // sizeof(IMAGE_IMPORT_DESCRIPTOR)
        }

        imports
    }

    /// Find an import image (DLL) by name (case-insensitive)
    pub fn find_import_image(&self, name: &str) -> Option<ImportInfo> {
        self.get_imports()
            .into_iter()
            .find(|imp| imp.dll_name.eq_ignore_ascii_case(name))
    }

    /// Find an import function's thunk RVA within an import descriptor
    pub fn find_import_function(
        &self,
        import: &ImportInfo,
        func_name: &str,
    ) -> Result<usize, PatcherError> {
        let mut oft_ptr = self.base + import.original_first_thunk as usize;
        let mut ft_offset: usize = 0;

        if self.is_64bit {
            loop {
                // SAFETY: walking import thunk array
                let thunk_data = unsafe { *(oft_ptr as *const u64) };
                if thunk_data == 0 {
                    break;
                }

                // Check if ordinal import (high bit set)
                if thunk_data & (1u64 << 63) == 0 {
                    let hint_name_ptr = self.base + thunk_data as usize + 2; // skip hint
                    let name = unsafe {
                        let ptr = hint_name_ptr as *const u8;
                        let mut len = 0;
                        while *ptr.add(len) != 0 && len < 256 {
                            len += 1;
                        }
                        let bytes = std::slice::from_raw_parts(ptr, len);
                        String::from_utf8_lossy(bytes)
                    };
                    if name.eq_ignore_ascii_case(func_name) {
                        return Ok(import.first_thunk as usize + ft_offset);
                    }
                }

                oft_ptr += 8;
                ft_offset += 8;
            }
        } else {
            loop {
                let thunk_data = unsafe { *(oft_ptr as *const u32) };
                if thunk_data == 0 {
                    break;
                }

                if thunk_data & (1u32 << 31) == 0 {
                    let hint_name_ptr = self.base + thunk_data as usize + 2;
                    let name = unsafe {
                        let ptr = hint_name_ptr as *const u8;
                        let mut len = 0;
                        while *ptr.add(len) != 0 && len < 256 {
                            len += 1;
                        }
                        let bytes = std::slice::from_raw_parts(ptr, len);
                        String::from_utf8_lossy(bytes)
                    };
                    if name.eq_ignore_ascii_case(func_name) {
                        return Ok(import.first_thunk as usize + ft_offset);
                    }
                }

                oft_ptr += 4;
                ft_offset += 4;
            }
        }

        Err(PatcherError::ImportFunctionNotFound(func_name.to_string()))
    }

    /// Get the x64 exception table (RUNTIME_FUNCTION array)
    pub fn get_exception_table(&self) -> Option<Vec<RuntimeFunction>> {
        if !self.is_64bit {
            return None;
        }

        let nt = self.nt_offset();
        // Exception directory is at index 3 in data directories
        let exc_dir_offset = self.base + nt + 0x18 + 0x70 + 3 * 8;
        let exc_rva = unsafe { *((exc_dir_offset) as *const u32) };
        let exc_size = unsafe { *((exc_dir_offset + 4) as *const u32) };

        if exc_rva == 0 || exc_size == 0 {
            return None;
        }

        let count = exc_size as usize / 12; // sizeof(RUNTIME_FUNCTION) = 12
        let mut entries = Vec::with_capacity(count);
        let table_ptr = self.base + exc_rva as usize;

        for i in 0..count {
            let entry_ptr = table_ptr + i * 12;
            entries.push(RuntimeFunction {
                begin_address: unsafe { *(entry_ptr as *const u32) },
                end_address: unsafe { *((entry_ptr + 4) as *const u32) },
                unwind_data: unsafe { *((entry_ptr + 8) as *const u32) },
            });
        }

        Some(entries)
    }

    /// Backtrace through chained unwind info using the loaded in-memory image
    /// as the byte source, returning the primary (hot) RUNTIME_FUNCTION.
    ///
    /// Thin wrapper over [`resolve_chained_unwind`] that reads bytes directly
    /// from the mapped image, bounding every access to `image_extent()`.
    ///
    /// SEC-CU-03: the resolved primary is self-validated against the `.text`
    /// extent (falling back to the whole-image extent when `.text` is absent),
    /// expressed as RVAs to match `RUNTIME_FUNCTION` begin/end. A bogus chain
    /// that resolves out of range yields the original `func` unchanged.
    pub fn resolve_chained_unwind_in_image(&self, func: &RuntimeFunction) -> RuntimeFunction {
        let (start, end) = self.image_extent();
        let base = self.base;

        // Validation window in RVA space: prefer `.text`, fall back to the whole
        // image. `RUNTIME_FUNCTION.begin_address`/`end_address` are RVAs, so the
        // absolute extents are rebased to `base` before subtracting.
        let valid_begin = self
            .text_extent()
            .map(|(lo, hi)| {
                (
                    lo.saturating_sub(base) as u32,
                    hi.saturating_sub(base) as u32,
                )
            })
            .or(Some((
                start.saturating_sub(base) as u32,
                end.saturating_sub(base) as u32,
            )));

        resolve_chained_unwind(
            *func,
            |rva| {
                let addr = base.checked_add(rva as usize)?;
                if addr < start || addr >= end {
                    return None;
                }
                // SAFETY: `addr` is within [start, end) == the mapped image extent,
                // so a single-byte read at `addr` stays inside the mapping.
                Some(unsafe { *(addr as *const u8) })
            },
            valid_begin,
        )
    }

    /// `SizeOfImage` from the optional header: the total size, in bytes, of the
    /// image as loaded in memory (header + all sections, rounded to the section
    /// alignment). The field lives at the same optional-header offset (0x38) for
    /// both PE32 and PE32+.
    ///
    /// Returned as a plain value so callers can compute the in-memory image
    /// extent (see [`image_extent`](Self::image_extent)).
    pub fn size_of_image(&self) -> u32 {
        let nt = self.nt_offset();
        // optional header starts at nt + 4 (PE sig) + 0x14 (file header) = nt+0x18.
        // SizeOfImage is at optional-header offset 0x38, identical for PE32/PE32+.
        // SAFETY: PE validity guaranteed by from_base; the optional header lies
        // wholly within the mapped image headers.
        unsafe { *((self.base + nt + 0x18 + 0x38) as *const u32) }
    }

    /// The loaded image's in-memory address extent as `[start, end)` absolute
    /// addresses, where `start == base` and `end == base + SizeOfImage`.
    ///
    /// Wrapper crates use this to bound a raw read at a decoded branch target
    /// (BF-1): given an absolute `target` inside the image, compute the readable
    /// span with `let (_, end) = pe.image_extent(); let avail =
    /// end.saturating_sub(target);` and clamp the length passed to
    /// `slice::from_raw_parts` to `avail` so a target near the end of the image
    /// cannot read past the mapping. Returns absolute addresses (not RVAs) to
    /// match the absolute IPs that iced-x86 resolves for branch targets.
    pub fn image_extent(&self) -> (usize, usize) {
        let start = self.base;
        let end = start.saturating_add(self.size_of_image() as usize);
        (start, end)
    }

    /// The `.text` section's in-memory address extent as `[start, end)` absolute
    /// addresses, computed from its VirtualAddress and VirtualSize, or `None`
    /// when the section is absent.
    ///
    /// Tighter than [`image_extent`](Self::image_extent) for callers that want to
    /// confirm a decoded branch target actually lands in executable code before
    /// reading instruction bytes there.
    pub fn text_extent(&self) -> Option<(usize, usize)> {
        let section = self.find_section(".text").ok()?;
        let start = self.base.saturating_add(section.virtual_address as usize);
        let end = start.saturating_add(section.virtual_size as usize);
        Some((start, end))
    }

    /// Read a slice of bytes from the loaded PE at a given RVA
    ///
    /// # Safety
    /// The RVA range must be within the loaded PE image
    pub unsafe fn read_bytes(&self, rva: usize, len: usize) -> &[u8] {
        let ptr = (self.adjusted_base + rva) as *const u8;
        std::slice::from_raw_parts(ptr, len)
    }

    /// Get a raw pointer to a given RVA in the adjusted base
    pub fn rva_to_ptr(&self, rva: usize) -> usize {
        self.adjusted_base + rva
    }
}

/// `UNW_FLAG_CHAININFO` — bit set in the UNWIND_INFO flags nibble when this
/// entry chains to a primary RUNTIME_FUNCTION. Used by PGO hot/cold splitting:
/// the cold (outlined) fragment carries a chained unwind entry pointing back at
/// the hot function it was split from.
const UNW_FLAG_CHAININFO: u8 = 0x4;

/// `RUNTIME_FUNCTION_INDIRECT` — low bit set in `UnwindData` means the field is
/// itself an RVA to another RUNTIME_FUNCTION rather than to an UNWIND_INFO.
const RUNTIME_FUNCTION_INDIRECT: u32 = 0x1;

/// Resolve a chained (PGO hot/cold split) RUNTIME_FUNCTION to its primary
/// (hot) function, returning the input unchanged when the entry is not chained.
///
/// # Why this exists
/// Profile-guided optimization can outline a cold path (e.g. an error/deny
/// branch) into a separate `.text$xx` fragment with its own RUNTIME_FUNCTION.
/// A string referenced only from that cold fragment will resolve, via
/// xref→containing-function, to the cold fragment — which does not contain the
/// gate we want to patch. The cold fragment's UNWIND_INFO carries
/// `UNW_FLAG_CHAININFO`, chaining back to the primary (hot) RUNTIME_FUNCTION.
/// Following that chain recovers the hot function so the patch analyzer slices
/// the correct bytes.
///
/// # UNWIND_INFO layout (x64; see MS x64 unwinding docs)
/// ```text
/// offset 0:  bits 0..2  Version (currently 1 or 2)
///            bits 3..7  Flags   (UNW_FLAG_* — CHAININFO == 0x4)
/// offset 1:  SizeOfProlog (u8)
/// offset 2:  CountOfUnwindCodes (u8) — number of 2-byte unwind code slots
/// offset 3:  bits 0..3  FrameRegister
///            bits 4..7  FrameOffset
/// offset 4:  UnwindCode[CountOfUnwindCodes]  (2 bytes each)
/// then, ONLY when UNW_FLAG_CHAININFO is set, a chained RUNTIME_FUNCTION
/// (12 bytes: BeginAddress, EndAddress, UnwindData) at:
///     4 + ((CountOfUnwindCodes + 1) / 2) * 4
/// (the unwind-code array is padded to a multiple of 4 bytes / an even number
/// of 2-byte slots before the trailing chained entry).
/// ```
/// Chains can nest, so this follows them recursively until a non-chained
/// UNWIND_INFO (capped to bound runtime and any pathological cycle).
///
/// # Bounds safety
/// `read_u8(rva)` must return `Some(byte)` only when `rva` is readable in the
/// backing image/file and `None` otherwise. Any out-of-range read aborts the
/// walk and returns the most recently resolved RUNTIME_FUNCTION rather than
/// panicking, so a truncated or malformed table can never cause OOB access.
///
/// # Self-validation (SEC-CU-03)
/// `valid_begin` is an optional `[lo, hi)` RVA window that the resolved primary
/// must land in (use `.text`, falling back to the whole image, via
/// [`text_extent`](LoadedPe::text_extent) / [`image_extent`](LoadedPe::image_extent)).
/// When supplied, after the walk the resolved primary is validated:
/// `lo <= begin_address < hi` AND `end_address > begin_address`. If validation
/// fails (a bogus or malformed chain that pointed off into garbage), the
/// ORIGINAL input `func` is returned unchanged so callers fall back to the
/// un-chained body rather than patching a bogus site. Pass `None` to skip
/// validation (e.g. unit tests using a synthetic byte buffer). This guard is at
/// the chokepoint, so every caller benefits.
pub fn resolve_chained_unwind<F>(
    func: RuntimeFunction,
    read_u8: F,
    valid_begin: Option<(u32, u32)>,
) -> RuntimeFunction
where
    F: Fn(u32) -> Option<u8>,
{
    // Validate a resolved primary against the optional `[lo, hi)` RVA window:
    // its begin must land in range and its end must lie strictly after begin.
    let is_valid = |rf: &RuntimeFunction| -> bool {
        match valid_begin {
            Some((lo, hi)) => {
                rf.begin_address >= lo && rf.begin_address < hi && rf.end_address > rf.begin_address
            }
            None => true,
        }
    };

    // Read a little-endian u32 at `rva`, or None if any byte is unreadable.
    let read_u32 = |rva: u32| -> Option<u32> {
        let b0 = read_u8(rva)? as u32;
        let b1 = read_u8(rva.checked_add(1)?)? as u32;
        let b2 = read_u8(rva.checked_add(2)?)? as u32;
        let b3 = read_u8(rva.checked_add(3)?)? as u32;
        Some(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
    };
    // Read a 12-byte RUNTIME_FUNCTION at `rva`, or None if out of range.
    let read_runtime_function = |rva: u32| -> Option<RuntimeFunction> {
        Some(RuntimeFunction {
            begin_address: read_u32(rva)?,
            end_address: read_u32(rva.checked_add(4)?)?,
            unwind_data: read_u32(rva.checked_add(8)?)?,
        })
    };

    // Walk the chain to the resolved primary (or the last good entry on any
    // out-of-range / malformed read). Kept as a closure so the SEC-CU-03 extent
    // validation below applies once, to whatever this returns, at the single
    // chokepoint.
    let walk = || {
        let mut current = func;
        // Chains are short in practice; the cap defends against malformed/cyclic
        // tables without an explicit visited-set.
        for _ in 0..16 {
            // An indirect RUNTIME_FUNCTION points at another RUNTIME_FUNCTION.
            if current.unwind_data & RUNTIME_FUNCTION_INDIRECT != 0 {
                match read_runtime_function(current.unwind_data & !RUNTIME_FUNCTION_INDIRECT) {
                    Some(next) => {
                        current = next;
                        continue;
                    }
                    None => return current,
                }
            }

            let unwind_rva = current.unwind_data;
            // UNWIND_INFO header: byte0 carries version|flags, byte2 the code count.
            let byte0 = match read_u8(unwind_rva) {
                Some(b) => b,
                None => return current,
            };
            let flags = byte0 >> 3;
            if flags & UNW_FLAG_CHAININFO == 0 {
                // Not chained: this is the primary (hot) function.
                return current;
            }
            let count_of_codes = match read_u8(unwind_rva.wrapping_add(2)) {
                Some(b) => b,
                None => return current,
            };

            // Bytes occupied by the unwind-code array, padded to an even slot count.
            // div_ceil(2) rounds the 2-byte slot count up to an even number; *4
            // converts the resulting slot pairs to bytes (each pair == 4 bytes).
            let codes_bytes = (count_of_codes as u32).div_ceil(2) * 4;
            let chain_rva = match unwind_rva
                .checked_add(4)
                .and_then(|v| v.checked_add(codes_bytes))
            {
                Some(v) => v,
                None => return current,
            };
            match read_runtime_function(chain_rva) {
                Some(primary) => current = primary,
                None => return current,
            }
        }

        current
    };

    let resolved = walk();
    // SEC-CU-03: a bogus/malformed chain can resolve to an entry that does not
    // land in the image (or has end <= begin). When that happens, treat the
    // chain as unresolvable and hand back the ORIGINAL input so callers fall
    // back to the un-chained body rather than slicing/patching a bogus site.
    if is_valid(&resolved) {
        resolved
    } else {
        func
    }
}

#[cfg(test)]
mod chained_unwind_tests {
    use super::*;

    /// Build an in-memory image buffer where bytes are addressed by RVA, and
    /// return a reader closure over it. RVAs outside the buffer read as None.
    fn reader(buf: &[u8]) -> impl Fn(u32) -> Option<u8> + '_ {
        move |rva: u32| buf.get(rva as usize).copied()
    }

    /// Write a RUNTIME_FUNCTION (begin,end,unwind) into `buf` at `off`.
    fn put_runtime_function(buf: &mut [u8], off: usize, begin: u32, end: u32, unwind: u32) {
        buf[off..off + 4].copy_from_slice(&begin.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&end.to_le_bytes());
        buf[off + 8..off + 12].copy_from_slice(&unwind.to_le_bytes());
    }

    #[test]
    fn non_chained_is_noop() {
        // UNWIND_INFO at rva 0x100: version 1, flags 0 (not chained), 2 codes.
        let mut buf = vec![0u8; 0x200];
        buf[0x100] = 0x01; // version=1, flags=0
        buf[0x102] = 2; // count_of_codes
        let input = RuntimeFunction {
            begin_address: 0x1000,
            end_address: 0x1050,
            unwind_data: 0x100,
        };
        let out = resolve_chained_unwind(input, reader(&buf), None);
        assert_eq!(out.begin_address, 0x1000);
        assert_eq!(out.end_address, 0x1050);
        assert_eq!(out.unwind_data, 0x100);
    }

    #[test]
    fn chained_resolves_to_primary() {
        // Cold UNWIND_INFO at 0x100: flags=CHAININFO, count_of_codes=3.
        // codes_bytes = ((3+1)/2)*4 = 8; chained RUNTIME_FUNCTION at 0x100+4+8=0x10C.
        let mut buf = vec![0u8; 0x400];
        buf[0x100] = 0x01 | (UNW_FLAG_CHAININFO << 3); // version=1, flags=CHAININFO
        buf[0x102] = 3; // count_of_codes
                        // Primary UNWIND_INFO at 0x200: not chained.
        buf[0x200] = 0x01;
        buf[0x202] = 1;
        // Chained entry -> hot function begin=0x1B790,end=0x1B7BA,unwind=0x200.
        put_runtime_function(&mut buf, 0x10C, 0x1B790, 0x1B7BA, 0x200);

        let cold = RuntimeFunction {
            begin_address: 0x2E45E,
            end_address: 0x2E47A,
            unwind_data: 0x100,
        };
        let out = resolve_chained_unwind(cold, reader(&buf), None);
        assert_eq!(out.begin_address, 0x1B790);
        assert_eq!(out.end_address, 0x1B7BA);
        assert_eq!(out.unwind_data, 0x200);
    }

    #[test]
    fn even_code_count_offset_math() {
        // count_of_codes = 4 -> codes_bytes = ((4+1)/2)*4 = 8; chain at +12.
        let mut buf = vec![0u8; 0x400];
        buf[0x100] = 0x01 | (UNW_FLAG_CHAININFO << 3);
        buf[0x102] = 4;
        buf[0x200] = 0x01; // primary, not chained
        put_runtime_function(&mut buf, 0x100 + 4 + 8, 0xAAAA, 0xBBBB, 0x200);

        let cold = RuntimeFunction {
            begin_address: 0x9000,
            end_address: 0x9010,
            unwind_data: 0x100,
        };
        let out = resolve_chained_unwind(cold, reader(&buf), None);
        assert_eq!(out.begin_address, 0xAAAA);
        assert_eq!(out.end_address, 0xBBBB);
    }

    #[test]
    fn nested_chain_followed_recursively() {
        // cold(0x100) -> mid(0x200) -> hot(0x300, not chained).
        let mut buf = vec![0u8; 0x600];
        // cold: chained, 1 code -> codes_bytes = ((1+1)/2)*4 = 4; chain at 0x108.
        buf[0x100] = 0x01 | (UNW_FLAG_CHAININFO << 3);
        buf[0x102] = 1;
        put_runtime_function(&mut buf, 0x108, 0x5000, 0x5010, 0x200);
        // mid: chained, 0 codes -> codes_bytes = 0; chain at 0x204.
        buf[0x200] = 0x01 | (UNW_FLAG_CHAININFO << 3);
        buf[0x202] = 0;
        put_runtime_function(&mut buf, 0x204, 0x6000, 0x6010, 0x300);
        // hot: not chained.
        buf[0x300] = 0x01;
        buf[0x302] = 2;

        let cold = RuntimeFunction {
            begin_address: 0xC000,
            end_address: 0xC010,
            unwind_data: 0x100,
        };
        let out = resolve_chained_unwind(cold, reader(&buf), None);
        assert_eq!(out.begin_address, 0x6000);
        assert_eq!(out.end_address, 0x6010);
        assert_eq!(out.unwind_data, 0x300);
    }

    #[test]
    fn out_of_range_returns_last_resolved() {
        // Chained flag set but the chained entry sits past the buffer end:
        // the walk must stop and return the cold entry, never read OOB.
        let mut buf = vec![0u8; 0x104];
        buf[0x100] = 0x01 | (UNW_FLAG_CHAININFO << 3);
        buf[0x102] = 8; // chain would be far past the 0x104-byte buffer
        let cold = RuntimeFunction {
            begin_address: 0x2E45E,
            end_address: 0x2E47A,
            unwind_data: 0x100,
        };
        let out = resolve_chained_unwind(cold, reader(&buf), None);
        // Unchanged — no panic, no OOB.
        assert_eq!(out.begin_address, 0x2E45E);
        assert_eq!(out.unwind_data, 0x100);
    }

    #[test]
    fn indirect_runtime_function_followed() {
        // unwind_data low bit set -> points at another RUNTIME_FUNCTION at 0x180.
        let mut buf = vec![0u8; 0x300];
        put_runtime_function(&mut buf, 0x180, 0x7000, 0x7010, 0x200);
        buf[0x200] = 0x01; // not chained
        let input = RuntimeFunction {
            begin_address: 0x8000,
            end_address: 0x8010,
            unwind_data: 0x180 | RUNTIME_FUNCTION_INDIRECT,
        };
        let out = resolve_chained_unwind(input, reader(&buf), None);
        assert_eq!(out.begin_address, 0x7000);
        assert_eq!(out.unwind_data, 0x200);
    }

    #[test]
    fn primary_out_of_extent_returns_original_func() {
        // SEC-CU-03: a bogus chain whose resolved primary lands OUTSIDE the
        // valid `.text` window must yield the ORIGINAL input unchanged so the
        // caller falls back to the un-chained cold body.
        let mut buf = vec![0u8; 0x400];
        // Cold UNWIND_INFO at 0x100: chained, 3 codes -> chain at 0x10C.
        buf[0x100] = 0x01 | (UNW_FLAG_CHAININFO << 3);
        buf[0x102] = 3;
        buf[0x200] = 0x01; // primary, not chained
                           // Chained entry resolves to begin=0x90000, which is
                           // well past the [0x1000, 0x40000) valid window.
        put_runtime_function(&mut buf, 0x10C, 0x90000, 0x90010, 0x200);

        let cold = RuntimeFunction {
            begin_address: 0x2E45E,
            end_address: 0x2E47A,
            unwind_data: 0x100,
        };
        // Valid `.text` RVA window: begin must satisfy 0x1000 <= begin < 0x40000.
        let out = resolve_chained_unwind(cold, reader(&buf), Some((0x1000, 0x40000)));
        // Bogus primary rejected -> original cold entry handed back.
        assert_eq!(out.begin_address, 0x2E45E);
        assert_eq!(out.end_address, 0x2E47A);
        assert_eq!(out.unwind_data, 0x100);
    }

    #[test]
    fn primary_in_extent_resolves_normally() {
        // Positive control: an in-range resolved primary passes validation and
        // is returned (the valid cold->hot chain still resolves).
        let mut buf = vec![0u8; 0x400];
        buf[0x100] = 0x01 | (UNW_FLAG_CHAININFO << 3);
        buf[0x102] = 3;
        buf[0x200] = 0x01; // primary, not chained
                           // Hot begin=0x1B790 is inside the [0x1000, 0x40000) window.
        put_runtime_function(&mut buf, 0x10C, 0x1B790, 0x1B7BA, 0x200);

        let cold = RuntimeFunction {
            begin_address: 0x2E45E,
            end_address: 0x2E47A,
            unwind_data: 0x100,
        };
        let out = resolve_chained_unwind(cold, reader(&buf), Some((0x1000, 0x40000)));
        assert_eq!(out.begin_address, 0x1B790);
        assert_eq!(out.end_address, 0x1B7BA);
        assert_eq!(out.unwind_data, 0x200);
    }

    #[test]
    fn primary_end_le_begin_returns_original_func() {
        // A malformed primary with end <= begin must also fail validation even
        // when begin is in range, yielding the original input.
        let mut buf = vec![0u8; 0x400];
        buf[0x100] = 0x01 | (UNW_FLAG_CHAININFO << 3);
        buf[0x102] = 3;
        buf[0x200] = 0x01; // primary, not chained
                           // begin in range but end == begin (degenerate span).
        put_runtime_function(&mut buf, 0x10C, 0x1B790, 0x1B790, 0x200);

        let cold = RuntimeFunction {
            begin_address: 0x2E45E,
            end_address: 0x2E47A,
            unwind_data: 0x100,
        };
        let out = resolve_chained_unwind(cold, reader(&buf), Some((0x1000, 0x40000)));
        assert_eq!(out.begin_address, 0x2E45E);
        assert_eq!(out.unwind_data, 0x100);
    }
}
