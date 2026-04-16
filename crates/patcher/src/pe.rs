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

/// x64 unwind info header
#[derive(Debug, Clone, Copy)]
pub struct UnwindInfo {
    pub version: u8,
    pub flags: u8,
    pub size_of_prolog: u8,
    pub count_of_codes: u8,
    pub frame_register: u8,
    pub frame_offset: u8,
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

    /// Backtrace through chained unwind info to find the root RUNTIME_FUNCTION.
    /// This is needed because some functions have chained unwind entries.
    pub fn backtrace_function(&self, func: &RuntimeFunction) -> RuntimeFunction {
        const RUNTIME_FUNCTION_INDIRECT: u32 = 0x1;
        const UNW_FLAG_CHAININFO: u8 = 0x4;

        let mut current = *func;

        if current.unwind_data & RUNTIME_FUNCTION_INDIRECT != 0 {
            let indirect_ptr = self.base + (current.unwind_data & !1) as usize;
            current = RuntimeFunction {
                begin_address: unsafe { *(indirect_ptr as *const u32) },
                end_address: unsafe { *((indirect_ptr + 4) as *const u32) },
                unwind_data: unsafe { *((indirect_ptr + 8) as *const u32) },
            };
        }

        loop {
            let unwind_ptr = self.base + current.unwind_data as usize;
            let info = unsafe { self.read_unwind_info(unwind_ptr) };

            if info.flags & UNW_FLAG_CHAININFO == 0 {
                break;
            }

            // Chained entry follows the unwind codes (aligned to even count)
            let codes_count = ((info.count_of_codes as usize + 1) & !1) * 2;
            let chain_ptr = unwind_ptr + 4 + codes_count;
            current = RuntimeFunction {
                begin_address: unsafe { *(chain_ptr as *const u32) },
                end_address: unsafe { *((chain_ptr + 4) as *const u32) },
                unwind_data: unsafe { *((chain_ptr + 8) as *const u32) },
            };
        }

        current
    }

    /// Read unwind info from a pointer
    ///
    /// # Safety
    /// `ptr` must point to a valid UNWIND_INFO structure
    unsafe fn read_unwind_info(&self, ptr: usize) -> UnwindInfo {
        let byte0 = *(ptr as *const u8);
        let byte1 = *((ptr + 1) as *const u8);
        let byte2 = *((ptr + 2) as *const u8);
        let byte3 = *((ptr + 3) as *const u8);

        UnwindInfo {
            version: byte0 & 0x7,
            flags: (byte0 >> 3) & 0x1F,
            size_of_prolog: byte1,
            count_of_codes: byte2,
            frame_register: byte3 & 0xF,
            frame_offset: (byte3 >> 4) & 0xF,
        }
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
