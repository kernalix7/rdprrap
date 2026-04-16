#[cfg(test)]
mod tests {
    use crate::pattern::find_pattern_in_section;
    use crate::pe::SectionInfo;

    /// Helper: create a fake LoadedPe-like setup for testing pattern matching.
    /// Allocates a buffer simulating a PE section and returns a mock LoadedPe.
    fn make_test_section(data: &[u8]) -> (usize, SectionInfo) {
        let base = data.as_ptr() as usize;
        let section = SectionInfo {
            name: ".rdata".to_string(),
            virtual_address: 0, // data starts at base + 0
            virtual_size: data.len() as u32,
            raw_data_offset: 0,
            raw_data_size: data.len() as u32,
        };
        (base, section)
    }

    #[test]
    fn test_find_pattern_aligned() {
        // Pattern at offset 0 (4-byte aligned)
        let mut data = vec![0u8; 64];
        data[0..5].copy_from_slice(b"Hello");

        let (base, section) = make_test_section(&data);
        let pe = crate::pe::LoadedPe {
            base,
            is_64bit: true,
            adjusted_base: base,
        };

        let result = find_pattern_in_section(&pe, &section, b"Hello");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_find_pattern_at_offset() {
        // Pattern at offset 8 (4-byte aligned)
        let mut data = vec![0u8; 64];
        data[8..13].copy_from_slice(b"World");

        let (base, section) = make_test_section(&data);
        let pe = crate::pe::LoadedPe {
            base,
            is_64bit: true,
            adjusted_base: base,
        };

        let result = find_pattern_in_section(&pe, &section, b"World");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 8);
    }

    #[test]
    fn test_find_pattern_not_found() {
        let data = vec![0u8; 64];

        let (base, section) = make_test_section(&data);
        let pe = crate::pe::LoadedPe {
            base,
            is_64bit: true,
            adjusted_base: base,
        };

        let result = find_pattern_in_section(&pe, &section, b"Missing");
        assert!(result.is_err());
    }

    #[test]
    fn test_find_pattern_misaligned_skipped() {
        // Pattern at offset 1 (NOT 4-byte aligned — should be skipped)
        let mut data = vec![0u8; 64];
        data[1..6].copy_from_slice(b"Oops!");

        let (base, section) = make_test_section(&data);
        let pe = crate::pe::LoadedPe {
            base,
            is_64bit: true,
            adjusted_base: base,
        };

        let result = find_pattern_in_section(&pe, &section, b"Oops!");
        assert!(result.is_err(), "misaligned pattern should not be found");
    }

    #[test]
    fn test_find_termsrv_string() {
        // Simulate a .rdata section with a known termsrv.dll string
        let mut data = vec![0u8; 128];
        let pattern = b"CDefPolicy::Query";
        // Place at offset 32 (aligned)
        data[32..32 + pattern.len()].copy_from_slice(pattern);

        let (base, section) = make_test_section(&data);
        let pe = crate::pe::LoadedPe {
            base,
            is_64bit: true,
            adjusted_base: base,
        };

        let result = find_pattern_in_section(
            &pe,
            &section,
            crate::pattern::termsrv_strings::CDEFPOLICY_QUERY,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 32);
    }
}
