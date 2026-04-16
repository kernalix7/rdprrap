use thiserror::Error;

#[derive(Error, Debug)]
pub enum PatcherError {
    #[error("PE section '{0}' not found")]
    SectionNotFound(String),

    #[error("string pattern '{0}' not found in section")]
    PatternNotFound(String),

    #[error("import image '{0}' not found")]
    ImportImageNotFound(String),

    #[error("import function '{0}' not found")]
    ImportFunctionNotFound(String),

    #[error("function xref not found for target RVA 0x{0:X}")]
    XrefNotFound(u64),

    #[error("patch target not found: {0}")]
    PatchTargetNotFound(String),

    #[error("disassembly failed at RVA 0x{0:X}")]
    DisassemblyFailed(u64),

    #[error("invalid PE: {0}")]
    InvalidPe(String),

    #[cfg(windows)]
    #[error("WriteProcessMemory failed: {0}")]
    WriteFailed(#[from] windows::core::Error),
}
