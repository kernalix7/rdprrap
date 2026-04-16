pub mod disasm;
pub mod error;
pub mod patch;
pub mod pattern;
pub mod pe;

mod disasm_tests;
mod pattern_tests;

pub use error::PatcherError;
