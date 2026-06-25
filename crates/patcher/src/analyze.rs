//! Pure, side-effect-free patch-site analyzers.
//!
//! Each submodule decodes a specific termsrv.dll function body (supplied as a
//! byte slice plus the address it is loaded at) and returns a descriptor naming
//! the patch site and the bytes that would be written there. The analyzers do no
//! memory writes and depend only on `iced-x86` plus [`crate::encode`] /
//! [`crate::disasm`], so they compile and unit-test on any host and are reused
//! both by the Windows-only wrapper crates (which perform the actual write) and
//! by the `offset-finder` patch-site dry-run.

pub mod def_policy;
pub mod property_device;
