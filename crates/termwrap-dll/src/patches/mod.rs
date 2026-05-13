#[cfg(target_arch = "aarch64")]
mod arm64;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod intel;

#[cfg(target_arch = "aarch64")]
pub use arm64::apply_patches;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub use intel::apply_patches;

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
use patcher::patch::debug_log;
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
use windows::Win32::Foundation::HMODULE;

/// Unsupported CPU architecture fallback.
///
/// x86, x64, and ARM64 have dedicated runtime patchers. Any other CPU
/// architecture only forwards the original termsrv.dll.
///
/// # Safety
/// `hmod` must be a valid handle to the loaded termsrv.dll.
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
pub unsafe fn apply_patches(_hmod: HMODULE) {
    debug_log(
        "TermWrap: CPU architecture is not supported for runtime patching; \
         forwarding original termsrv.dll without modifications\n",
    );
}
