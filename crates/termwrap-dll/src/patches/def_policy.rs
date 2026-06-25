use patcher::analyze::def_policy::{analyze_defpolicy, SCAN_LEN};
use patcher::patch::{debug_log, write_patch};
use patcher::pe::LoadedPe;

use super::util::read_image_bytes;

/// Apply DefPolicyPatch — patches `CDefPolicy::Query` to allow multiple sessions.
///
/// The patch site is found structurally by the pure `analyze_defpolicy` core: a
/// compare of a `CDefPolicy` struct member that gates the connection decision,
/// immediately followed by a conditional jump. The struct-member displacement is
/// captured dynamically (it shifts between Windows builds), so this survives
/// struct-layout changes that broke the previous hardcoded `0x63c`/`0x638` scan.
///
/// # Safety
/// - All threads must be suspended
/// - `func_rva` must be the RVA of `CDefPolicy::Query`
pub unsafe fn apply(pe: &LoadedPe, func_rva: usize) {
    let base = pe.adjusted_base;
    let ip = base + func_rva;

    // In-memory extent of the loaded termsrv.dll image. `func_rva` is the
    // begin address of a (possibly chained-unwind-resolved) RUNTIME_FUNCTION;
    // on a layout-shifted build that resolution can yield an address outside
    // the mapped image, and an unbounded SCAN_LEN read there can fault and
    // crash the Terminal Services svchost. Bound the read against this span and
    // degrade to "patch not found" rather than trusting the resolved address
    // (SEC-UNSAFE-001 / SEC-PATCH-004).
    let (img_lo, img_hi) = pe.image_extent();

    // SAFETY: bounded by `read_image_bytes`, which validates `ip` lies within
    // `[img_lo, img_hi)` and clamps the read length to the bytes mapped after
    // it; an out-of-image function start degrades to "patch not found".
    let code = match read_image_bytes("DefPolicyPatch", ip, SCAN_LEN, img_lo, img_hi) {
        Some(c) => c,
        None => {
            debug_log("DefPolicyPatch function start outside image\n");
            return;
        }
    };

    match analyze_defpolicy(code, ip as u64) {
        Some(patch) => {
            // SAFETY: `patch.patch_addr` lies within the disassembled function
            // body of the loaded DLL, and threads are suspended by the caller.
            if let Err(e) = unsafe { write_patch(patch.patch_addr as usize, &patch.bytes) } {
                debug_log(&format!("DefPolicyPatch write failed: {e}\n"));
            }
        }
        None => debug_log("DefPolicyPatch not found\n"),
    }
}
