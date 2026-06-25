//! Shared bounds-checked image readers for the termsrv.dll patchers.
//!
//! rdprrap patches a LIVE termsrv.dll mapped inside the Terminal Services
//! svchost. Several patchers decode an absolute address (a function start
//! resolved from the exception/unwind table, or a branch target decoded from
//! instruction bytes) and then read raw bytes there to keep disassembling. A
//! mis-decoded or layout-shifted address can resolve OUTSIDE the mapped image;
//! an unbounded read there can fault and crash a critical service.
//!
//! [`read_image_bytes`] is the single guard for those reads: it rejects an
//! address outside the loaded image extent `[img_lo, img_hi)` (from
//! [`patcher::pe::LoadedPe::image_extent`]) and clamps the read length to the
//! bytes actually mapped after the address. Callers degrade to a `debug_log`
//! plus "patch not found"/skip when it returns `None`.

use patcher::patch::debug_log;

/// Read up to `len` bytes at the absolute address `addr`, bounded to the loaded
/// image extent `[img_lo, img_hi)`.
///
/// Returns `None` (and logs) when `addr` is outside the image or no bytes are
/// mapped after it; otherwise clamps the length to the bytes remaining before
/// `img_hi` so a target near the end of the image cannot read past the mapping.
///
/// This is the shared guard for every followed-branch / function-start raw read
/// in the termsrv.dll patchers (SEC-UNSAFE-001 / SEC-PATCH-004 / BF-1 / BF-3):
/// a mis-decoded or layout-shifted address can resolve to an address outside
/// the mapped image, and an unbounded read there can fault and crash the
/// Terminal Services svchost. The `context` label is included in the log so the
/// originating patcher is identifiable in OutputDebugString traces.
pub(crate) fn read_image_bytes(
    context: &str,
    addr: usize,
    len: usize,
    img_lo: usize,
    img_hi: usize,
) -> Option<&'static [u8]> {
    if addr < img_lo || addr >= img_hi {
        debug_log(&format!(
            "{context}: target {addr:#x} outside image [{img_lo:#x},{img_hi:#x})\n"
        ));
        return None;
    }
    let avail = img_hi.saturating_sub(addr);
    if avail == 0 {
        debug_log(&format!("{context}: no mapped bytes at {addr:#x}\n"));
        return None;
    }
    let n = avail.min(len);
    // SAFETY: `addr` has been confirmed to lie within `[img_lo, img_hi)` (the
    // loaded image extent supplied by the caller from `pe.image_extent()`) and
    // `n` is clamped to `img_hi - addr`, so the `n` bytes read here are entirely
    // within the mapped image. The returned slice borrows the live module, which
    // stays mapped for the duration of the calling patcher; the `'static`
    // lifetime is a decode-buffer convenience and the slice is not retained past
    // that call.
    Some(unsafe { std::slice::from_raw_parts(addr as *const u8, n) })
}
