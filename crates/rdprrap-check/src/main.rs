#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

//! rdprrap-check — Rust port of the original rdpwrap `RDPCheck.exe`.
//!
//! Behaviour summary (matches upstream functionally — not pixel-perfect):
//!   1. Require admin elevation (writing to HKLM\...\WinStations\RDP-Tcp).
//!   2. Snapshot & temporarily zero `SecurityLayer` / `UserAuthentication`
//!      via [`nla_guard::NlaGuard`] so an unauthenticated loopback connection
//!      can complete without NLA / CredSSP.
//!   3. Show a 640x480 status window.
//!   4. Spawn `mstsc.exe /v:127.0.0.2:<PortNumber>` and wait for exit.
//!   5. Report success / mapped `discReason` failure to the user.
//!   6. Drop the NLA guard — restores the original registry state even on
//!      panic (Rust RAII guarantees Drop fires during unwind for `Owned` /
//!      stack objects).
//!
//! Non-Windows builds compile to a stub that prints an error and exits 1.

// disc_reason is pure logic (no Windows APIs) so its unit tests can run on
// any host. The other modules are gated to Windows because they touch the
// Win32 API surface.
mod disc_reason;

#[cfg(windows)]
mod elevation;
#[cfg(windows)]
mod gui;
#[cfg(windows)]
mod nla_guard;
#[cfg(windows)]
mod rdp;

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::Context;

    // 1. Elevation check. Without admin we cannot rewrite SecurityLayer /
    //    UserAuthentication on HKLM, so fail fast with a user-visible error
    //    rather than silently crashing inside NlaGuard::install().
    match elevation::is_elevated() {
        Ok(true) => {}
        Ok(false) => {
            show_error_box(
                "Administrator required",
                "rdprrap-check must be run as Administrator to \
                 modify the RDP listener's SecurityLayer / \
                 UserAuthentication values for a loopback test.\n\n\
                 Please relaunch with elevation (right-click → \
                 'Run as administrator').",
            );
            std::process::exit(2);
        }
        Err(e) => {
            show_error_box(
                "Elevation check failed",
                &format!("Could not determine process elevation: {e:#}"),
            );
            std::process::exit(3);
        }
    }

    // 2. Install NLA guard. This is the FIRST owned resource in main() so it
    //    outlives every fallible step below; Drop restores the registry even
    //    if the GUI/mstsc stages panic.
    let guard = nla_guard::NlaGuard::install().context("installing NLA guard")?;
    let port = guard.port();

    // 3. Build the status window.
    let win = match gui::init() {
        Ok(w) => w,
        Err(e) => {
            // Guard will be dropped on return — registry restored.
            return Err(e.context("initialising GUI"));
        }
    };
    gui::set_status(
        &win,
        &format!("Connecting to 127.0.0.2:{port} via mstsc.exe…"),
    );

    // 4. Run the mstsc.exe round-trip synchronously. This blocks the UI thread
    //    while mstsc is up, which is fine: the child window is a separate
    //    top-level mstsc window and our status window stays drawn.
    //
    //    We do the work BEFORE entering the event loop so the status label
    //    reflects the terminal outcome on first paint.
    let outcome = rdp::run_loopback_check(port);
    update_status_from_outcome(&win, &outcome);

    // 5. Run the event loop until the user dismisses the window.
    gui::run_event_loop(&win);

    // 6. Explicit drop for clarity. `guard` would be dropped at scope end
    //    regardless, but naming the drop point documents the ordering.
    drop(guard);
    Ok(())
}

#[cfg(windows)]
fn update_status_from_outcome(win: &gui::MainWindow, outcome: &anyhow::Result<rdp::MstscOutcome>) {
    match outcome {
        Ok(r) if r.is_success() => {
            gui::set_status(win, "Connected. Loopback RDP round-trip succeeded.");
        }
        Ok(r) => {
            let code = r.status.code().unwrap_or(-1);
            // mstsc.exe doesn't forward the protocol discReason verbatim, but
            // the common mapping between its exit codes and MSTSC disconnect
            // reasons is `raw == discReason` on the failure-on-connect path.
            let mapped = disc_reason::describe(code);
            let msg = format!(
                "Connection failed (mstsc exit {code}): {mapped}\n\
                 stderr: {}",
                if r.stderr.trim().is_empty() {
                    "(none)"
                } else {
                    r.stderr.trim()
                }
            );
            gui::set_status(win, &msg);
        }
        Err(e) => {
            gui::set_status(win, &format!("Could not launch mstsc.exe: {e:#}"));
        }
    }
}

#[cfg(windows)]
fn show_error_box(title: &str, body: &str) {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

    let wtitle = to_wide(title);
    let wbody = to_wide(body);
    // SAFETY: Both string pointers are NUL-terminated UTF-16 and live for the
    // duration of the call. `HWND::default()` (NULL) is the documented "no
    // owner" value accepted by MessageBoxW.
    unsafe {
        MessageBoxW(
            HWND::default(),
            PCWSTR(wbody.as_ptr()),
            PCWSTR(wtitle.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

#[cfg(not(windows))]
fn main() {
    eprintln!("rdprrap-check is Windows-only");
    std::process::exit(1);
}
