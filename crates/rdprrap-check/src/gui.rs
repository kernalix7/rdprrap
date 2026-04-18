//! Minimal native-windows-gui front-end for rdprrap-check.
//!
//! Layout intentionally mirrors the essentials of the original 640x480
//! `Local RDP Checker` Delphi VCL form, but drops the embedded MSTSCAX
//! control — we spawn `mstsc.exe` out-of-process instead (see `rdp.rs`).
//!
//! The window exposes:
//!   * A title:  "Local RDP Checker — rdprrap"
//!   * A status label centred in the window that reports progress:
//!     "Connecting to 127.0.0.2…" → "Connected." | error details
//!   * An OK / Close button that terminates the event loop.
//!
//! The window is constructed with a builder instead of NWG's derive macro so
//! we can keep the crate's `#![deny(warnings)]`/clippy posture clean without
//! pulling the macro-generated code through lint exceptions.

use anyhow::{Context, Result};
use native_windows_gui as nwg;

/// Public handle returned by [`init`]. The caller holds this across the
/// event loop; dropping it destroys all child controls.
pub struct MainWindow {
    pub window: nwg::Window,
    pub status: nwg::Label,
    pub close_button: nwg::Button,
}

/// Initialise NWG (fonts, default ui) and construct the main window.
///
/// Must be called once on the UI thread. Subsequent calls that try to
/// double-initialise NWG will return an error.
pub fn init() -> Result<MainWindow> {
    nwg::init().map_err(|e| anyhow::anyhow!("nwg::init failed: {e:?}"))?;

    let mut window = nwg::Window::default();
    nwg::Window::builder()
        .size((640, 480))
        .position((300, 200))
        .title("Local RDP Checker — rdprrap")
        .flags(nwg::WindowFlags::WINDOW | nwg::WindowFlags::VISIBLE)
        .build(&mut window)
        .map_err(|e| anyhow::anyhow!("Window::build failed: {e:?}"))
        .context("building main window")?;

    let mut status = nwg::Label::default();
    nwg::Label::builder()
        .text("Initialising…")
        .size((600, 40))
        .position((20, 200))
        .parent(&window)
        .build(&mut status)
        .map_err(|e| anyhow::anyhow!("Label::build failed: {e:?}"))
        .context("building status label")?;

    let mut close_button = nwg::Button::default();
    nwg::Button::builder()
        .text("Close")
        .size((100, 32))
        .position((270, 410))
        .parent(&window)
        .build(&mut close_button)
        .map_err(|e| anyhow::anyhow!("Button::build failed: {e:?}"))
        .context("building close button")?;

    Ok(MainWindow {
        window,
        status,
        close_button,
    })
}

/// Update the centred status label text.
pub fn set_status(w: &MainWindow, text: &str) {
    w.status.set_text(text);
}

/// Dispatch messages until the window is closed. Returns when the user
/// clicks Close or X.
pub fn run_event_loop(w: &MainWindow) {
    let window_handle = w.window.handle;
    let close_handle = w.close_button.handle;
    let handler = nwg::full_bind_event_handler(&window_handle, move |evt, _data, handle| {
        use nwg::Event as E;
        match evt {
            E::OnButtonClick if handle == close_handle => {
                nwg::stop_thread_dispatch();
            }
            E::OnWindowClose if handle == window_handle => {
                nwg::stop_thread_dispatch();
            }
            _ => {}
        }
    });
    nwg::dispatch_thread_events();
    nwg::unbind_event_handler(&handler);
}
