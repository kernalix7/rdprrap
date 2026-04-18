//! `rdprrap-conf` — Rust replacement for the original Delphi `RDPConf.exe`.
//!
//! Windows-only binary. On any other platform the process exits with a
//! user-facing message so that `cargo build` on Linux CI still succeeds.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(windows)]
mod diag;
#[cfg(windows)]
mod elevation;
#[cfg(windows)]
mod gui;
#[cfg(windows)]
mod listener;
#[cfg(windows)]
mod registry;
#[cfg(windows)]
mod service_query;
#[cfg(windows)]
mod settings;
#[cfg(windows)]
mod version;

#[cfg(windows)]
fn main() {
    if let Err(e) = run() {
        // Surface the top-level error in a message box so the failure is
        // actually visible even when launched from Explorer.
        let msg = format!("rdprrap-conf failed to start:\n\n{e}");
        native_windows_gui::error_message("rdprrap Configuration", &msg);
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    let app = gui::App::build()?;
    app.run();
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("rdprrap-conf is Windows-only");
    std::process::exit(1);
}
