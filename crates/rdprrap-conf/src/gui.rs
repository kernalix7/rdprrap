//! Main configuration window — layout, event wiring, and state machine.
//!
//! We build controls programmatically rather than via `native-windows-derive`
//! because the live-diagnostics timer needs to shuttle state between the
//! timer callback and the individual labels; a flat builder keeps the control
//! map explicit.
//!
//! Layout strategy: two absolute-positioned `GroupBox`es on the left/top of
//! the window, with a `GridLayout` holding the label pairs inside each group
//! and a simple vertical stack of buttons at the bottom. native-windows-gui
//! `GridLayout` handles resizing the text rows automatically.

#![allow(clippy::too_many_lines)]

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use anyhow::Result;
use native_windows_gui as nwg;

use crate::diag::{Diagnostics, SupportLevel, WrapperState};
use crate::elevation::is_elevated;
use crate::listener::ListenerState;
use crate::service_query::ServiceState;
use crate::settings::{read_settings, write_settings, AuthMode, Settings};

/// Timer tick interval. The original RDPConf uses 250 ms, which is wasteful
/// — service state rarely changes that fast and each tick performs a handful
/// of RPC calls. We poll every 1 s, which still feels immediate to humans
/// while cutting registry / SCM / winsta traffic 4x.
const TIMER_INTERVAL_MS: u32 = 1000;

/// Top-level window handle + controls + shared mutable state.
///
/// `RefCell` is used for the *current UI model* (read at start-up, mutated by
/// event handlers, committed by Apply/OK). `Cell<bool>` holds the cheap
/// "dirty" flag so we can toggle it without borrowing anything else.
pub struct App {
    // Window + resources.
    pub window: nwg::Window,
    /// RAII owner for the per-window font. The raw `HFONT` is released on
    /// `Drop`, so we must keep it alive for the lifetime of the window even
    /// though we never read it back after creation.
    #[allow(dead_code)]
    pub font: nwg::Font,
    pub timer: nwg::AnimationTimer,

    // Diagnostics labels.
    pub lbl_wrapper_state: nwg::Label,
    pub lbl_wrapper_version: nwg::Label,
    pub lbl_service_state: nwg::Label,
    pub lbl_termsrv_version: nwg::Label,
    pub lbl_listener_state: nwg::Label,
    pub lbl_support_level: nwg::Label,

    // Settings controls.
    pub chk_enable_rdp: nwg::CheckBox,
    pub spn_port: nwg::NumberSelect,
    pub chk_single_session: nwg::CheckBox,
    pub chk_hide_users: nwg::CheckBox,
    pub chk_allow_custom: nwg::CheckBox,
    pub rg_auth_gui: nwg::RadioButton,
    pub rg_auth_default: nwg::RadioButton,
    pub rg_auth_nla: nwg::RadioButton,
    pub rg_shadow: [nwg::RadioButton; 5],

    // Buttons.
    pub btn_ok: nwg::Button,
    pub btn_cancel: nwg::Button,
    pub btn_apply: nwg::Button,
    pub btn_license: nwg::Button,

    // Shared mutable state.
    pub settings: RefCell<Settings>,
    pub previous_port: Cell<u16>,
    pub dirty: Cell<bool>,
    pub elevated: Cell<bool>,
}

impl App {
    /// Build the window, apply initial diagnostics, load settings, and start
    /// the 1 s polling timer. Event handlers are attached in `run()`.
    pub fn build() -> Result<Rc<Self>> {
        nwg::init().map_err(|e| anyhow::anyhow!("nwg::init failed: {e}"))?;

        let mut font = nwg::Font::default();
        nwg::Font::builder()
            .size(15)
            .family("Segoe UI")
            .build(&mut font)
            .map_err(|e| anyhow::anyhow!("font build failed: {e}"))?;
        // `nwg::Font` is not `Clone`, and `set_global_default` takes the Font
        // by value. Build a second identical font for the global default so we
        // can still keep a handle on `self.font` for future use.
        let mut global_font = nwg::Font::default();
        nwg::Font::builder()
            .size(15)
            .family("Segoe UI")
            .build(&mut global_font)
            .map_err(|e| anyhow::anyhow!("global font build failed: {e}"))?;
        nwg::Font::set_global_default(Some(global_font));

        let mut window = nwg::Window::default();
        nwg::Window::builder()
            .size((420, 560))
            .position((300, 300))
            .title("rdprrap Configuration")
            .flags(nwg::WindowFlags::WINDOW | nwg::WindowFlags::VISIBLE)
            .build(&mut window)
            .map_err(|e| anyhow::anyhow!("window build failed: {e}"))?;

        // --- Diagnostics frame -------------------------------------------------
        let mut grp_diag = nwg::Frame::default();
        nwg::Frame::builder()
            .parent(&window)
            .position((8, 8))
            .size((400, 170))
            .build(&mut grp_diag)
            .ok();

        let mk_label = |parent: &nwg::Frame, text: &str, x: i32, y: i32, w: i32| -> nwg::Label {
            let mut l = nwg::Label::default();
            nwg::Label::builder()
                .parent(parent)
                .text(text)
                .position((x, y))
                .size((w, 20))
                .build(&mut l)
                .ok();
            l
        };

        let _ = mk_label(&grp_diag, "Wrapper state:", 8, 8, 140);
        let lbl_wrapper_state = mk_label(&grp_diag, "", 150, 8, 240);
        let _ = mk_label(&grp_diag, "Wrapper version:", 8, 32, 140);
        let lbl_wrapper_version = mk_label(&grp_diag, "", 150, 32, 240);
        let _ = mk_label(&grp_diag, "Service state:", 8, 56, 140);
        let lbl_service_state = mk_label(&grp_diag, "", 150, 56, 240);
        let _ = mk_label(&grp_diag, "TermSrv version:", 8, 80, 140);
        let lbl_termsrv_version = mk_label(&grp_diag, "", 150, 80, 240);
        let _ = mk_label(&grp_diag, "Listener state:", 8, 104, 140);
        let lbl_listener_state = mk_label(&grp_diag, "", 150, 104, 240);
        let _ = mk_label(&grp_diag, "Support level:", 8, 128, 140);
        let lbl_support_level = mk_label(&grp_diag, "", 150, 128, 240);

        // --- General Settings frame -------------------------------------------
        let mut grp_general = nwg::Frame::default();
        nwg::Frame::builder()
            .parent(&window)
            .position((8, 186))
            .size((400, 140))
            .build(&mut grp_general)
            .ok();

        let mut chk_enable_rdp = nwg::CheckBox::default();
        nwg::CheckBox::builder()
            .parent(&grp_general)
            .text("Enable Remote Desktop")
            .position((8, 8))
            .size((300, 20))
            .build(&mut chk_enable_rdp)
            .ok();

        let mut _lbl_port = nwg::Label::default();
        nwg::Label::builder()
            .parent(&grp_general)
            .text("RDP Port:")
            .position((8, 32))
            .size((80, 20))
            .build(&mut _lbl_port)
            .ok();

        let mut spn_port = nwg::NumberSelect::default();
        nwg::NumberSelect::builder()
            .parent(&grp_general)
            .position((90, 30))
            .size((80, 22))
            .value_int(3389)
            .min_int(0)
            .max_int(65_535)
            .build(&mut spn_port)
            .ok();

        let mut chk_single_session = nwg::CheckBox::default();
        nwg::CheckBox::builder()
            .parent(&grp_general)
            .text("Single session per user")
            .position((8, 58))
            .size((300, 20))
            .build(&mut chk_single_session)
            .ok();

        let mut chk_hide_users = nwg::CheckBox::default();
        nwg::CheckBox::builder()
            .parent(&grp_general)
            .text("Hide users on logon screen")
            .position((8, 82))
            .size((300, 20))
            .build(&mut chk_hide_users)
            .ok();

        let mut chk_allow_custom = nwg::CheckBox::default();
        nwg::CheckBox::builder()
            .parent(&grp_general)
            .text("Allow custom programs to start")
            .position((8, 106))
            .size((300, 20))
            .build(&mut chk_allow_custom)
            .ok();

        // --- Authentication Mode frame ----------------------------------------
        let mut grp_auth = nwg::Frame::default();
        nwg::Frame::builder()
            .parent(&window)
            .position((8, 334))
            .size((200, 90))
            .build(&mut grp_auth)
            .ok();

        let mut rg_auth_gui = nwg::RadioButton::default();
        nwg::RadioButton::builder()
            .parent(&grp_auth)
            .text("GUI authentication only")
            .position((8, 4))
            .size((180, 20))
            .build(&mut rg_auth_gui)
            .ok();
        let mut rg_auth_default = nwg::RadioButton::default();
        nwg::RadioButton::builder()
            .parent(&grp_auth)
            .text("Default RDP authentication")
            .position((8, 28))
            .size((180, 20))
            .build(&mut rg_auth_default)
            .ok();
        let mut rg_auth_nla = nwg::RadioButton::default();
        nwg::RadioButton::builder()
            .parent(&grp_auth)
            .text("Network Level Authentication")
            .position((8, 52))
            .size((190, 20))
            .build(&mut rg_auth_nla)
            .ok();

        // --- Session Shadowing frame ------------------------------------------
        let mut grp_shadow = nwg::Frame::default();
        nwg::Frame::builder()
            .parent(&window)
            .position((210, 334))
            .size((200, 140))
            .build(&mut grp_shadow)
            .ok();

        let shadow_labels = [
            "Disable",
            "Full access with user's permission",
            "Full access without permission",
            "View only with user's permission",
            "View only without permission",
        ];
        let mut rg_shadow: [nwg::RadioButton; 5] = Default::default();
        for (i, lbl) in shadow_labels.iter().enumerate() {
            nwg::RadioButton::builder()
                .parent(&grp_shadow)
                .text(lbl)
                .position((8, 4 + (i as i32) * 22))
                .size((190, 20))
                .build(&mut rg_shadow[i])
                .ok();
        }

        // --- Buttons ----------------------------------------------------------
        let mut btn_ok = nwg::Button::default();
        nwg::Button::builder()
            .parent(&window)
            .text("OK")
            .position((8, 486))
            .size((90, 28))
            .build(&mut btn_ok)
            .ok();
        let mut btn_cancel = nwg::Button::default();
        nwg::Button::builder()
            .parent(&window)
            .text("Cancel")
            .position((108, 486))
            .size((90, 28))
            .build(&mut btn_cancel)
            .ok();
        let mut btn_apply = nwg::Button::default();
        nwg::Button::builder()
            .parent(&window)
            .text("Apply")
            .position((210, 486))
            .size((90, 28))
            .build(&mut btn_apply)
            .ok();
        btn_apply.set_enabled(false);
        let mut btn_license = nwg::Button::default();
        nwg::Button::builder()
            .parent(&window)
            .text("License")
            .position((312, 486))
            .size((90, 28))
            .build(&mut btn_license)
            .ok();

        // --- Timer ------------------------------------------------------------
        let mut timer = nwg::AnimationTimer::default();
        nwg::AnimationTimer::builder()
            .parent(&window)
            .interval(std::time::Duration::from_millis(u64::from(
                TIMER_INTERVAL_MS,
            )))
            .active(true)
            .build(&mut timer)
            .ok();

        // Initial settings + elevation check.
        let initial = read_settings().unwrap_or_default();
        let elevated = is_elevated().unwrap_or(false);

        let app = App {
            window,
            font,
            timer,
            lbl_wrapper_state,
            lbl_wrapper_version,
            lbl_service_state,
            lbl_termsrv_version,
            lbl_listener_state,
            lbl_support_level,
            chk_enable_rdp,
            spn_port,
            chk_single_session,
            chk_hide_users,
            chk_allow_custom,
            rg_auth_gui,
            rg_auth_default,
            rg_auth_nla,
            rg_shadow,
            btn_ok,
            btn_cancel,
            btn_apply,
            btn_license,
            previous_port: Cell::new(initial.rdp_port),
            settings: RefCell::new(initial),
            dirty: Cell::new(false),
            elevated: Cell::new(elevated),
        };

        let app = Rc::new(app);
        app.apply_settings_to_ui();
        app.refresh_diag();

        if !elevated {
            // In read-only mode the Apply button stays disabled no matter what.
            app.btn_apply.set_enabled(false);
            app.window
                .set_text("rdprrap Configuration (read-only — not elevated)");
        }

        Ok(app)
    }

    /// Run the native event loop until the window is closed.
    pub fn run(self: &Rc<Self>) {
        let weak = Rc::downgrade(self);
        let handler =
            nwg::full_bind_event_handler(&self.window.handle, move |evt, _data, handle| {
                let Some(app) = weak.upgrade() else { return };
                app.handle_event(evt, handle);
            });

        nwg::dispatch_thread_events();
        nwg::unbind_event_handler(&handler);
    }

    fn handle_event(&self, evt: nwg::Event, handle: nwg::ControlHandle) {
        use nwg::Event as E;
        match evt {
            E::OnWindowClose => {
                if self.dirty.get() {
                    nwg::simple_message(
                        "rdprrap Configuration",
                        "Settings not saved. Closing without applying changes.",
                    );
                }
                nwg::stop_thread_dispatch();
            }
            E::OnTimerTick if handle == self.timer.handle => {
                self.refresh_diag();
            }
            E::OnButtonClick => {
                // NWG fires `OnButtonClick` for Button, CheckBox, and RadioButton
                // alike — disambiguate by handle. Any non-button is treated as a
                // settings edit (dirty + sync model).
                if handle == self.btn_ok.handle {
                    if self.try_write_and_toast() {
                        nwg::stop_thread_dispatch();
                    }
                } else if handle == self.btn_cancel.handle {
                    if self.dirty.get() {
                        nwg::simple_message("rdprrap Configuration", "Settings not saved.");
                    }
                    nwg::stop_thread_dispatch();
                } else if handle == self.btn_apply.handle {
                    let _ = self.try_write_and_toast();
                } else if handle == self.btn_license.handle {
                    show_license_dialog();
                } else {
                    // Checkbox / radio-button click.
                    self.pull_ui_into_settings();
                    self.mark_dirty();
                }
            }
            E::OnButtonDoubleClick => {}
            E::OnComboxBoxSelection => {
                self.pull_ui_into_settings();
                self.mark_dirty();
            }
            _ => {}
        }
    }

    /// Read current UI control states back into the `Settings` model.
    fn pull_ui_into_settings(&self) {
        let mut s = self.settings.borrow_mut();
        s.enable_rdp = self.chk_enable_rdp.check_state() == nwg::CheckBoxState::Checked;
        let v = match self.spn_port.data() {
            nwg::NumberSelectData::Int { value, .. } => value,
            nwg::NumberSelectData::Float { value, .. } => value as i64,
        };
        s.rdp_port = u16::try_from(v.clamp(0, 65_535)).unwrap_or(3389);
        s.single_session_per_user =
            self.chk_single_session.check_state() == nwg::CheckBoxState::Checked;
        s.hide_users_on_logon = self.chk_hide_users.check_state() == nwg::CheckBoxState::Checked;
        s.allow_custom_programs =
            self.chk_allow_custom.check_state() == nwg::CheckBoxState::Checked;
        s.auth = if self.rg_auth_gui.check_state() == nwg::RadioButtonState::Checked {
            AuthMode::GuiOnly
        } else if self.rg_auth_nla.check_state() == nwg::RadioButtonState::Checked {
            AuthMode::NetworkLevel
        } else {
            AuthMode::Default
        };
        for (i, rb) in self.rg_shadow.iter().enumerate() {
            if rb.check_state() == nwg::RadioButtonState::Checked {
                s.shadow = u8::try_from(i).unwrap_or(0);
                break;
            }
        }
    }

    /// Apply the in-memory `Settings` model to every control.
    fn apply_settings_to_ui(&self) {
        let s = self.settings.borrow();
        self.chk_enable_rdp
            .set_check_state(bool_to_check(s.enable_rdp));
        // Preserve existing step/min/max; only overwrite the current value.
        let new_data = match self.spn_port.data() {
            nwg::NumberSelectData::Int { step, max, min, .. } => nwg::NumberSelectData::Int {
                value: i64::from(s.rdp_port),
                step,
                max,
                min,
            },
            other => other, // Float variant is never used for port — leave as-is.
        };
        self.spn_port.set_data(new_data);
        self.chk_single_session
            .set_check_state(bool_to_check(s.single_session_per_user));
        self.chk_hide_users
            .set_check_state(bool_to_check(s.hide_users_on_logon));
        self.chk_allow_custom
            .set_check_state(bool_to_check(s.allow_custom_programs));
        self.rg_auth_gui
            .set_check_state(radio_to_state(matches!(s.auth, AuthMode::GuiOnly)));
        self.rg_auth_default
            .set_check_state(radio_to_state(matches!(s.auth, AuthMode::Default)));
        self.rg_auth_nla
            .set_check_state(radio_to_state(matches!(s.auth, AuthMode::NetworkLevel)));
        for (i, rb) in self.rg_shadow.iter().enumerate() {
            rb.set_check_state(radio_to_state(i == s.shadow as usize));
        }
    }

    fn mark_dirty(&self) {
        self.dirty.set(true);
        if self.elevated.get() {
            self.btn_apply.set_enabled(true);
        }
    }

    /// Commit the current UI model via `write_settings`. Returns `true` on a
    /// clean commit; `false` (with a toast) if any per-field failure occurred.
    fn try_write_and_toast(&self) -> bool {
        if !self.elevated.get() {
            nwg::simple_message(
                "rdprrap Configuration",
                "Cannot write settings — this process is not elevated.",
            );
            return false;
        }
        self.pull_ui_into_settings();
        let s = self.settings.borrow().clone();
        let prev_port = self.previous_port.get();
        let res = write_settings(&s, prev_port);
        if res.is_clean() {
            self.previous_port.set(s.rdp_port);
            self.dirty.set(false);
            self.btn_apply.set_enabled(false);
            true
        } else {
            let body = format!(
                "Some settings could not be saved:\n\n- {}",
                res.failures.join("\n- ")
            );
            nwg::simple_message("rdprrap Configuration", &body);
            // Successful fields were still written — clear dirty only if no
            // further edits happened concurrently, which we can't detect from
            // here. Conservative: keep dirty=true so the user can retry Apply.
            false
        }
    }

    /// Recompute diagnostics and refresh the labels. Called from the 1 s timer.
    fn refresh_diag(&self) {
        let d = Diagnostics::collect();
        self.lbl_wrapper_state.set_text(d.wrapper.label());
        self.lbl_wrapper_version
            .set_text(d.wrapper_version.as_deref().unwrap_or("N/A"));
        self.lbl_service_state.set_text(d.service.label());
        self.lbl_termsrv_version
            .set_text(d.termsrv_version.as_deref().unwrap_or("N/A"));
        self.lbl_listener_state.set_text(d.listener.label());
        self.lbl_support_level.set_text(d.support.label());

        // Colouring: windows-rs / nwg doesn't expose SetTextColor for labels
        // without subclassing; the original rdpwrap configurator relies on
        // TColor. For a drop-in replacement we keep the semantic signal in
        // the text itself (e.g. "Installed" vs "Not installed") and let the
        // label colour stay system default. The `color()` helpers on the
        // enums remain available for a future owner-draw pass.
        let _ = (WrapperState::Installed.color(), SupportLevel::Fully.color());
        let _ = (
            ServiceState::Running.label(),
            ListenerState::Listening.label(),
        );
    }
}

fn bool_to_check(b: bool) -> nwg::CheckBoxState {
    if b {
        nwg::CheckBoxState::Checked
    } else {
        nwg::CheckBoxState::Unchecked
    }
}

fn radio_to_state(b: bool) -> nwg::RadioButtonState {
    if b {
        nwg::RadioButtonState::Checked
    } else {
        nwg::RadioButtonState::Unchecked
    }
}

/// Simple modal presenting the project license text.
fn show_license_dialog() {
    const TEXT: &str = "rdprrap — MIT License\n\n\
        Copyright (c) 2026 rdprrap contributors\n\n\
        Permission is hereby granted, free of charge, to any person obtaining a copy \
        of this software and associated documentation files (the \"Software\"), to deal \
        in the Software without restriction, including without limitation the rights \
        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell \
        copies of the Software, and to permit persons to whom the Software is \
        furnished to do so, subject to the following conditions:\n\n\
        The above copyright notice and this permission notice shall be included in all \
        copies or substantial portions of the Software.\n\n\
        THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR \
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, \
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE \
        AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER \
        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, \
        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE \
        SOFTWARE.";

    nwg::simple_message("rdprrap License", TEXT);
}
