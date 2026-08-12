//! Global hotkey (Ctrl/Cmd+Shift+V) -> active window title -> daemon match ->
//! enigo keyboard injection. rdev::listen is used on Wayland too; GNOME/KDE's
//! security model may block it entirely there (compositor-level, not
//! something this code can work around) - a silent "no key events ever
//! received" in the logs means check udev/input-group permissions. Active
//! window title has no Wayland equivalent at all (X11-only; None otherwise).

use crate::daemon::DaemonMsg;
use enigo::{Direction, Enigo, Key, Keyboard, Settings};
use rdev::{Event, EventType, Key as RdevKey};
use std::collections::HashSet;
use tokio::sync::mpsc;

/// rdev::listen blocks, so this runs on its own OS thread, not a tokio task.
pub fn spawn_watcher(tx: mpsc::Sender<DaemonMsg>) {
    std::thread::spawn(move || {
        let mut pressed: HashSet<RdevKey> = HashSet::new();

        let callback = move |event: Event| {
            match event.event_type {
                EventType::KeyPress(key) => {
                    pressed.insert(key);

                    if is_autofill_hotkey(&pressed) {
                        let title = get_active_window_title().unwrap_or_default();
                        if let Err(e) = tx.blocking_send(DaemonMsg::AutofillTriggered {
                            window_title: title,
                        }) {
                            log::warn!("autofill: failed to notify daemon: {e}");
                        }
                    }
                }
                EventType::KeyRelease(key) => {
                    pressed.remove(&key);
                }
                _ => {}
            }
        };

        log::info!("autofill hotkey watcher started (rdev::listen)");
        if let Err(e) = rdev::listen(callback) {
            log::error!(
                "rdev::listen failed: {e:?} — on Linux this usually means missing input \
                 device permissions (add user to the 'input' group) or a Wayland compositor \
                 that blocks global key listening entirely"
            );
        }
    });
}

// TODO: read hotkey from config (AppConfig.hotkey in commands/config.rs); hardcoded for now
fn is_autofill_hotkey(pressed: &HashSet<RdevKey>) -> bool {
    let ctrl_or_meta = pressed.contains(&RdevKey::ControlLeft)
        || pressed.contains(&RdevKey::ControlRight)
        || pressed.contains(&RdevKey::MetaLeft)
        || pressed.contains(&RdevKey::MetaRight);

    let shift = pressed.contains(&RdevKey::ShiftLeft) || pressed.contains(&RdevKey::ShiftRight);
    let v = pressed.contains(&RdevKey::KeyV);

    ctrl_or_meta && shift && v
}

/// tab_between: type username, Tab, type password (typical login form layout).
pub fn inject_credentials(
    username: &str,
    password: &str,
    tab_between: bool,
) -> crate::error::VaultResult<()> {
    std::thread::sleep(std::time::Duration::from_millis(150));

    let mut enigo = Enigo::new(&Settings::default())
        .map_err(|e| crate::error::VaultError::Internal(format!("enigo init failed: {e:?}")))?;

    if !username.is_empty() {
        enigo
            .text(username)
            .map_err(|e| crate::error::VaultError::Internal(format!("failed to type username: {e:?}")))?;
    }

    if tab_between {
        enigo
            .key(Key::Tab, Direction::Click)
            .map_err(|e| crate::error::VaultError::Internal(format!("failed to press Tab: {e:?}")))?;
    }

    if !password.is_empty() {
        enigo
            .text(password)
            .map_err(|e| crate::error::VaultError::Internal(format!("failed to type password: {e:?}")))?;
    }

    Ok(())
}

pub fn get_active_window_title() -> Option<String> {
    #[cfg(target_os = "windows")]
    { windows_impl::get_active_window_title() }

    #[cfg(target_os = "macos")]
    { macos_impl::get_active_window_title() }

    #[cfg(target_os = "linux")]
    { linux_impl::get_active_window_title() }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    { None }
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW};

    pub fn get_active_window_title() -> Option<String> {
        unsafe {
            let hwnd: HWND = GetForegroundWindow();
            if hwnd == 0 {
                return None;
            }

            let mut buf = [0u16; 512];
            let len = GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
            if len <= 0 {
                return None;
            }

            Some(String::from_utf16_lossy(&buf[..len as usize]))
        }
    }
}

#[cfg(target_os = "macos")]
mod macos_impl {
    // Lowest-confidence code in this project: objc2-app-kit's API surface shifts
    // between versions. If this fails to compile, check the method signatures
    // against the currently pinned objc2-app-kit docs.
    // frontmostApplication.localizedName needs no special permission; going
    // beyond "which app" (e.g. which document) would need Accessibility + AXUIElement.
    use objc2_app_kit::NSWorkspace;

    pub fn get_active_window_title() -> Option<String> {
        unsafe {
            let workspace = NSWorkspace::sharedWorkspace();
            let app = workspace.frontmostApplication()?;
            let name = app.localizedName()?;
            Some(name.to_string())
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{AtomEnum, ConnectionExt};

    pub fn get_active_window_title() -> Option<String> {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            log::debug!("autofill: running under Wayland, active window title unavailable");
            return None;
        }

        get_active_window_title_x11().ok()
    }

    fn get_active_window_title_x11() -> Result<Option<String>, Box<dyn std::error::Error>> {
        let (conn, screen_num) = x11rb::connect(None)?;
        let root = conn.setup().roots[screen_num].root;

        let net_active_window = conn.intern_atom(false, b"_NET_ACTIVE_WINDOW")?.reply()?.atom;
        let net_wm_name = conn.intern_atom(false, b"_NET_WM_NAME")?.reply()?.atom;
        let utf8_string = conn.intern_atom(false, b"UTF8_STRING")?.reply()?.atom;

        let active_reply = conn
            .get_property(false, root, net_active_window, AtomEnum::WINDOW, 0, 1)?
            .reply()?;

        let active_window = match active_reply.value32().and_then(|mut it| it.next()) {
            Some(w) if w != 0 => w,
            _ => return Ok(None),
        };

        let title_reply = conn
            .get_property(false, active_window, net_wm_name, utf8_string, 0, u32::MAX)?
            .reply()?;

        Ok(String::from_utf8(title_reply.value).ok())
    }
}
