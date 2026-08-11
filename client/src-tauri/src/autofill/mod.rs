/// Autofill 模块
///
/// 职责：
///   1. 监听全局热键（默认 Ctrl+Shift+V，macOS 上是 Cmd+Shift+V）
///   2. 获取当前活动窗口标题
///   3. 通知 daemon 匹配候选凭据
///   4. 用户选择后，用 enigo 模拟键盘将凭据注入目标窗口
///
/// 平台差异（按需求明确要求：Linux Wayland 也统一用 rdev，不做 xdg-desktop-portal 降级）：
///   - 热键监听：三平台统一走 rdev::listen，包括 Wayland。
///     现实情况是：GNOME/KDE 在 Wayland 下出于安全模型通常会拦截全局按键监听
///     （rdev 底层依赖的是 evdev/libinput 或旧式 X11 grab 机制，在纯 Wayland
///     合成器下可能完全收不到事件，或者需要用户把程序加入 input group 并有
///     /dev/input/* 读权限）。这是合成器的安全策略决定的，不是 rdev 或本实现
///     能绕过的限制 —— 这里不做检测和提示分支，出问题时日志里能看到"从未收到
///     任何按键事件"，届时用户需要自行检查 udev/权限配置。
///   - 活动窗口标题获取：
///       Windows → GetForegroundWindow + GetWindowTextW
///       macOS   → NSWorkspace.frontmostApplication.localizedName
///       Linux   → 仅 X11（_NET_ACTIVE_WINDOW + _NET_WM_NAME via x11rb）；
///                 Wayland 下没有标准协议能拿到这个信息，直接返回 None
///                 （autofill 仍然可以工作，只是无法根据窗口标题自动匹配凭据，
///                 需要用户手动从列表选择）。

use crate::daemon::DaemonMsg;
use enigo::{Direction, Enigo, Key, Keyboard, Settings};
use rdev::{Event, EventType, Key as RdevKey};
use std::collections::HashSet;
use tokio::sync::mpsc;

/// 启动全局热键监听（rdev::listen 是同步阻塞调用，必须跑在独立 OS 线程，
/// 不能直接扔进 tokio 的 async task）
pub fn spawn_watcher(tx: mpsc::Sender<DaemonMsg>) {
    std::thread::spawn(move || {
        let mut pressed: HashSet<RdevKey> = HashSet::new();

        let callback = move |event: Event| {
            match event.event_type {
                EventType::KeyPress(key) => {
                    pressed.insert(key);

                    if is_autofill_hotkey(&pressed) {
                        let title = get_active_window_title().unwrap_or_default();
                        // rdev 的回调是同步上下文，用 blocking_send 往 tokio channel 里塞消息
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
            // 常见原因：Linux 下没有 /dev/input 读权限，或者 Wayland 合成器完全拦截了监听
            log::error!(
                "rdev::listen failed: {e:?} — on Linux this usually means missing input \
                 device permissions (add user to the 'input' group) or a Wayland compositor \
                 that blocks global key listening entirely"
            );
        }
    });
}

/// 判断当前按下的按键组合是否命中 autofill 热键（Ctrl+Shift+V 或 Cmd/Meta+Shift+V）
///
/// TODO: 从配置读取自定义热键（当前硬编码），配置结构见 commands/config.rs 的 AppConfig.hotkey
fn is_autofill_hotkey(pressed: &HashSet<RdevKey>) -> bool {
    let ctrl_or_meta = pressed.contains(&RdevKey::ControlLeft)
        || pressed.contains(&RdevKey::ControlRight)
        || pressed.contains(&RdevKey::MetaLeft)   // macOS Cmd / Linux Super
        || pressed.contains(&RdevKey::MetaRight);

    let shift = pressed.contains(&RdevKey::ShiftLeft) || pressed.contains(&RdevKey::ShiftRight);
    let v = pressed.contains(&RdevKey::KeyV);

    ctrl_or_meta && shift && v
}

// ─── 凭据注入 ─────────────────────────────────────────────────────────────────

/// 将凭据注入当前活动窗口。
/// tab_between: true = 先输入 username，按 Tab，再输入 password（多数登录表单的标准布局）
pub fn inject_credentials(
    username: &str,
    password: &str,
    tab_between: bool,
) -> crate::error::VaultResult<()> {
    // 注入前留一点时间让焦点真正切回目标窗口（比如用户刚从托盘菜单点击"填充"）
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

// ─── 活动窗口标题（平台相关）──────────────────────────────────────────────────

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
    /// NOTE：objc2-app-kit 的确切 API 表面（方法名/返回类型包装）在不同版本间变化较快，
    /// 这里的实现基于 objc2 生态的常见惯用法（Retained<T> 智能指针 + Option 链式调用），
    /// 是本项目里置信度最低的一段代码 —— 如果编译报错，大概率是 objc2-app-kit 的具体
    /// 版本把方法签名改了，请对照 https://docs.rs/objc2-app-kit 当前版本的文档调整。
    ///
    /// 另外需要注意：读取其他 App 的窗口标题在 macOS 上通常还需要 Accessibility 权限
    /// （系统设置 → 隐私与安全性 → 辅助功能），仅拿到 frontmostApplication 的
    /// localizedName（前台 App 的显示名称，例如 "Safari"）不需要这个权限，
    /// 但如果以后想细化到"具体是哪个网页/文档"，就需要额外的 AXUIElement 调用了。
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
        // Wayland 下没有标准途径拿到全局活动窗口标题；直接放弃而不是硬凑一个 X11 连接
        // （多数 Wayland 会话根本没有 XWayland 的 root window EWMH 支持）
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
            _ => return Ok(None), // 没有活动窗口（比如所有窗口都最小化了）
        };

        let title_reply = conn
            .get_property(false, active_window, net_wm_name, utf8_string, 0, u32::MAX)?
            .reply()?;

        Ok(String::from_utf8(title_reply.value).ok())
    }
}
