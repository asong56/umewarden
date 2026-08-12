// Umewarden Client — Rust + Tauri password manager
// Single binary: daemon task + Tauri GUI in the same process.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod crypto;
mod daemon;
mod error;
mod model;
mod storage;

mod bitwarden;
mod kdbx;

mod autofill;

use tauri::Manager;

fn main() {
    #[cfg(feature = "dev-logging")]
    simple_logger::init_with_level(log::Level::Debug).expect("logger init failed");

    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let app_handle = app.handle().clone();

            tauri::async_runtime::spawn(async move {
                if let Err(e) = daemon::run(app_handle).await {
                    log::error!("daemon exited with error: {e}");
                }
            });

            tray::setup_tray(app)?;
            Ok(()) // main window stays hidden until the tray icon is clicked
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault::unlock,
            commands::vault::lock,
            commands::vault::list_items,
            commands::vault::get_item,
            commands::vault::create_item,
            commands::vault::update_item,
            commands::vault::delete_item,
            commands::vault::get_totp_code,
            commands::config::get_config,
            commands::config::set_vaultwarden_server,
            commands::config::open_kdbx_file,
            commands::config::create_kdbx_file,
            commands::generator::generate_password,
            commands::generator::generate_passphrase,
            commands::autofill::trigger_autofill,
            commands::sync::sync_now,
            commands::sync::get_sync_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

mod tray {
    use tauri::{
        menu::{Menu, MenuItem},
        tray::TrayIconBuilder,
        App, Manager, Result,
    };

    pub fn setup_tray(app: &mut App) -> Result<()> {
        let show  = MenuItem::with_id(app, "show",  "Show Umewarden Client", true, None::<&str>)?;
        let lock  = MenuItem::with_id(app, "lock",  "Lock Vault",    true, None::<&str>)?;
        let sep   = tauri::menu::PredefinedMenuItem::separator(app)?;
        let quit  = MenuItem::with_id(app, "quit",  "Quit",          true, None::<&str>)?;

        let menu = Menu::with_items(app, &[&show, &lock, &sep, &quit])?;

        TrayIconBuilder::new()
            .menu(&menu)
            .on_menu_event(|app, event| match event.id.as_ref() {
                "show" => {
                    if let Some(win) = app.get_webview_window("main") {
                        let _ = win.show();
                        let _ = win.set_focus();
                    }
                }
                "lock" => {
                    let app = app.clone();
                    tauri::async_runtime::spawn(async move {
                        if let Some(daemon) = app.try_state::<crate::daemon::DaemonHandle>() {
                            let _ = daemon.tx.send(crate::daemon::DaemonMsg::Lock).await;
                        }
                    });
                }
                "quit" => app.exit(0),
                _ => {}
            })
            .on_tray_icon_event(|tray, event| {
                if let tauri::tray::TrayIconEvent::Click {
                    button: tauri::tray::MouseButton::Left,
                    button_state: tauri::tray::MouseButtonState::Up,
                    ..
                } = event
                {
                    let app = tray.app_handle();
                    if let Some(win) = app.get_webview_window("main") {
                        if win.is_visible().unwrap_or(false) {
                            let _ = win.hide();
                        } else {
                            let _ = win.show();
                            let _ = win.set_focus();
                        }
                    }
                }
            })
            .build(app)?;

        Ok(())
    }
}
