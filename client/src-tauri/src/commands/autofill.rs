use crate::{
    daemon::DaemonHandle,
    error::{VaultError, VaultResult},
    model::ItemKind,
};
use tauri::{AppHandle, Manager, State};
use uuid::Uuid;

#[tauri::command]
pub async fn trigger_autofill(
    app:     AppHandle,
    daemon:  State<'_, DaemonHandle>,
    item_id: Uuid,
) -> VaultResult<()> {
    let (username, password) = {
        let state = daemon.state.read().await;
        if state.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        let item = state
            .items
            .get(&item_id)
            .ok_or_else(|| VaultError::NotFound(item_id.to_string()))?;

        match &item.kind {
            ItemKind::Login(login) => (
                login.username.clone().unwrap_or_default(),
                login.password.as_ref().map(|p| p.expose().to_string()).unwrap_or_default(),
            ),
            _ => return Err(VaultError::Internal("only Login items support autofill".into())),
        }
    };

    // hide the main window first, or the credentials get typed into our own search box
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.hide();
    }

    // enigo is sync/blocking, not async - spawn_blocking to avoid stalling the tokio worker
    tokio::task::spawn_blocking(move || {
        crate::autofill::inject_credentials(&username, &password, true)
    })
    .await
    .map_err(|e| VaultError::Internal(format!("autofill task panicked: {e}")))??;

    Ok(())
}
