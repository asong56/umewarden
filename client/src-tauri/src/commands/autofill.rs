use crate::{
    daemon::DaemonHandle,
    error::{VaultError, VaultResult},
    model::ItemKind,
};
use tauri::{AppHandle, Manager, State};
use uuid::Uuid;

/// 手动触发 autofill（前端按钮触发，或者热键弹出候选列表后用户点选触发）
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

    // 把主窗口挪开，避免把凭据敲进自己的搜索框里
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.hide();
    }

    // autofill::inject_credentials 内部有 150ms 延迟等焦点切回目标窗口，
    // 但它是同步阻塞调用（enigo 不是 async 的），扔进 spawn_blocking 避免卡住 tokio worker 线程
    tokio::task::spawn_blocking(move || {
        crate::autofill::inject_credentials(&username, &password, true)
    })
    .await
    .map_err(|e| VaultError::Internal(format!("autofill task panicked: {e}")))??;

    Ok(())
}
