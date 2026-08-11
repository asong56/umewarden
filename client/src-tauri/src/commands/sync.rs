use crate::{
    daemon::{DaemonHandle, DaemonMsg},
    error::{VaultError, VaultResult},
};
use serde::Serialize;
use tauri::State;

#[derive(Serialize)]
pub struct SyncStatus {
    pub last_sync:    Option<i64>,  // Unix timestamp，None = 从未同步
    pub in_progress:  bool,
    pub error:        Option<String>,
}

#[tauri::command]
pub async fn sync_now(daemon: State<'_, DaemonHandle>) -> VaultResult<()> {
    daemon
        .tx
        .send(DaemonMsg::SyncNow)
        .await
        .map_err(|_| VaultError::Internal("daemon channel closed".into()))
}

#[tauri::command]
pub async fn get_sync_status(daemon: State<'_, DaemonHandle>) -> VaultResult<SyncStatus> {
    let state = daemon.state.read().await;
    Ok(SyncStatus {
        last_sync:   state.last_sync_unix,
        in_progress: false, // TODO: 需要一个 AtomicBool 或 state 字段跟踪同步进行中状态才能准确反映
        error:       None,
    })
}
