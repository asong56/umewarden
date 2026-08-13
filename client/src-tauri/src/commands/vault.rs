use crate::{
    daemon::{DaemonHandle, DaemonMsg},
    error::{VaultError, VaultResult},
    model::{BackendKind, VaultItem},
};
use tauri::State;
use uuid::Uuid;

/// two_factor_code is set on retry after a vault:two_factor_required event.
/// Only provider "0" (TOTP) supported; WebAuthn/Email not implemented.
#[tauri::command]
pub async fn unlock(
    daemon: State<'_, DaemonHandle>,
    password: String,
    two_factor_code: Option<String>,
) -> VaultResult<()> {
    let two_factor = two_factor_code.map(|code| ("0".to_string(), code));
    daemon
        .tx
        .send(DaemonMsg::Unlock { password, two_factor })
        .await
        .map_err(|_| VaultError::Internal("daemon channel closed".into()))
}

#[tauri::command]
pub async fn lock(daemon: State<'_, DaemonHandle>) -> VaultResult<()> {
    daemon
        .tx
        .send(DaemonMsg::Lock)
        .await
        .map_err(|_| VaultError::Internal("daemon channel closed".into()))
}

#[tauri::command]
pub async fn list_items(
    daemon:    State<'_, DaemonHandle>,
    folder_id: Option<Uuid>,
) -> VaultResult<Vec<VaultItem>> {
    let state = daemon.state.read().await;
    if state.is_locked() {
        return Err(VaultError::VaultLocked);
    }
    // TODO: search query param - currently filtered client-side in vault.js
    Ok(state.list_items(folder_id).into_iter().cloned().collect())
}

#[tauri::command]
pub async fn get_item(daemon: State<'_, DaemonHandle>, id: Uuid) -> VaultResult<VaultItem> {
    let state = daemon.state.read().await;
    if state.is_locked() {
        return Err(VaultError::VaultLocked);
    }
    state
        .items
        .get(&id)
        .cloned()
        .ok_or_else(|| VaultError::NotFound(id.to_string()))
}

#[tauri::command]
pub async fn create_item(daemon: State<'_, DaemonHandle>, item: VaultItem) -> VaultResult<VaultItem> {
    let backend = {
        let state = daemon.state.read().await;
        if state.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        state.backend
    };

    match backend {
        Some(BackendKind::Vaultwarden) => {
            let (client, ctx) = {
                let state = daemon.state.read().await;
                let client = state.bw_client.clone().ok_or(VaultError::VaultLocked)?;
                let ctx = state.decrypt_ctx.clone().ok_or(VaultError::VaultLocked)?;
                (client, ctx)
            };

            let session = client.session.as_ref().ok_or(VaultError::VaultLocked)?;
            let request = crate::bitwarden::models::encrypt_item(&item, &ctx)?;

            let url = format!("{}/api/ciphers", client.base_url);
            let resp = client
                .client
                .post(&url)
                .bearer_auth(&session.access_token)
                .json(&request)
                .send()
                .await
                .map_err(|e| VaultError::Network(e.to_string()))?;

            if !resp.status().is_success() {
                return Err(VaultError::Api(format!("create item failed with status {}", resp.status())));
            }

            let created: crate::bitwarden::models::CipherResponse = resp
                .json()
                .await
                .map_err(|e| VaultError::Api(format!("create item: invalid response: {e}")))?;
            let saved_item = crate::bitwarden::models::decrypt_cipher(&created, &ctx)?;

            let mut state = daemon.state.write().await;
            state.items.insert(saved_item.id, saved_item.clone());
            Ok(saved_item)
        }
        Some(BackendKind::Kdbx) => {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            daemon
                .tx
                .send(DaemonMsg::KdbxCreateItem { item: item.clone(), reply: reply_tx })
                .await
                .map_err(|_| VaultError::Internal("daemon channel closed".into()))?;
            reply_rx.await.map_err(|_| VaultError::Internal("daemon dropped reply channel".into()))?
        }
        None => Err(VaultError::Internal("no backend configured".into())),
    }
}

#[tauri::command]
pub async fn update_item(daemon: State<'_, DaemonHandle>, item: VaultItem) -> VaultResult<VaultItem> {
    let backend = {
        let state = daemon.state.read().await;
        if state.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        if !state.items.contains_key(&item.id) {
            return Err(VaultError::NotFound(item.id.to_string()));
        }
        state.backend
    };

    match backend {
        Some(BackendKind::Vaultwarden) => {
            let (client, ctx) = {
                let state = daemon.state.read().await;
                let client = state.bw_client.clone().ok_or(VaultError::VaultLocked)?;
                let ctx = state.decrypt_ctx.clone().ok_or(VaultError::VaultLocked)?;
                (client, ctx)
            };

            let session = client.session.as_ref().ok_or(VaultError::VaultLocked)?;
            let request = crate::bitwarden::models::encrypt_item(&item, &ctx)?;

            let url = format!("{}/api/ciphers/{}", client.base_url, item.id);
            let resp = client
                .client
                .put(&url)
                .bearer_auth(&session.access_token)
                .json(&request)
                .send()
                .await
                .map_err(|e| VaultError::Network(e.to_string()))?;

            if !resp.status().is_success() {
                return Err(VaultError::Api(format!("update item failed with status {}", resp.status())));
            }

            let updated: crate::bitwarden::models::CipherResponse = resp
                .json()
                .await
                .map_err(|e| VaultError::Api(format!("update item: invalid response: {e}")))?;
            let saved_item = crate::bitwarden::models::decrypt_cipher(&updated, &ctx)?;

            let mut state = daemon.state.write().await;
            state.items.insert(saved_item.id, saved_item.clone());
            Ok(saved_item)
        }
        Some(BackendKind::Kdbx) => {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            daemon
                .tx
                .send(DaemonMsg::KdbxUpdateItem { item: item.clone(), reply: reply_tx })
                .await
                .map_err(|_| VaultError::Internal("daemon channel closed".into()))?;
            reply_rx.await.map_err(|_| VaultError::Internal("daemon dropped reply channel".into()))??;

            let mut state = daemon.state.write().await;
            state.items.insert(item.id, item.clone());
            Ok(item)
        }
        None => Err(VaultError::Internal("no backend configured".into())),
    }
}

/// Returns (code, remaining_secs); frontend re-calls once remaining_secs hits 0.
#[tauri::command]
pub async fn get_totp_code(daemon: State<'_, DaemonHandle>, id: Uuid) -> VaultResult<(String, u8)> {
    let state = daemon.state.read().await;
    if state.is_locked() {
        return Err(VaultError::VaultLocked);
    }
    let item = state.items.get(&id).ok_or_else(|| VaultError::NotFound(id.to_string()))?;

    let crate::model::ItemKind::Login(login) = &item.kind else {
        return Err(VaultError::Internal("item is not a Login".into()));
    };
    let secret = login
        .totp
        .as_ref()
        .ok_or_else(|| VaultError::Internal("item has no TOTP configured".into()))?;

    crate::crypto::totp::generate(secret.expose())
}

#[tauri::command]
pub async fn delete_item(daemon: State<'_, DaemonHandle>, id: Uuid) -> VaultResult<()> {
    let backend = {
        let state = daemon.state.read().await;
        if state.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        state.backend
    };

    match backend {
        Some(BackendKind::Vaultwarden) => {
            let client = {
                let state = daemon.state.read().await;
                state.bw_client.clone().ok_or(VaultError::VaultLocked)?
            };
            let session = client.session.as_ref().ok_or(VaultError::VaultLocked)?;

            let url = format!("{}/api/ciphers/{}", client.base_url, id);
            let resp = client
                .client
                .delete(&url)
                .bearer_auth(&session.access_token)
                .send()
                .await
                .map_err(|e| VaultError::Network(e.to_string()))?;

            if !resp.status().is_success() {
                return Err(VaultError::Api(format!("delete failed with status {}", resp.status())));
            }
        }
        Some(BackendKind::Kdbx) => {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            daemon
                .tx
                .send(DaemonMsg::KdbxDeleteItem { id, reply: reply_tx })
                .await
                .map_err(|_| VaultError::Internal("daemon channel closed".into()))?;
            reply_rx.await.map_err(|_| VaultError::Internal("daemon dropped reply channel".into()))??;
        }
        None => return Err(VaultError::Internal("no backend configured".into())),
    }

    let mut state = daemon.state.write().await;
    state.items.remove(&id);
    Ok(())
}
