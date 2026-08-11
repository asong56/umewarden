/// Vault CRUD — Tauri IPC commands
///
/// 所有函数通过 `State<DaemonHandle>` 访问 daemon 的 vault state。
/// 操作前检查 vault 是否已解锁。

use crate::{
    daemon::{DaemonHandle, DaemonMsg},
    error::{VaultError, VaultResult},
    model::{BackendKind, VaultItem},
};
use tauri::State;
use uuid::Uuid;

/// 解锁 vault。
/// two_factor_code: 若服务器要求 2FA（会先收到 `vault:two_factor_required` 事件），
/// 前端拿到用户输入的验证码后带上这个参数重新调用一次。目前只支持 provider "0"
/// （身份验证器 App TOTP），WebAuthn/Email 等其他方式未实现。
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

/// 锁定 vault（清零内存中的所有敏感数据）
#[tauri::command]
pub async fn lock(daemon: State<'_, DaemonHandle>) -> VaultResult<()> {
    daemon
        .tx
        .send(DaemonMsg::Lock)
        .await
        .map_err(|_| VaultError::Internal("daemon channel closed".into()))
}

/// 获取所有 vault items（可选 folder 过滤）
#[tauri::command]
pub async fn list_items(
    daemon:    State<'_, DaemonHandle>,
    folder_id: Option<Uuid>,
) -> VaultResult<Vec<VaultItem>> {
    let state = daemon.state.read().await;
    if state.is_locked() {
        return Err(VaultError::VaultLocked);
    }
    // TODO: 搜索 query 参数（当前搜索过滤逻辑在前端 vault.js 里做，量大之后应该挪到这里）
    Ok(state.list_items(folder_id).into_iter().cloned().collect())
}

/// 获取单个 item
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

/// 创建新 item
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
            let mut state = daemon.state.write().await;
            let vault = state.kdbx_vault.as_mut().ok_or(VaultError::VaultLocked)?;
            let saved_item = vault.create_item(&item)?;
            state.items.insert(saved_item.id, saved_item.clone());
            Ok(saved_item)
        }
        None => Err(VaultError::Internal("no backend configured".into())),
    }
}

/// 更新 item
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
            let mut state = daemon.state.write().await;
            let vault = state.kdbx_vault.as_mut().ok_or(VaultError::VaultLocked)?;
            vault.update_item(&item)?;
            state.items.insert(item.id, item.clone());
            Ok(item)
        }
        None => Err(VaultError::Internal("no backend configured".into())),
    }
}

/// 获取指定 item 当前的 TOTP 验证码（如果它配置了 TOTP 的话）
/// 返回 (code, remaining_secs)，前端拿 remaining_secs 做倒计时，归零后重新调用即可
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
/// 删除 item
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
            let mut state = daemon.state.write().await;
            let vault = state.kdbx_vault.as_mut().ok_or(VaultError::VaultLocked)?;
            vault.delete_item(&id)?; // 目前会返回 Err，见 kdbx/mod.rs 里的 NOTE
        }
        None => return Err(VaultError::Internal("no backend configured".into())),
    }

    let mut state = daemon.state.write().await;
    state.items.remove(&id);
    Ok(())
}
