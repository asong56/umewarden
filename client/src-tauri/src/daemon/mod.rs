//! Background task: vault state, auto-lock, sync, autofill hotkey, event
//! broadcast to the frontend. In-process mpsc channel to commands/, no
//! cross-process IPC.
//!
//! KdbxVault lives as a local variable in run()'s loop, not in the shared
//! VaultState - see the NOTE at the top of daemon/state.rs for why. All
//! KDBX reads/writes from commands go through DaemonMsg::Kdbx* messages
//! with a oneshot response channel, same shape as the existing Unlock/Lock
//! messages.

pub mod state;
pub mod timer;

use crate::bitwarden::BitwardenClient;
use crate::commands::config::BackendConfig;
use crate::error::{VaultError, VaultResult};
use crate::kdbx::KdbxVault;
use crate::model::{BackendKind, VaultItem};
use crate::storage;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::{mpsc, oneshot, RwLock};
use uuid::Uuid;

use state::VaultState;

#[derive(Debug)]
pub enum DaemonMsg {
    Unlock { password: String, two_factor: Option<(String, String)> }, // two_factor provider "0" = TOTP only, today
    Lock,
    SyncNow,
    AutofillTriggered { window_title: String },
    Shutdown,

    // ─── KDBX-only operations ───────────────────────────────────────────────
    // KdbxVault can't cross threads (see state.rs), so these carry the
    // request plus a oneshot sender for the reply instead of returning a
    // value directly like the in-process daemon.state reads do.
    KdbxCreateItem { item: VaultItem, reply: oneshot::Sender<VaultResult<VaultItem>> },
    KdbxUpdateItem { item: VaultItem, reply: oneshot::Sender<VaultResult<()>> },
    KdbxDeleteItem { id: Uuid, reply: oneshot::Sender<VaultResult<()>> },
}

#[derive(Clone)]
pub struct DaemonHandle {
    pub tx:    mpsc::Sender<DaemonMsg>,
    pub state: Arc<RwLock<VaultState>>,
}

pub async fn run(app: AppHandle) -> VaultResult<()> {
    let (tx, mut rx) = mpsc::channel::<DaemonMsg>(32);
    let state = Arc::new(RwLock::new(VaultState::new()));

    app.manage(DaemonHandle {
        tx:    tx.clone(),
        state: state.clone(),
    });

    // TODO: read timeout from config, currently hardcoded to 5 minutes
    let _auto_lock_reset = timer::spawn_auto_lock(tx.clone(), std::time::Duration::from_secs(300));
    crate::autofill::spawn_watcher(tx.clone());

    log::info!("daemon started");

    // Owned by this task only - never sent across an .await that could hop
    // threads on the multi-threaded runtime, and never touched from a
    // Tauri command directly. See the NOTE in daemon/state.rs.
    let mut kdbx_vault: Option<KdbxVault> = None;

    while let Some(msg) = rx.recv().await {
        match msg {
            DaemonMsg::Unlock { password, two_factor } => {
                handle_unlock(&app, &tx, &state, &mut kdbx_vault, password, two_factor).await;
            }
            DaemonMsg::Lock => {
                handle_lock(&app, &state, &mut kdbx_vault).await;
            }
            DaemonMsg::SyncNow => {
                handle_sync_now(&app, &state).await;
            }
            DaemonMsg::AutofillTriggered { window_title } => {
                handle_autofill_triggered(&app, &state, window_title).await;
            }
            DaemonMsg::Shutdown => {
                log::info!("daemon shutting down");
                break;
            }
            DaemonMsg::KdbxCreateItem { item, reply } => {
                let result = handle_kdbx_create_item(&state, &mut kdbx_vault, item).await;
                let _ = reply.send(result);
            }
            DaemonMsg::KdbxUpdateItem { item, reply } => {
                let result = handle_kdbx_update_item(&state, &mut kdbx_vault, item).await;
                let _ = reply.send(result);
            }
            DaemonMsg::KdbxDeleteItem { id, reply } => {
                let result = handle_kdbx_delete_item(&mut kdbx_vault, id).await;
                let _ = reply.send(result);
            }
        }
    }

    Ok(())
}

async fn handle_unlock(
    app:         &AppHandle,
    daemon_tx:   &mpsc::Sender<DaemonMsg>,
    state:       &Arc<RwLock<VaultState>>,
    kdbx_vault:  &mut Option<KdbxVault>,
    password:    String,
    two_factor:  Option<(String, String)>,
) {
    let config = match crate::commands::config::load_config_internal(app).await {
        Ok(c) => c,
        Err(e) => {
            let _ = app.emit("vault:unlock_failed", e.to_string());
            return;
        }
    };

    match config.backend {
        BackendConfig::Vaultwarden { server_url, email } => {
            unlock_vaultwarden(app, daemon_tx, state, server_url, email, password, two_factor).await;
        }
        BackendConfig::Kdbx { file_path } => {
            unlock_kdbx(app, state, kdbx_vault, file_path, password).await;
        }
        BackendConfig::None => {
            let _ = app.emit("vault:unlock_failed", "no backend configured yet — go to Settings first");
        }
    }
}

async fn unlock_vaultwarden(
    app:        &AppHandle,
    daemon_tx:  &mpsc::Sender<DaemonMsg>,
    state:      &Arc<RwLock<VaultState>>,
    server_url: String,
    email:      String,
    password:   String,
    two_factor: Option<(String, String)>,
) {
    let device_id = match storage::get_or_create_device_id() {
        Ok(id) => id,
        Err(e) => { let _ = app.emit("vault:unlock_failed", e.to_string()); return; }
    };

    let mut client = match BitwardenClient::new(&server_url) {
        Ok(c) => c,
        Err(e) => { let _ = app.emit("vault:unlock_failed", e.to_string()); return; }
    };

    let tf_ref = two_factor.as_ref().map(|(p, c)| (p.as_str(), c.as_str()));

    match client.login(&email, &password, &device_id, tf_ref).await {
        Ok(outcome) => {
            // sync via local vars first, before moving client/ctx into state -
            // full_sync takes its own write lock on state, avoid holding it across the request
            if let Err(e) = crate::bitwarden::sync::full_sync(&client, &outcome.decrypt_ctx, state).await {
                log::warn!("initial sync after login failed: {e}");
            }

            let access_token = outcome.session.access_token.clone();
            let base_url = client.base_url.clone();

            let push_tx = daemon_tx.clone();
            let listener_handle = tokio::spawn(async move {
                crate::bitwarden::sync::run_push_listener(base_url, access_token, push_tx).await;
            });

            {
                let mut s = state.write().await;
                s.bw_client = Some(client);
                s.decrypt_ctx = Some(outcome.decrypt_ctx);
                s.backend = Some(BackendKind::Vaultwarden);
                s.push_listener = Some(listener_handle);
                s.locked = false;
            }

            let _ = app.emit("vault:unlocked", ());
        }
        Err(VaultError::TwoFactorRequired { providers }) => {
            let _ = app.emit("vault:two_factor_required", providers);
        }
        Err(e) => {
            let _ = app.emit("vault:unlock_failed", e.to_string());
        }
    }
}

async fn unlock_kdbx(
    app:        &AppHandle,
    state:      &Arc<RwLock<VaultState>>,
    kdbx_vault: &mut Option<KdbxVault>,
    file_path:  String,
    password:   String,
) {
    match crate::kdbx::open(std::path::Path::new(&file_path), &password, None) {
        Ok(vault) => {
            let items = vault.list_items().unwrap_or_else(|e| {
                log::warn!("kdbx list_items failed: {e}");
                vec![]
            });
            let folders = vault.list_folders().unwrap_or_else(|e| {
                log::warn!("kdbx list_folders failed: {e}");
                vec![]
            });

            let mut s = state.write().await;
            s.items = items.into_iter().map(|i| (i.id, i)).collect();
            s.folders = folders;
            s.backend = Some(BackendKind::Kdbx);
            s.locked = false;
            drop(s);

            *kdbx_vault = Some(vault);

            let _ = app.emit("vault:unlocked", ());
        }
        Err(e) => {
            let _ = app.emit("vault:unlock_failed", e.to_string());
        }
    }
}

async fn handle_lock(app: &AppHandle, state: &Arc<RwLock<VaultState>>, kdbx_vault: &mut Option<KdbxVault>) {
    let mut s = state.write().await;
    s.lock();
    drop(s);
    *kdbx_vault = None;
    let _ = app.emit("vault:locked", ());
    log::info!("vault locked");
}

async fn handle_kdbx_create_item(
    state:      &Arc<RwLock<VaultState>>,
    kdbx_vault: &mut Option<KdbxVault>,
    item:       VaultItem,
) -> VaultResult<VaultItem> {
    let vault = kdbx_vault.as_mut().ok_or(VaultError::VaultLocked)?;
    let saved_item = vault.create_item(&item)?;

    let mut s = state.write().await;
    s.items.insert(saved_item.id, saved_item.clone());
    Ok(saved_item)
}

async fn handle_kdbx_update_item(
    state:      &Arc<RwLock<VaultState>>,
    kdbx_vault: &mut Option<KdbxVault>,
    item:       VaultItem,
) -> VaultResult<()> {
    let vault = kdbx_vault.as_mut().ok_or(VaultError::VaultLocked)?;
    vault.update_item(&item)?;

    let mut s = state.write().await;
    s.items.insert(item.id, item);
    Ok(())
}

async fn handle_kdbx_delete_item(
    kdbx_vault: &mut Option<KdbxVault>,
    id:         Uuid,
) -> VaultResult<()> {
    let vault = kdbx_vault.as_mut().ok_or(VaultError::VaultLocked)?;
    vault.delete_item(&id) // currently always Err - see NOTE in kdbx/mod.rs
}

async fn handle_sync_now(app: &AppHandle, state: &Arc<RwLock<VaultState>>) {
    // clone out then drop the read lock, avoids deadlock with full_sync's write lock
    let (client, ctx) = {
        let s = state.read().await;
        match (&s.bw_client, &s.decrypt_ctx) {
            (Some(c), Some(ctx)) => (c.clone(), ctx.clone()),
            _ => {
                log::debug!("sync requested but not on Vaultwarden backend (or vault locked)");
                return;
            }
        }
    };

    match crate::bitwarden::sync::full_sync(&client, &ctx, state).await {
        Ok(()) => {
            let mut s = state.write().await;
            s.last_sync_unix = Some(now_unix());
            drop(s);
            let _ = app.emit("vault:synced", serde_json::json!({ "timestamp": now_unix() }));
        }
        Err(e) => {
            log::warn!("manual sync failed: {e}");
            let _ = app.emit("vault:sync_failed", e.to_string());
        }
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

async fn handle_autofill_triggered(app: &AppHandle, state: &Arc<RwLock<VaultState>>, window_title: String) {
    let s = state.read().await;
    if s.is_locked() {
        log::debug!("autofill triggered but vault is locked, ignoring");
        return;
    }

    let title_lower = window_title.to_lowercase();

    let candidates: Vec<serde_json::Value> = s
        .items
        .values()
        .filter_map(|item| {
            let crate::model::ItemKind::Login(login) = &item.kind else { return None };
            let matches = login.uris.iter().any(|u| {
                let domain = extract_domain(&u.uri);
                !domain.is_empty() && title_lower.contains(&domain.to_lowercase())
            });
            matches.then(|| serde_json::json!({ "id": item.id, "name": item.name }))
        })
        .collect();
    drop(s);

    if candidates.is_empty() {
        log::debug!("autofill: no matching credentials for window title '{window_title}'");
        return;
    }

    let _ = app.emit("autofill:candidates", candidates);
}

fn extract_domain(uri: &str) -> String {
    let without_scheme = uri
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(uri);
    without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .to_string()
}
