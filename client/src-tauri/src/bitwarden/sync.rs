//! Push notifications don't carry full payloads, so any SignalR invocation
//! just triggers a full re-sync rather than applying a delta.
//!
//! Unverified: official Bitwarden cloud uses MessagePack for the hub, not
//! JSON. If push connects but nothing ever arrives (manual sync_now still
//! works), try "messagepack" + rmp-serde here instead of "json".

use super::{models, BitwardenClient};
use crate::crypto::keys::DecryptContext;
use crate::daemon::state::VaultState;
use crate::error::{VaultError, VaultResult};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio_tungstenite::tungstenite::Message;

const RECORD_SEPARATOR: char = '\u{1e}';

pub async fn full_sync(
    client: &BitwardenClient,
    ctx:    &DecryptContext,
    state:  &Arc<RwLock<VaultState>>,
) -> VaultResult<()> {
    let session = client
        .session
        .as_ref()
        .ok_or(VaultError::VaultLocked)?;

    let url = format!("{}/api/sync?excludeDomains=true", client.base_url);
    let resp = client
        .client
        .get(&url)
        .bearer_auth(&session.access_token)
        .send()
        .await
        .map_err(|e| VaultError::Network(e.to_string()))?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(VaultError::Api("session expired, please unlock again".into()));
    }
    if !resp.status().is_success() {
        return Err(VaultError::Api(format!("sync failed with status {}", resp.status())));
    }

    let sync_data: models::SyncResponse = resp
        .json()
        .await
        .map_err(|e| VaultError::Api(format!("sync: invalid response body: {e}")))?;

    let mut items = std::collections::HashMap::new();
    for cipher in &sync_data.ciphers {
        match models::decrypt_cipher(cipher, ctx) {
            Ok(item) => { items.insert(item.id, item); }
            Err(e) => log::warn!("failed to decrypt cipher {}: {e}", cipher.id),
        }
    }

    let mut folders = Vec::new();
    for folder in &sync_data.folders {
        match models::decrypt_folder(folder, ctx) {
            Ok(f) => folders.push(f),
            Err(e) => log::warn!("failed to decrypt folder {}: {e}", folder.id),
        }
    }

    let mut state = state.write().await;
    state.items = items;
    state.folders = folders;
    drop(state);

    log::info!(
        "sync complete: {} items, {} folders",
        sync_data.ciphers.len(),
        sync_data.folders.len()
    );

    Ok(())
}

/// Runs in its own task; reconnects with exponential backoff (cap 60s).
pub async fn run_push_listener(
    base_url:  String,
    access_token: String,
    sync_tx:   tokio::sync::mpsc::Sender<crate::daemon::DaemonMsg>,
) {
    let mut backoff = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(60);

    loop {
        match connect_and_listen(&base_url, &access_token, &sync_tx).await {
            Ok(()) => {
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                log::warn!("push listener error: {e}, reconnecting in {backoff:?}");
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
    }
}

async fn connect_and_listen(
    base_url: &str,
    access_token: &str,
    sync_tx: &tokio::sync::mpsc::Sender<crate::daemon::DaemonMsg>,
) -> VaultResult<()> {
    let ws_base = base_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    let url = format!("{ws_base}/notifications/hub?access_token={access_token}");

    let (mut ws, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .map_err(|e| VaultError::Network(format!("websocket connect failed: {e}")))?;

    let handshake = format!("{{\"protocol\":\"json\",\"version\":1}}{RECORD_SEPARATOR}");
    ws.send(Message::Text(handshake))
        .await
        .map_err(|e| VaultError::Network(format!("handshake send failed: {e}")))?;

    log::info!("push listener connected");

    while let Some(msg) = ws.next().await {
        let msg = msg.map_err(|e| VaultError::Network(format!("websocket read error: {e}")))?;

        match msg {
            Message::Text(text) => {
                for frame in text.split(RECORD_SEPARATOR).filter(|s| !s.is_empty()) {
                    handle_signalr_frame(frame, &mut ws, sync_tx).await;
                }
            }
            Message::Close(_) => {
                log::info!("push listener: server closed connection");
                return Ok(());
            }
            _ => {}
        }
    }

    Ok(())
}

async fn handle_signalr_frame(
    frame: &str,
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    sync_tx: &tokio::sync::mpsc::Sender<crate::daemon::DaemonMsg>,
) {
    if frame == "{}" {
        return;
    }

    let Ok(value) = serde_json::from_str::<serde_json::Value>(frame) else {
        log::debug!("push listener: non-JSON frame ignored: {frame}");
        return;
    };

    match value.get("type").and_then(|t| t.as_u64()) {
        Some(6) => {
            let pong = format!("{{\"type\":6}}{RECORD_SEPARATOR}");
            let _ = ws.send(Message::Text(pong)).await;
        }
        Some(1) => {
            let target = value.get("target").and_then(|t| t.as_str()).unwrap_or("");
            log::debug!("push notification received: target={target}");
            let _ = sync_tx.send(crate::daemon::DaemonMsg::SyncNow).await;
        }
        _ => {}
    }
}
