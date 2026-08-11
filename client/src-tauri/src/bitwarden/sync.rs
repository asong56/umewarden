/// Vaultwarden vault 同步
///
/// 两种同步路径：
///   1. 主动同步：GET /api/sync → 全量拉取所有 cipher
///   2. 被动推送：WebSocket wss://{host}/notifications/hub?access_token=...
///              （路径已通过 Vaultwarden 官方文档核对，不带 /api 或 /identity 前缀）
///              收到推送后触发一次全量 full_sync（不做增量同步的消息级区分，
///              因为 Bitwarden 的 SignalR 推送消息本身不带完整数据，
///              大多数客户端收到通知后也是直接重新拉取）
///
/// SignalR 协议细节：
///   - 握手：客户端发 `{"protocol":"json","version":1}\x1e`，服务端回 `{}\x1e`
///   - 消息以 0x1E（ASCII Record Separator）分隔，允许一个 WS frame 里有多条
///   - Ping 消息：`{"type":6}`，收到后原样回复即可（保活）
///   - Invocation 消息：`{"type":1,"target":"...","arguments":[...]}`
///
///   注意：官方 Bitwarden 云端服务器的 notifications hub 实际使用 MessagePack
///   二进制协议（而不是 JSON）；但 Vaultwarden 是完全独立的 Rust 重实现，其
///   hub 部分是否严格复刻这个细节未经过本实现验证。如果连接后收不到任何推送
///   （full_sync 仍能通过手动 sync_now 正常工作），大概率是协议协商不匹配，
///   需要把下面的 "json" 换成 "messagepack" 并引入 rmp-serde 做二进制编解码。

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

// ─── 主动同步 ─────────────────────────────────────────────────────────────────

/// 全量同步：拉取服务器所有数据并更新本地 state
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

    // 逐条解密；单条失败只跳过并记录日志，不影响整体同步（详见 models.rs 里的注释）
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

// ─── WebSocket 推送 ───────────────────────────────────────────────────────────

/// 长连接：监听服务器推送的 vault 变更通知。
/// 应在独立 tokio task 中运行；断线后自动重连（指数退避，上限 60 秒）。
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
                // 正常关闭（服务器主动断开），重置退避后重连
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
    // http(s) → ws(s)
    let ws_base = base_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    let url = format!("{ws_base}/notifications/hub?access_token={access_token}");

    let (mut ws, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .map_err(|e| VaultError::Network(format!("websocket connect failed: {e}")))?;

    // SignalR 握手
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
            _ => {} // 忽略 Binary/Ping/Pong（tungstenite 自动处理 WS 层 ping/pong）
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
    // 空的 "{}" 是握手响应确认，直接忽略
    if frame == "{}" {
        return;
    }

    let Ok(value) = serde_json::from_str::<serde_json::Value>(frame) else {
        log::debug!("push listener: non-JSON frame ignored: {frame}");
        return;
    };

    match value.get("type").and_then(|t| t.as_u64()) {
        // type 6 = Ping —— 原样回复保活
        Some(6) => {
            let pong = format!("{{\"type\":6}}{RECORD_SEPARATOR}");
            let _ = ws.send(Message::Text(pong)).await;
        }
        // type 1 = Invocation —— 服务器调用了客户端方法（通常是 "ReceiveMessage"）
        Some(1) => {
            let target = value.get("target").and_then(|t| t.as_str()).unwrap_or("");
            log::debug!("push notification received: target={target}");
            // 不区分具体是哪种变更（新增/更新/删除 cipher，还是 folder 变更），
            // 统一触发一次全量同步 —— 简单但正确，Bitwarden 官方客户端在很多场景下也是这么做的。
            let _ = sync_tx.send(crate::daemon::DaemonMsg::SyncNow).await;
        }
        _ => {}
    }
}
