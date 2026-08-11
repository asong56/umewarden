/// Vaultwarden / Bitwarden 后端 adapter
///
/// 实现 Bitwarden Web API 对接：
///   - 账号登录（邮箱 + master password，支持 2FA）
///   - vault 同步（GET /sync）
///   - CRUD 操作（cipher create/update/delete）
///   - WebSocket 推送（实时 vault 变更通知）
///
/// 所有 API 请求走 reqwest + rustls（不依赖系统 OpenSSL）。
///
/// 参考：Goldwarden cli/agent/bitwarden/ 的协议实现
/// 文档：https://contributing.bitwarden.com/architecture/clients/

pub mod auth;
pub mod models;
pub mod sync;

use crate::error::{VaultError, VaultResult};
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Bitwarden API 客户端
///
/// 派生 Clone：reqwest::Client 内部是 Arc 包裹的连接池，克隆代价很小。
/// 这么做是为了让调用方可以从 `state.read().await` 里克隆一份出来，
/// 在不跨 await 持有读锁的情况下发起网络请求（避免和 full_sync 内部的
/// write 锁产生死锁 —— 详见 daemon/mod.rs 的 SyncNow 处理逻辑）。
#[derive(Clone)]
pub struct BitwardenClient {
    pub base_url: String,
    pub client:   Client,
    pub session:  Option<AuthSession>,
}

/// 登录后的会话令牌
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub access_token:  String,
    pub refresh_token: String,
    pub token_type:    String,
    pub expires_in:    u64,
}

impl BitwardenClient {
    /// 创建客户端实例
    /// base_url: Vaultwarden 服务器地址，如 "https://vault.example.com"
    pub fn new(base_url: impl Into<String>) -> VaultResult<Self> {
        let client = Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| VaultError::Network(e.to_string()))?;

        Ok(BitwardenClient {
            base_url: base_url.into(),
            client,
            session: None,
        })
    }

    /// 构造 API endpoint URL
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

// ─── 实现状态 ──────────────────────────────────────────────────────────────────
//
// auth.rs   ✅ 已实现：prelogin → login（含 2FA）→ token refresh
//              端点/字段格式已与 Vaultwarden 实际响应核对（见该文件顶部注释）
// sync.rs   ✅ 已实现：GET /api/sync 全量拉取 + WebSocket push（SignalR 简化版）
// models.rs ✅ 已实现：CipherResponse ↔ VaultItem 双向转换（借助 DecryptContext）
