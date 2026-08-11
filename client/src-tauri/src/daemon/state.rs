/// Vault 运行时内存状态
///
/// 解锁后，所有 vault item 保存在此结构中。
/// 调用 lock() 时，调用 zeroize 清除所有敏感字段，
/// 并将 master_key 置零（ring 的 SealingKey Drop 时自动清零）。

use crate::bitwarden::BitwardenClient;
use crate::crypto::keys::DecryptContext;
use crate::crypto::MasterKey;
use crate::kdbx::KdbxVault;
use crate::model::{BackendKind, Folder, VaultItem};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Default)]
pub struct VaultState {
    pub locked:      bool,
    /// 当前未被任何 backend 使用（Vaultwarden 走 decrypt_ctx，KDBX 的 KDF 由
    /// keepass-ng 内部处理）。保留这个字段是为了以后如果加一个"纯本地、不接
    /// 任何后端"的模式时可以直接用 —— crypto::MasterKey 已经是现成的通用原语。
    pub master_key:  Option<MasterKey>,
    pub backend:     Option<BackendKind>,
    pub items:       HashMap<Uuid, VaultItem>,
    pub folders:     Vec<Folder>,

    // ─── Vaultwarden 专用 ────────────────────────────────────────────────────
    pub bw_client:    Option<BitwardenClient>,
    pub decrypt_ctx:  Option<DecryptContext>,

    // ─── KDBX 专用 ───────────────────────────────────────────────────────────
    pub kdbx_vault:   Option<KdbxVault>,

    /// Vaultwarden WebSocket 推送监听任务的句柄，lock() 时需要 abort 掉，
    /// 否则每次 unlock 都会新开一个监听任务，越攒越多。
    pub push_listener: Option<tokio::task::JoinHandle<()>>,

    pub last_sync_unix: Option<i64>,
}

impl VaultState {
    pub fn new() -> Self {
        VaultState {
            locked: true,
            ..Default::default()
        }
    }

    /// 清空所有敏感数据，标记为锁定状态
    pub fn lock(&mut self) {
        self.master_key = None;
        self.decrypt_ctx = None;  // Zeroizing 字段 Drop 时自动清零
        self.bw_client = None;    // 内含 access_token/refresh_token，一起丢弃
        self.kdbx_vault = None;
        self.items.clear();
        self.folders.clear();
        self.backend = None;
        if let Some(handle) = self.push_listener.take() {
            handle.abort();
        }
        self.locked = true;
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// 列出所有 items（可按 folder / kind 过滤）
    /// TODO: 添加搜索 / 排序支持
    pub fn list_items(&self, folder_id: Option<Uuid>) -> Vec<&VaultItem> {
        self.items
            .values()
            .filter(|item| {
                folder_id.map_or(true, |fid| item.folder_id == Some(fid))
            })
            .collect()
    }
}
