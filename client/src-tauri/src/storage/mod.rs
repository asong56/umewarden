/// 持久化层
///
/// 分两类存储：
///   A. 敏感数据  → OS keychain（keyring crate）
///      - master key 的 salt（每个 vault 唯一，32 字节 hex）
///      - refresh token（Vaultwarden）
///   B. 非敏感配置 → tauri-plugin-store（本地 JSON 文件）
///      - 服务器 URL、email、lock timeout 等
///
/// 注意：master key 本身不存储，每次解锁时由密码实时派生。
///       keychain 只存储 salt（无 salt 则无法派生同一个 key）。

use crate::error::{VaultError, VaultResult};

// ─── Keychain（OS 原生） ──────────────────────────────────────────────────────

const SERVICE: &str = "io.umewarden.client";

/// 将 salt 存入 OS keychain
/// account: 区分不同 vault（Vaultwarden 用 email，KDBX 用文件路径的 hash）
pub fn store_salt(account: &str, salt: &[u8]) -> VaultResult<()> {
    use keyring::Entry;
    let entry = Entry::new(SERVICE, &format!("salt:{account}"))
        .map_err(|e| VaultError::Internal(e.to_string()))?;
    let hex = hex_encode(salt);
    entry.set_password(&hex)
        .map_err(|e| VaultError::Internal(e.to_string()))
}

/// 从 OS keychain 读取 salt
/// 返回 None 表示尚未初始化（首次使用）
pub fn load_salt(account: &str) -> VaultResult<Option<Vec<u8>>> {
    use keyring::Entry;
    let entry = Entry::new(SERVICE, &format!("salt:{account}"))
        .map_err(|e| VaultError::Internal(e.to_string()))?;
    match entry.get_password() {
        Ok(hex) => Ok(Some(hex_decode(&hex)?)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(VaultError::Internal(e.to_string())),
    }
}

/// 存储 refresh token（Vaultwarden）
pub fn store_refresh_token(account: &str, token: &str) -> VaultResult<()> {
    use keyring::Entry;
    let entry = Entry::new(SERVICE, &format!("refresh:{account}"))
        .map_err(|e| VaultError::Internal(e.to_string()))?;
    entry.set_password(token)
        .map_err(|e| VaultError::Internal(e.to_string()))
}

pub fn load_refresh_token(account: &str) -> VaultResult<Option<String>> {
    use keyring::Entry;
    let entry = Entry::new(SERVICE, &format!("refresh:{account}"))
        .map_err(|e| VaultError::Internal(e.to_string()))?;
    match entry.get_password() {
        Ok(tok) => Ok(Some(tok)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(VaultError::Internal(e.to_string())),
    }
}

/// 清除指定 account 的所有 keychain 条目（logout 时调用）
pub fn clear_keychain(account: &str) -> VaultResult<()> {
    use keyring::Entry;
    for key in &[format!("salt:{account}"), format!("refresh:{account}")] {
        let entry = Entry::new(SERVICE, key)
            .map_err(|e| VaultError::Internal(e.to_string()))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(VaultError::Internal(e.to_string())),
        }
    }
    Ok(())
}

/// 获取（或首次生成并持久化）本机的设备标识符。
/// Bitwarden 登录需要一个稳定的 deviceIdentifier —— 每次登录都用不同的值
/// 会让服务器把每次登录都当成新设备，某些安全策略下会触发额外的邮件确认。
pub fn get_or_create_device_id() -> VaultResult<String> {
    use keyring::Entry;
    let entry = Entry::new(SERVICE, "device_id")
        .map_err(|e| VaultError::Internal(e.to_string()))?;

    match entry.get_password() {
        Ok(id) => Ok(id),
        Err(keyring::Error::NoEntry) => {
            let id = uuid::Uuid::new_v4().to_string();
            entry
                .set_password(&id)
                .map_err(|e| VaultError::Internal(e.to_string()))?;
            Ok(id)
        }
        Err(e) => Err(VaultError::Internal(e.to_string())),
    }
}

// ─── Hex 工具（避免引入额外 crate） ──────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> VaultResult<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| VaultError::Internal("invalid hex in keychain".into())))
        .collect()
}

// ─── TODO: tauri-plugin-store 配置读写封装 ────────────────────────────────────
//
// tauri-plugin-store 的读写需要持有 AppHandle，
// 所以配置 CRUD 放在 commands/config.rs 中直接调用 plugin。
// 本模块只负责 keychain（纯 Rust，不依赖 Tauri 运行时）。
