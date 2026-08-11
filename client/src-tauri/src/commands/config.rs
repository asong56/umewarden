/// 配置管理 commands
///
/// 非敏感配置（服务器 URL、锁定超时等）使用 tauri-plugin-store 持久化到本地 JSON。
/// 敏感数据（master key 的 salt、refresh token）存储在 OS keychain（见 storage/mod.rs）。

use crate::error::{VaultError, VaultResult};
use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use tauri_plugin_store::StoreExt;

const STORE_FILE: &str = "config.json";
const CONFIG_KEY:  &str = "app_config";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub backend:          BackendConfig,
    pub auto_lock_secs:   u64,
    pub hotkey:           String,       // e.g. "ctrl+shift+v" — TODO: 目前 autofill/mod.rs 里硬编码，未读取这个值
    pub minimize_to_tray: bool,
    pub theme:            String,       // "system" | "light" | "dark"
    pub language:         String,       // BCP-47，如 "zh-CN"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum BackendConfig {
    Vaultwarden { server_url: String, email: String },
    Kdbx        { file_path:  String },
    None,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            backend:          BackendConfig::None,
            auto_lock_secs:   300,
            hotkey:           "ctrl+shift+v".into(),
            minimize_to_tray: true,
            theme:            "system".into(),
            language:         "en".into(),
        }
    }
}

// ─── 内部函数（daemon 和 Tauri command 共用，避免逻辑重复）────────────────────

/// 读取当前配置；找不到 store 或找不到 key 时返回默认配置（不是错误 —— 首次启动就是这样）
pub async fn load_config_internal(app: &AppHandle) -> VaultResult<AppConfig> {
    let store = app
        .store(STORE_FILE)
        .map_err(|e| VaultError::Internal(format!("failed to open config store: {e}")))?;

    match store.get(CONFIG_KEY) {
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|e| VaultError::Internal(format!("config store contains invalid data: {e}"))),
        None => Ok(AppConfig::default()),
    }
}

pub async fn save_config_internal(app: &AppHandle, config: &AppConfig) -> VaultResult<()> {
    let store = app
        .store(STORE_FILE)
        .map_err(|e| VaultError::Internal(format!("failed to open config store: {e}")))?;

    let value = serde_json::to_value(config)
        .map_err(|e| VaultError::Internal(format!("failed to serialize config: {e}")))?;

    store.set(CONFIG_KEY.to_string(), value);
    store
        .save()
        .map_err(|e| VaultError::Internal(format!("failed to persist config: {e}")))?;

    Ok(())
}

// ─── Tauri commands ───────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_config(app: AppHandle) -> VaultResult<AppConfig> {
    load_config_internal(&app).await
}

/// 配置 Vaultwarden 服务器（只做保存，不在这里做登录——登录发生在 unlock 时）
#[tauri::command]
pub async fn set_vaultwarden_server(app: AppHandle, server_url: String, email: String) -> VaultResult<()> {
    let server_url = server_url.trim().trim_end_matches('/').to_string();
    if !server_url.starts_with("https://") && !server_url.starts_with("http://localhost") {
        return Err(VaultError::Internal(
            "server URL must start with https:// (http://localhost is allowed for local testing)".into(),
        ));
    }
    if !email.contains('@') {
        return Err(VaultError::Internal("invalid email address".into()));
    }

    // 轻量可达性检查：GET /alive 是 Vaultwarden 的健康检查端点，返回 200 即可
    // （检查失败不阻止保存配置，只记录警告 —— 服务器可能暂时下线，不代表配置错了）
    let check_url = format!("{server_url}/alive");
    match reqwest::Client::new().get(&check_url).send().await {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => log::warn!("server reachability check returned status {}", resp.status()),
        Err(e) => log::warn!("server reachability check failed (saving config anyway): {e}"),
    }

    let mut config = load_config_internal(&app).await?;
    config.backend = BackendConfig::Vaultwarden { server_url, email };
    save_config_internal(&app, &config).await
}

/// 记录 KDBX 文件路径（文件本身在 unlock 时才真正打开校验密码）
#[tauri::command]
pub async fn open_kdbx_file(app: AppHandle, file_path: String) -> VaultResult<()> {
    let path = std::path::Path::new(&file_path);
    if !path.exists() {
        return Err(VaultError::Internal(format!("file not found: {file_path}")));
    }

    let mut config = load_config_internal(&app).await?;
    config.backend = BackendConfig::Kdbx { file_path };
    save_config_internal(&app, &config).await
}

/// 创建一个全新的空 KDBX 文件（配合"没有现成 vault，新建一个"的首次使用流程）
#[tauri::command]
pub async fn create_kdbx_file(app: AppHandle, file_path: String, password: String) -> VaultResult<()> {
    crate::kdbx::create(std::path::Path::new(&file_path), &password)?;

    let mut config = load_config_internal(&app).await?;
    config.backend = BackendConfig::Kdbx { file_path };
    save_config_internal(&app, &config).await
}
