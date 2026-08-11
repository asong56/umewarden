/// Umewarden 统一错误类型。
///
/// 实现 `serde::Serialize` 使其可作为 Tauri command 的错误返回值
/// （Tauri 要求 Err(E) 中的 E: Serialize）。
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error, Serialize)]
#[serde(tag = "kind", content = "message")]
pub enum VaultError {
    #[error("vault is locked")]
    VaultLocked,

    #[error("wrong master password")]
    WrongPassword,

    #[error("two-factor authentication required")]
    TwoFactorRequired { providers: Vec<String> },

    #[error("item not found: {0}")]
    NotFound(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("KDBX error: {0}")]
    Kdbx(String),

    #[error("Bitwarden API error: {0}")]
    Api(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("internal error: {0}")]
    Internal(String),
}

// 方便从 std::io::Error 转换
impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e.to_string())
    }
}

pub type VaultResult<T> = Result<T, VaultError>;
