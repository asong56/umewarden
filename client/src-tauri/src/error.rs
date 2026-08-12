//! Serialize is required so this can be a Tauri command's Err(E).
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

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e.to_string())
    }
}

pub type VaultResult<T> = Result<T, VaultError>;
