/// Umewarden 内部 canonical 数据模型。
///
/// 无论数据来自 Vaultwarden 还是 KDBX，在内存中统一表示为此结构。
/// 各 backend adapter 负责双向转换。
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

// ─── Vault item 主类型 ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id:         Uuid,
    pub name:       String,
    pub kind:       ItemKind,
    pub favorite:   bool,
    pub folder_id:  Option<Uuid>,
    pub created_at: i64,   // Unix timestamp
    pub updated_at: i64,
    pub fields:     Vec<CustomField>,
    pub notes:      Option<SensitiveString>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ItemKind {
    Login(LoginData),
    Card(CardData),
    Identity(IdentityData),
    SecureNote,
    // TODO: 扩展 SSH key 类型（参考 Keyguard/Goldwarden 实现）
}

// ─── Login ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginData {
    pub username: Option<String>,
    pub password: Option<SensitiveString>,
    pub totp:     Option<SensitiveString>,   // TOTP secret
    pub uris:     Vec<LoginUri>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginUri {
    pub uri:   String,
    pub r#match: UriMatchType,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum UriMatchType {
    #[default]
    Domain,
    Host,
    StartsWith,
    Exact,
    RegularExpression,
    Never,
}

// ─── Card / Identity（占位，字段待补全）────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardData {
    // TODO: 卡号、持卡人、有效期、CVV 等
    // 注意：卡号/CVV 应包装成 SensitiveString
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityData {
    // TODO: 姓名、地址、电话等身份信息字段
}

// ─── Custom field ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomField {
    pub name:       String,
    pub value:      FieldValue,
    pub linked_id:  Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum FieldValue {
    Text(String),
    Hidden(SensitiveString),
    Boolean(bool),
}

// ─── SensitiveString：离开作用域自动清零 ─────────────────────────────────────

/// 包装敏感字符串，Drop 时调用 zeroize 清零内存。
/// 序列化时直接输出内部字符串（仅在必要的 IPC 边界使用）。
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct SensitiveString(String);

impl SensitiveString {
    pub fn new(s: impl Into<String>) -> Self {
        SensitiveString(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for SensitiveString {
    fn from(s: String) -> Self { SensitiveString(s) }
}
impl From<&str> for SensitiveString {
    fn from(s: &str) -> Self { SensitiveString(s.to_owned()) }
}

// ─── Folder ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub id:   Uuid,
    pub name: String,
}

// ─── Backend 来源标记 ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendKind {
    Vaultwarden,
    Kdbx,
}
