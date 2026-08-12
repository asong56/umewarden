//! Canonical in-memory representation; each backend adapter converts to/from this.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id:         Uuid,
    pub name:       String,
    pub kind:       ItemKind,
    pub favorite:   bool,
    pub folder_id:  Option<Uuid>,
    pub created_at: i64,
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
    // TODO: SSH key type
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginData {
    pub username: Option<String>,
    pub password: Option<SensitiveString>,
    pub totp:     Option<SensitiveString>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardData {
    // TODO: number/holder/expiry/CVV - CVV and number should be SensitiveString
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityData {
    // TODO: name/address/phone
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub id:   Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendKind {
    Vaultwarden,
    Kdbx,
}
