/// Bitwarden API 数据模型
///
/// 这些结构直接对应 Vaultwarden `/api/sync` 的 JSON 响应（camelCase，与 identity
/// server 的 PascalCase 不同 —— 两个子系统历史上是分开演进的）。
/// 转换到/从 crate::model::VaultItem 由本文件的函数完成，需要 DecryptContext
/// 来解开每个字段的 EncString。

use crate::crypto::keys::DecryptContext;
use crate::error::{VaultError, VaultResult};
use crate::model::{
    CustomField, FieldValue, Folder, ItemKind, LoginData, LoginUri, UriMatchType, VaultItem,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Sync response ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub profile:  ProfileResponse,
    pub ciphers:  Vec<CipherResponse>,
    pub folders:  Vec<FolderResponse>,
    // TODO: collections（组织共享凭据）、sends、policies —— 当前只做个人 vault
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileResponse {
    pub id:    Uuid,
    pub email: String,
    /// 用户的 protected symmetric key（EncString），登录时 token 响应里通常已经带了一份，
    /// 这里再存一份是为了处理"刷新 token 但没有重新登录"的场景（此时需要复用旧的 DecryptContext，
    /// 不需要重新解密 key —— 所以这个字段目前只用作校验/兜底，不是主路径）。
    pub key: Option<String>,
    // TODO: organizations（组织密钥列表，每个组织有自己的 protected key）
}

// ─── Cipher（vault item）─────────────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherResponse {
    pub id:            Uuid,
    pub folder_id:     Option<Uuid>,
    pub r#type:        u8,         // 1=Login, 2=SecureNote, 3=Card, 4=Identity
    pub name:          String,     // EncString
    pub notes:         Option<String>, // EncString
    pub favorite:      bool,
    pub login:         Option<CipherLogin>,
    pub card:          Option<CipherCard>,
    pub identity:      Option<CipherIdentity>,
    #[serde(default)]
    pub fields:        Vec<CipherField>,
    pub revision_date: String,     // ISO 8601
    pub creation_date: Option<String>,
    // TODO: reprompt（主密码二次确认标记）、password_history、attachments
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherLogin {
    pub username: Option<String>,   // EncString
    pub password: Option<String>,   // EncString
    pub totp:     Option<String>,   // EncString（解密后可能是裸 secret 或 otpauth:// URI）
    #[serde(default)]
    pub uris:     Vec<CipherUri>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherUri {
    pub uri:   Option<String>,   // EncString
    pub r#match: Option<u8>,     // 0=Domain,1=Host,2=StartsWith,3=Exact,4=RegularExpression,5=Never
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherCard {
    // TODO: cardholder_name, brand, number, exp_month, exp_year, code（均为 EncString）
    //       字段名与 Bitwarden API 一致：cardholderName/brand/number/expMonth/expYear/code
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherIdentity {
    // TODO: title, firstName, lastName, email, phone, address1/2/3, city, state,
    //       postalCode, country, company, ssn, passportNumber, licenseNumber（均为 EncString）
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherField {
    pub r#type: u8,             // 0=Text, 1=Hidden, 2=Boolean, 3=Linked
    pub name:   Option<String>, // EncString
    pub value:  Option<String>, // EncString（Boolean 类型时是明文 "true"/"false"，不加密）
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderResponse {
    pub id:   Uuid,
    pub name: String,  // EncString
}

// ─── CipherResponse → VaultItem ──────────────────────────────────────────────

/// 解密并转换单个 cipher。任何一个必需字段解密失败都会中止整个转换 ——
/// 宁可这一条目在列表里消失（并记录日志），也不要把半解密的乱码显示给用户。
pub fn decrypt_cipher(cipher: &CipherResponse, ctx: &DecryptContext) -> VaultResult<VaultItem> {
    let name = ctx.decrypt_str(&cipher.name)?;
    let notes = cipher
        .notes
        .as_deref()
        .map(|n| ctx.decrypt_str(n))
        .transpose()?
        .map(Into::into);

    let kind = match cipher.r#type {
        1 => ItemKind::Login(decrypt_login(cipher.login.as_ref(), ctx)?),
        2 => ItemKind::SecureNote,
        3 => ItemKind::Card(crate::model::CardData {}),     // TODO: 解密卡片字段（见 CipherCard 的 TODO）
        4 => ItemKind::Identity(crate::model::IdentityData {}), // TODO: 解密身份字段
        other => {
            return Err(VaultError::Api(format!("unknown cipher type: {other}")));
        }
    };

    let fields = cipher
        .fields
        .iter()
        .map(|f| decrypt_field(f, ctx))
        .collect::<VaultResult<Vec<_>>>()?;

    let updated_at = parse_iso8601_to_unix(&cipher.revision_date).unwrap_or(0);
    let created_at = cipher
        .creation_date
        .as_deref()
        .and_then(parse_iso8601_to_unix)
        .unwrap_or(updated_at);

    Ok(VaultItem {
        id: cipher.id,
        name,
        kind,
        favorite: cipher.favorite,
        folder_id: cipher.folder_id,
        created_at,
        updated_at,
        fields,
        notes,
    })
}

fn decrypt_login(login: Option<&CipherLogin>, ctx: &DecryptContext) -> VaultResult<LoginData> {
    let Some(login) = login else {
        return Ok(LoginData { username: None, password: None, totp: None, uris: vec![] });
    };

    let username = login.username.as_deref().map(|u| ctx.decrypt_str(u)).transpose()?;
    let password = login
        .password
        .as_deref()
        .map(|p| ctx.decrypt_str(p))
        .transpose()?
        .map(Into::into);
    let totp = login
        .totp
        .as_deref()
        .map(|t| ctx.decrypt_str(t))
        .transpose()?
        .map(Into::into);

    let uris = login
        .uris
        .iter()
        .map(|u| -> VaultResult<LoginUri> {
            let uri = u
                .uri
                .as_deref()
                .map(|s| ctx.decrypt_str(s))
                .transpose()?
                .unwrap_or_default();
            Ok(LoginUri {
                uri,
                r#match: match u.r#match {
                    Some(0) => UriMatchType::Domain,
                    Some(1) => UriMatchType::Host,
                    Some(2) => UriMatchType::StartsWith,
                    Some(3) => UriMatchType::Exact,
                    Some(4) => UriMatchType::RegularExpression,
                    Some(5) => UriMatchType::Never,
                    _ => UriMatchType::Domain,
                },
            })
        })
        .collect::<VaultResult<Vec<_>>>()?;

    Ok(LoginData { username, password, totp, uris })
}

fn decrypt_field(field: &CipherField, ctx: &DecryptContext) -> VaultResult<CustomField> {
    let name = field
        .name
        .as_deref()
        .map(|n| ctx.decrypt_str(n))
        .transpose()?
        .unwrap_or_default();

    let value = match field.r#type {
        1 => FieldValue::Hidden(
            field
                .value
                .as_deref()
                .map(|v| ctx.decrypt_str(v))
                .transpose()?
                .unwrap_or_default()
                .into(),
        ),
        2 => FieldValue::Boolean(field.value.as_deref() == Some("true")),
        _ => FieldValue::Text(
            field
                .value
                .as_deref()
                .map(|v| ctx.decrypt_str(v))
                .transpose()?
                .unwrap_or_default(),
        ),
    };

    Ok(CustomField { name, value, linked_id: None })
}

pub fn decrypt_folder(folder: &FolderResponse, ctx: &DecryptContext) -> VaultResult<Folder> {
    Ok(Folder {
        id:   folder.id,
        name: ctx.decrypt_str(&folder.name)?,
    })
}

/// 极简 ISO 8601 → Unix timestamp 转换（Bitwarden 的日期格式固定为
/// "2024-01-15T10:30:00.0000000Z"，不需要引入 chrono 这种重量级依赖）
fn parse_iso8601_to_unix(s: &str) -> Option<i64> {
    // 格式：YYYY-MM-DDTHH:MM:SS(.fraction)?Z
    let s = s.trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;

    let time_main = time.split('.').next()?;
    let mut time_parts = time_main.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let min: i64 = time_parts.next()?.parse().ok()?;
    let sec: i64 = time_parts.next()?.parse().ok()?;

    // days_from_civil 算法（Howard Hinnant 的公有领域实现），避免引入 chrono
    let days = days_from_civil(year, month, day);
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

// ─── VaultItem → CipherRequest（创建/更新用）──────────────────────────────────

/// 创建/更新 cipher 时发给服务器的请求体。
/// 字段集合是 CipherResponse 的子集（服务器分配 id/revisionDate，不需要客户端提供）。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherRequest {
    pub r#type:    u8,
    pub folder_id: Option<Uuid>,
    pub name:      String,   // EncString
    pub notes:     Option<String>, // EncString
    pub favorite:  bool,
    pub login:     Option<CipherLogin>,
    pub fields:    Vec<CipherField>,
}

/// 将 canonical VaultItem 加密为可上传的 CipherRequest
pub fn encrypt_item(item: &VaultItem, ctx: &DecryptContext) -> VaultResult<CipherRequest> {
    let name = ctx.encrypt_str(&item.name)?;
    let notes = item.notes.as_ref().map(|n| ctx.encrypt_str(n.expose())).transpose()?;

    let (r#type, login) = match &item.kind {
        ItemKind::Login(l) => (1u8, Some(encrypt_login(l, ctx)?)),
        ItemKind::SecureNote => (2u8, None),
        ItemKind::Card(_) => (3u8, None),       // TODO: 加密卡片字段
        ItemKind::Identity(_) => (4u8, None),   // TODO: 加密身份字段
    };

    let fields = item
        .fields
        .iter()
        .map(|f| encrypt_field(f, ctx))
        .collect::<VaultResult<Vec<_>>>()?;

    Ok(CipherRequest {
        r#type,
        folder_id: item.folder_id,
        name,
        notes,
        favorite: item.favorite,
        login,
        fields,
    })
}

fn encrypt_login(login: &LoginData, ctx: &DecryptContext) -> VaultResult<CipherLogin> {
    Ok(CipherLogin {
        username: login.username.as_ref().map(|u| ctx.encrypt_str(u)).transpose()?,
        password: login.password.as_ref().map(|p| ctx.encrypt_str(p.expose())).transpose()?,
        totp: login.totp.as_ref().map(|t| ctx.encrypt_str(t.expose())).transpose()?,
        uris: login
            .uris
            .iter()
            .map(|u| -> VaultResult<CipherUri> {
                Ok(CipherUri {
                    uri: Some(ctx.encrypt_str(&u.uri)?),
                    r#match: Some(match u.r#match {
                        UriMatchType::Domain => 0,
                        UriMatchType::Host => 1,
                        UriMatchType::StartsWith => 2,
                        UriMatchType::Exact => 3,
                        UriMatchType::RegularExpression => 4,
                        UriMatchType::Never => 5,
                    }),
                })
            })
            .collect::<VaultResult<Vec<_>>>()?,
    })
}

fn encrypt_field(field: &CustomField, ctx: &DecryptContext) -> VaultResult<CipherField> {
    let name = Some(ctx.encrypt_str(&field.name)?);
    let (r#type, value) = match &field.value {
        FieldValue::Text(v)   => (0u8, Some(ctx.encrypt_str(v)?)),
        FieldValue::Hidden(v) => (1u8, Some(ctx.encrypt_str(v.expose())?)),
        FieldValue::Boolean(b) => (2u8, Some(b.to_string())), // Boolean 值本身不加密
    };
    Ok(CipherField { r#type, name, value })
}
