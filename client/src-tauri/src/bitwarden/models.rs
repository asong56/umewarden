//! Maps directly onto /api/sync's JSON (camelCase, unlike identity's PascalCase).

use crate::crypto::keys::DecryptContext;
use crate::error::{VaultError, VaultResult};
use crate::model::{
    CustomField, FieldValue, Folder, ItemKind, LoginData, LoginUri, UriMatchType, VaultItem,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub profile:  ProfileResponse,
    pub ciphers:  Vec<CipherResponse>,
    pub folders:  Vec<FolderResponse>,
    // TODO: collections, sends, policies - personal vault only for now
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileResponse {
    pub id:    Uuid,
    pub email: String,
    pub key: Option<String>, // fallback only; token response already carries this on login
    // TODO: organizations
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherResponse {
    pub id:            Uuid,
    pub folder_id:     Option<Uuid>,
    pub r#type:        u8, // 1=Login, 2=SecureNote, 3=Card, 4=Identity
    pub name:          String,
    pub notes:         Option<String>,
    pub favorite:      bool,
    pub login:         Option<CipherLogin>,
    pub card:          Option<CipherCard>,
    pub identity:      Option<CipherIdentity>,
    #[serde(default)]
    pub fields:        Vec<CipherField>,
    pub revision_date: String,
    pub creation_date: Option<String>,
    // TODO: reprompt, password_history, attachments
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherLogin {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp:     Option<String>, // secret or otpauth:// URI after decrypt
    #[serde(default)]
    pub uris:     Vec<CipherUri>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherUri {
    pub uri:   Option<String>,
    pub r#match: Option<u8>, // 0=Domain,1=Host,2=StartsWith,3=Exact,4=RegularExpression,5=Never
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherCard {
    // TODO: cardholderName, brand, number, expMonth, expYear, code
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherIdentity {
    // TODO: title, firstName, lastName, email, phone, address1/2/3, city, state,
    //       postalCode, country, company, ssn, passportNumber, licenseNumber
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherField {
    pub r#type: u8, // 0=Text, 1=Hidden, 2=Boolean, 3=Linked
    pub name:   Option<String>,
    pub value:  Option<String>, // plaintext "true"/"false" when type=Boolean
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderResponse {
    pub id:   Uuid,
    pub name: String,
}

/// Any failed field decrypt aborts the whole item (logged, skipped) rather
/// than surfacing partially-decrypted garbage.
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
        3 => ItemKind::Card(crate::model::CardData {}),     // TODO
        4 => ItemKind::Identity(crate::model::IdentityData {}), // TODO
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

/// Bitwarden dates are fixed-format ("2024-01-15T10:30:00.0000000Z"), so this
/// skips pulling in chrono just for parsing them.
fn parse_iso8601_to_unix(s: &str) -> Option<i64> {
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherRequest {
    pub r#type:    u8,
    pub folder_id: Option<Uuid>,
    pub name:      String,
    pub notes:     Option<String>,
    pub favorite:  bool,
    pub login:     Option<CipherLogin>,
    pub fields:    Vec<CipherField>,
}

pub fn encrypt_item(item: &VaultItem, ctx: &DecryptContext) -> VaultResult<CipherRequest> {
    let name = ctx.encrypt_str(&item.name)?;
    let notes = item.notes.as_ref().map(|n| ctx.encrypt_str(n.expose())).transpose()?;

    let (r#type, login) = match &item.kind {
        ItemKind::Login(l) => (1u8, Some(encrypt_login(l, ctx)?)),
        ItemKind::SecureNote => (2u8, None),
        ItemKind::Card(_) => (3u8, None),     // TODO
        ItemKind::Identity(_) => (4u8, None), // TODO
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
        FieldValue::Boolean(b) => (2u8, Some(b.to_string())), // not encrypted
    };
    Ok(CipherField { r#type, name, value })
}
