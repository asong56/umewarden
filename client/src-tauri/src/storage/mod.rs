//! Sensitive data (salt, refresh token) -> OS keychain. Non-sensitive config
//! -> tauri-plugin-store (see commands/config.rs). master_key itself is never
//! stored - only its salt, re-derived from the password on every unlock.

use crate::error::{VaultError, VaultResult};

const SERVICE: &str = "io.umewarden.client";

/// account: email for Vaultwarden, hashed file path for KDBX.
pub fn store_salt(account: &str, salt: &[u8]) -> VaultResult<()> {
    use keyring::Entry;
    let entry = Entry::new(SERVICE, &format!("salt:{account}"))
        .map_err(|e| VaultError::Internal(e.to_string()))?;
    let hex = hex_encode(salt);
    entry.set_password(&hex)
        .map_err(|e| VaultError::Internal(e.to_string()))
}

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

/// A stable deviceIdentifier avoids the server treating every login as a new
/// device (which can trigger extra email confirmation under some policies).
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

// Config CRUD lives in commands/config.rs (needs AppHandle); this module is
// keychain only, no Tauri runtime dependency.
