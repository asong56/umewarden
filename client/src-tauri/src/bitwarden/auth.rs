//! /connect/token is form-urlencoded, not JSON. Its 400 error body is
//! PascalCase (TwoFactorProviders) while prelogin's response is camelCase —
//! upstream Bitwarden inconsistency, not a bug here.

use crate::crypto::keys::{self, DecryptContext, EncString, KdfParams, KdfType};
use crate::error::{VaultError, VaultResult};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::BitwardenClient;

#[derive(Serialize)]
struct PreloginRequest<'a> {
    email: &'a str,
}

#[derive(Deserialize, Debug)]
struct PreloginResponse {
    kdf:            u32,
    #[serde(rename = "kdfIterations")]
    kdf_iterations: u32,
    #[serde(rename = "kdfMemory")]
    kdf_memory:     Option<u32>,
    #[serde(rename = "kdfParallelism")]
    kdf_parallelism: Option<u32>,
}

fn kdf_params_from_prelogin(r: PreloginResponse) -> VaultResult<KdfParams> {
    Ok(KdfParams {
        kdf_type:    KdfType::from_server_value(r.kdf)?,
        iterations:  r.kdf_iterations,
        memory_mib:  r.kdf_memory,
        parallelism: r.kdf_parallelism,
    })
}

#[derive(Deserialize, Debug, Default)]
struct TokenErrorResponse {
    error: Option<String>,
    error_description: Option<String>,
    #[serde(rename = "TwoFactorProviders")]
    two_factor_providers: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
struct TokenResponse {
    access_token:  String,
    refresh_token: String,
    token_type:    String,
    expires_in:    u64,
    #[serde(rename = "Key")]
    key: Option<String>,
}

fn device_type_for_platform() -> u32 {
    #[cfg(target_os = "windows")]
    { 11 }
    #[cfg(target_os = "macos")]
    { 12 }
    #[cfg(target_os = "linux")]
    { 13 }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    { 21 }
}

pub struct LoginOutcome {
    pub session:     super::AuthSession,
    pub decrypt_ctx: DecryptContext,
    pub kdf_params:  KdfParams,
}

#[derive(Debug)]
pub struct TwoFactorRequired {
    pub providers: Vec<String>,
}

impl BitwardenClient {
    async fn prelogin(&self, email: &str) -> VaultResult<KdfParams> {
        let url = self.url("/identity/accounts/prelogin");
        let resp = self
            .client
            .post(&url)
            .json(&PreloginRequest { email })
            .send()
            .await
            .map_err(|e| VaultError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(VaultError::Api(format!(
                "prelogin failed with status {}",
                resp.status()
            )));
        }

        let body: PreloginResponse = resp
            .json()
            .await
            .map_err(|e| VaultError::Api(format!("prelogin: invalid response body: {e}")))?;

        kdf_params_from_prelogin(body)
    }

    /// two_factor: Some((provider_type, code)) on retry after TwoFactorRequired.
    pub async fn login(
        &mut self,
        email:      &str,
        password:   &str,
        device_id:  &str,
        two_factor: Option<(&str, &str)>,
    ) -> VaultResult<LoginOutcome> {
        let kdf_params = self.prelogin(email).await?;
        let master_key = keys::derive_master_key(password, email, &kdf_params)?;
        let hashed_password = keys::master_password_hash(&master_key, password);

        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "password".into()),
            ("username", email.to_string()),
            ("password", hashed_password),
            ("scope", "api offline_access".into()),
            ("client_id", "cli".into()),
            ("deviceType", device_type_for_platform().to_string()),
            ("deviceIdentifier", device_id.to_string()),
            ("deviceName", "umewarden-client".into()),
        ];

        if let Some((provider, code)) = two_factor {
            form.push(("twoFactorProvider", provider.to_string()));
            form.push(("twoFactorToken", code.to_string()));
            form.push(("twoFactorRemember", "0".into())); // field is Option<i32> server-side, not bool
        }

        let url = self.url("/identity/connect/token");
        let resp = self
            .client
            .post(&url)
            .form(&form)
            .send()
            .await
            .map_err(|e| VaultError::Network(e.to_string()))?;

        let status = resp.status();

        if status == reqwest::StatusCode::BAD_REQUEST {
            let err: TokenErrorResponse = resp.json().await.unwrap_or_default();

            if let Some(providers) = err.two_factor_providers {
                if !providers.is_empty() {
                    return Err(VaultError::TwoFactorRequired { providers });
                }
            }

            return Err(VaultError::WrongPassword);
        }

        if !status.is_success() {
            return Err(VaultError::Api(format!("login failed with status {status}")));
        }

        let body: TokenResponse = resp
            .json()
            .await
            .map_err(|e| VaultError::Api(format!("login: invalid response body: {e}")))?;

        let (stretched_enc, stretched_mac) = keys::stretch_master_key(&master_key)?;
        let protected_key_str = body
            .key
            .as_deref()
            .ok_or_else(|| VaultError::Api("token response missing Key field".into()))?;
        let protected_key = EncString::parse(protected_key_str)?;
        let decrypt_ctx = DecryptContext::from_protected_key(&protected_key, &stretched_enc, &stretched_mac)?;

        let session = super::AuthSession {
            access_token:  body.access_token,
            refresh_token: body.refresh_token,
            token_type:    body.token_type,
            expires_in:    body.expires_in,
        };
        self.session = Some(session.clone());

        Ok(LoginOutcome { session, decrypt_ctx, kdf_params })
    }

    pub async fn refresh_token(&mut self) -> VaultResult<()> {
        let refresh_token = self
            .session
            .as_ref()
            .map(|s| s.refresh_token.clone())
            .ok_or(VaultError::VaultLocked)?;

        let form = [
            ("grant_type", "refresh_token"),
            ("client_id", "cli"),
            ("refresh_token", &refresh_token),
        ];

        let url = self.url("/identity/connect/token");
        let resp = self
            .client
            .post(&url)
            .form(&form)
            .send()
            .await
            .map_err(|e| VaultError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(VaultError::Api(format!(
                "token refresh failed with status {}",
                resp.status()
            )));
        }

        let body: TokenResponse = resp
            .json()
            .await
            .map_err(|e| VaultError::Api(format!("refresh: invalid response body: {e}")))?;

        self.session = Some(super::AuthSession {
            access_token:  body.access_token,
            refresh_token: body.refresh_token,
            token_type:    body.token_type,
            expires_in:    body.expires_in,
        });

        Ok(())
    }
}
