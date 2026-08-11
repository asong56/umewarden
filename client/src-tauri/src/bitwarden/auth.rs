/// Bitwarden 认证流程
///
/// 端点与字段格式经过与 Vaultwarden 实际行为核对（而非凭记忆假设）：
///   - POST {base}/identity/accounts/prelogin   — JSON body，响应字段是 camelCase
///       { "kdf": 0, "kdfIterations": 600000, "kdfMemory": null, "kdfParallelism": null }
///   - POST {base}/identity/connect/token       — **form-urlencoded**（不是 JSON！），
///       字段：grant_type, username, password(=master_password_hash), scope,
///             client_id, deviceType, deviceIdentifier, deviceName
///   - 2FA 需要时，/connect/token 返回 400，body 里是 PascalCase：
///       { "TwoFactorProviders": ["0"], "error": "invalid_grant",
///         "error_description": "Two factor required." }
///     （注意：prelogin 是 camelCase，token 端点错误体是 PascalCase —— 这是
///      Bitwarden identity server 历史遗留的不一致，不是我们写错了。）

use crate::crypto::keys::{self, DecryptContext, EncString, KdfParams, KdfType};
use crate::error::{VaultError, VaultResult};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::BitwardenClient;

// ─── Prelogin ─────────────────────────────────────────────────────────────────

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

// ─── Token endpoint（2FA 错误体）────────────────────────────────────────────────

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
    /// Bitwarden 在 token 响应里直接带上用户的 protected symmetric key（"Key" 字段），
    /// 省去了再发一次请求去取的步骤。
    #[serde(rename = "Key")]
    key: Option<String>,
}

/// 设备类型枚举值（Bitwarden 官方定义的一部分，桌面端相关的几个）
fn device_type_for_platform() -> u32 {
    #[cfg(target_os = "windows")]
    { 11 } // WindowsDesktop
    #[cfg(target_os = "macos")]
    { 12 } // MacOsDesktop
    #[cfg(target_os = "linux")]
    { 13 } // LinuxDesktop
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    { 21 } // UnknownBrowser 兜底（实际不会走到这个分支）
}

/// 登录成功后的完整产出：会话 + 立即可用的解密上下文
pub struct LoginOutcome {
    pub session:     super::AuthSession,
    pub decrypt_ctx: DecryptContext,
    pub kdf_params:  KdfParams,
}

/// 2FA 询问：当 /connect/token 因缺少二次验证码而失败时返回
#[derive(Debug)]
pub struct TwoFactorRequired {
    pub providers: Vec<String>,
}

impl BitwardenClient {
    /// Step 1：获取该邮箱账号的 KDF 参数
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

    /// 完整登录流程：prelogin → 本地派生 master key → POST /connect/token
    ///
    /// `two_factor`: 若服务器要求 2FA，调用方需要再次调用本方法并带上
    /// `Some((provider_type, code))`（provider_type 来自 TwoFactorRequired::providers[0]，
    /// 常见值 "0" = 身份验证器 App TOTP）。
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
            ("client_id", "cli".into()), // "cli" 是官方承认的 client_id 之一，自建 Vaultwarden 通常不做白名单校验
            ("deviceType", device_type_for_platform().to_string()),
            ("deviceIdentifier", device_id.to_string()),
            ("deviceName", "umewarden-client".into()),
        ];

        if let Some((provider, code)) = two_factor {
            form.push(("twoFactorProvider", provider.to_string()));
            form.push(("twoFactorToken", code.to_string()));
            // Server's ConnectData::two_factor_remember is `Option<i32>` (see
            // server/src/api/identity.rs), not a bool - "false" would fail Rocket's
            // form parsing and turn every 2FA login into a 400. Send "0" instead,
            // matching server/src/static/vault/vault-api.js's reference implementation.
            form.push(("twoFactorRemember", "0".into()));
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
            // 可能是 2FA required，也可能是密码错误 —— 区分开
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

        // 用 stretched master key 解密服务器返回的 protected symmetric key
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

    /// Token 刷新（refresh_token 换新的 access_token）
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

