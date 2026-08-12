//! Bitwarden Web API adapter: login+2FA, sync, cipher CRUD, push.
//! reqwest + rustls, no system OpenSSL. Docs: https://contributing.bitwarden.com/architecture/clients/

pub mod auth;
pub mod models;
pub mod sync;

use crate::error::{VaultError, VaultResult};
use reqwest::Client;
use serde::{Deserialize, Serialize};

// Clone is cheap (reqwest::Client is Arc-backed internally) - callers clone out
// of state.read().await so a network request never holds the lock across an await.
#[derive(Clone)]
pub struct BitwardenClient {
    pub base_url: String,
    pub client:   Client,
    pub session:  Option<AuthSession>,
}

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub access_token:  String,
    pub refresh_token: String,
    pub token_type:    String,
    pub expires_in:    u64,
}

impl BitwardenClient {
    pub fn new(base_url: impl Into<String>) -> VaultResult<Self> {
        let client = Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| VaultError::Network(e.to_string()))?;

        Ok(BitwardenClient {
            base_url: base_url.into(),
            client,
            session: None,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}
