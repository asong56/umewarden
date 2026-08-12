use std::collections::HashMap;

use chrono::Utc;
use data_encoding::HEXLOWER;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use reqwest::{StatusCode, header};
use ring::digest::{Digest, SHA512_256, digest};
use serde::Serialize;
use url::Url;

use crate::{
    CONFIG,
    api::{EmptyResult, core::two_factor::duo::get_duo_keys_email},
    crypto,
    db::{
        DbConn, DbPool,
        models::{DeviceId, TwoFactorDuoContext},
    },
    error::{Error, EventType},
    http_client::make_http_request,
};

// redirect target is a bridge built into the Bitwarden clients themselves:
// https://github.com/bitwarden/clients/blob/5fb46df3415aefced0b52f2db86c873962255448/apps/web/src/connectors/duo-redirect.ts
const DUO_REDIRECT_LOCATION: &str = "duo-redirect-connector.html";

const JWT_VALIDITY_SECS: i64 = 300;

const CTX_VALIDITY_SECS: i64 = 300;

const DUO_RESP_SIGNATURE_ALG: Algorithm = Algorithm::HS512;

const JWT_SIGNATURE_ALG: Algorithm = Algorithm::HS512;

// 16-1024 chars; if raised past 64, also widen twofactor_duo_ctx.state/nonce columns (postgres/mariadb)
const STATE_LENGTH: usize = 64;

#[derive(Debug, Serialize, Deserialize)]
struct ClientAssertion {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub jti: String,
    pub iat: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthorizationRequest {
    pub response_type: String,
    pub scope: String,
    pub exp: i64,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub duo_uname: String,
    pub iss: String,
    pub aud: String,
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum HealthCheckResponse {
    HealthOK {
        stat: String,
    },
    HealthFail {
        message: String,
        message_detail: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct IdTokenResponse {
    id_token: String, // IdTokenClaims
    access_token: String,
    expires_in: i64,
    token_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdTokenClaims {
    preferred_username: String,
    nonce: String,
}

// https://duo.com/docs/oauthapi
struct DuoClient {
    client_id: String,     // Duo Client ID (DuoData.ik)
    client_secret: String, // Duo Client Secret (DuoData.sk)
    api_host: String,      // Duo API hostname (DuoData.host)
    redirect_uri: String,  // URL in this application clients should call for MFA verification
}

impl DuoClient {
    fn new(client_id: String, client_secret: String, api_host: String, redirect_uri: String) -> DuoClient {
        DuoClient {
            client_id,
            client_secret,
            api_host,
            redirect_uri,
        }
    }

    fn new_client_assertion(&self, url: &str) -> ClientAssertion {
        let now = Utc::now().timestamp();
        let jwt_id = crypto::get_random_string_alphanum(STATE_LENGTH);

        ClientAssertion {
            iss: self.client_id.clone(),
            sub: self.client_id.clone(),
            aud: url.to_owned(),
            exp: now + JWT_VALIDITY_SECS,
            jti: jwt_id,
            iat: now,
        }
    }

    fn encode_duo_jwt<T: Serialize>(&self, jwt_payload: T) -> Result<String, Error> {
        match jsonwebtoken::encode(
            &Header::new(JWT_SIGNATURE_ALG),
            &jwt_payload,
            &EncodingKey::from_secret(self.client_secret.as_bytes()),
        ) {
            Ok(token) => Ok(token),
            Err(e) => err!(format!("Error encoding Duo JWT: {e:?}")),
        }
    }

    // required health check: verifies config + Duo availability. https://duo.com/docs/oauthapi#health-check
    async fn health_check(&self) -> Result<(), Error> {
        let health_check_url: String = format!("https://{}/oauth/v1/health_check", self.api_host);

        let jwt_payload = self.new_client_assertion(&health_check_url);

        let token = match self.encode_duo_jwt(jwt_payload) {
            Ok(token) => token,
            Err(e) => return Err(e),
        };

        let mut post_body = HashMap::new();
        post_body.insert("client_assertion", token);
        post_body.insert("client_id", self.client_id.clone());

        let res = match make_http_request(reqwest::Method::POST, &health_check_url)?
            .header(header::USER_AGENT, "vaultwarden:Duo/2.0 (Rust)")
            .form(&post_body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => err!(format!("Error requesting Duo health check: {e:?}")),
        };

        let response: HealthCheckResponse = match res.json::<HealthCheckResponse>().await {
            Ok(r) => r,
            Err(e) => err!(format!("Duo health check response decode error: {e:?}")),
        };

        let health_stat: String = match response {
            HealthCheckResponse::HealthOK {
                stat,
            } => stat,
            HealthCheckResponse::HealthFail {
                message,
                message_detail,
            } => err!(format!("Duo health check FAIL response, msg: {message}, detail: {message_detail}")),
        };

        if health_stat != "OK" {
            err!(format!("Duo health check failed, got OK-like body with stat {health_stat}"));
        }

        Ok(())
    }

    // clients are redirected here to continue auth. https://duo.com/docs/oauthapi#authorization-request
    fn make_authz_req_url(&self, duo_username: &str, state: String, nonce: String) -> Result<String, Error> {
        let now = Utc::now().timestamp();

        let jwt_payload = AuthorizationRequest {
            response_type: String::from("code"),
            scope: String::from("openid"),
            exp: now + JWT_VALIDITY_SECS,
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            state,
            duo_uname: String::from(duo_username),
            iss: self.client_id.clone(),
            aud: format!("https://{}", self.api_host),
            nonce,
        };

        let token = self.encode_duo_jwt(jwt_payload)?;

        let authz_endpoint = format!("https://{}/oauth/v1/authorize", self.api_host);
        let mut auth_url = match Url::parse(authz_endpoint.as_str()) {
            Ok(url) => url,
            Err(e) => err!(format!("Error parsing Duo authorization URL: {e:?}")),
        };

        {
            let mut query_params = auth_url.query_pairs_mut();
            query_params.append_pair("response_type", "code");
            query_params.append_pair("client_id", self.client_id.as_str());
            query_params.append_pair("request", token.as_str());
        }

        let final_auth_url = auth_url.to_string();
        Ok(final_auth_url)
    }

    // https://duo.com/docs/oauthapi#access-token (under Response Format)
    async fn exchange_authz_code_for_result(
        &self,
        duo_code: &str,
        duo_username: &str,
        nonce: &str,
    ) -> Result<(), Error> {
        if duo_code.is_empty() {
            err!("Empty Duo authorization code")
        }

        let token_url = format!("https://{}/oauth/v1/token", self.api_host);

        let jwt_payload = self.new_client_assertion(&token_url);

        let token = match self.encode_duo_jwt(jwt_payload) {
            Ok(token) => token,
            Err(e) => return Err(e),
        };

        let mut post_body = HashMap::new();
        post_body.insert("grant_type", String::from("authorization_code"));
        post_body.insert("code", String::from(duo_code));

        post_body.insert("redirect_uri", self.redirect_uri.clone());

        post_body
            .insert("client_assertion_type", String::from("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
        post_body.insert("client_assertion", token);

        let res = match make_http_request(reqwest::Method::POST, &token_url)?
            .header(header::USER_AGENT, "vaultwarden:Duo/2.0 (Rust)")
            .form(&post_body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => err!(format!("Error exchanging Duo code: {e:?}")),
        };

        let status_code = res.status();
        if status_code != StatusCode::OK {
            err!(format!("Failure response from Duo: {status_code}"))
        }

        let response: IdTokenResponse = match res.json::<IdTokenResponse>().await {
            Ok(r) => r,
            Err(e) => err!(format!("Error decoding ID token response: {e:?}")),
        };

        let mut validation = Validation::new(DUO_RESP_SIGNATURE_ALG);
        validation.set_required_spec_claims(&["exp", "aud", "iss"]);
        validation.set_audience(&[&self.client_id]);
        validation.set_issuer(&[token_url.as_str()]);

        let token_data = match jsonwebtoken::decode::<IdTokenClaims>(
            &response.id_token,
            &DecodingKey::from_secret(self.client_secret.as_bytes()),
            &validation,
        ) {
            Ok(c) => c,
            Err(e) => err!(format!("Failed to decode Duo token {e:?}")),
        };

        let matching_nonces = crypto::ct_eq(nonce, &token_data.claims.nonce);
        let matching_usernames = crypto::ct_eq(duo_username, &token_data.claims.preferred_username);

        if !(matching_nonces && matching_usernames) {
            err!("Error validating Duo authorization, nonce or username mismatch.")
        }

        Ok(())
    }
}

struct DuoAuthContext {
    pub state: String,
    pub user_email: String,
    pub nonce: String,
    pub exp: i64,
}

async fn extract_context(state: &str, conn: &DbConn) -> Option<DuoAuthContext> {
    let ctx: TwoFactorDuoContext = match TwoFactorDuoContext::find_by_state(state, conn).await {
        Some(c) => c,
        None => return None,
    };

    if ctx.exp < Utc::now().timestamp() {
        ctx.delete(conn).await.ok();
        return None;
    }

    let ret_ctx = DuoAuthContext {
        state: ctx.state.clone(),
        user_email: ctx.user_email.clone(),
        nonce: ctx.nonce.clone(),
        exp: ctx.exp,
    };

    ctx.delete(conn).await.ok();
    Some(ret_ctx)
}

pub async fn purge_duo_contexts(pool: DbPool) {
    debug!("Purging Duo authentication contexts");
    if let Ok(conn) = pool.get().await {
        TwoFactorDuoContext::purge_expired_duo_contexts(&conn).await;
    } else {
        error!("Failed to get DB connection while purging expired Duo authentications");
    }
}

fn make_callback_url(client_name: &str) -> Result<String, Error> {
    let base = match Url::parse(&format!("{}/", CONFIG.domain())) {
        Ok(url) => url,
        Err(e) => err!(format!("Error parsing configured domain URL (check your domain configuration): {e:?}")),
    };

    let mut callback = match base.join(DUO_REDIRECT_LOCATION) {
        Ok(url) => url,
        Err(e) => err!(format!("Error constructing Duo redirect URL (check your domain configuration): {e:?}")),
    };

    // 'client' param: the callback connector branches on this to handle different client types
    {
        let mut query_params = callback.query_pairs_mut();
        query_params.append_pair("client", client_name);
    }
    Ok(callback.to_string())
}

// Stage 1: returns the "AuthUrl" clients redirect to for MFA.
pub async fn get_duo_auth_url(
    email: &str,
    client_id: &str,
    device_identifier: &DeviceId,
    conn: &DbConn,
) -> Result<String, Error> {
    let (ik, sk, _, host) = get_duo_keys_email(email, conn).await?;

    let callback_url = match make_callback_url(client_id) {
        Ok(url) => url,
        Err(e) => return Err(e),
    };

    let client = DuoClient::new(ik, sk, host, callback_url);

    match client.health_check().await {
        Ok(()) => {}
        Err(e) => return Err(e),
    }

    let state: String = crypto::get_random_string_alphanum(STATE_LENGTH);
    let nonce: String = crypto::get_random_string_alphanum(STATE_LENGTH);

    // OIDC nonce sent is actually hash(nonce, device_id), binding it to this device
    let d: Digest = digest(&SHA512_256, format!("{nonce}{device_identifier}").as_bytes());
    let hash: String = HEXLOWER.encode(d.as_ref());

    match TwoFactorDuoContext::save(state.as_str(), email, nonce.as_str(), CTX_VALIDITY_SECS, conn).await {
        Ok(()) => client.make_authz_req_url(email, state, hash),
        Err(e) => err!(format!("Error saving Duo authentication context: {e:?}")),
    }
}

// Stage 2: exchanges the authz code for the MFA result with Duo's API and validates it.
pub async fn validate_duo_login(
    email: &str,
    two_factor_token: &str,
    client_id: &str,
    device_identifier: &DeviceId,
    conn: &DbConn,
) -> EmptyResult {
    let split: Vec<&str> = two_factor_token.split('|').collect();
    if split.len() != 2 {
        err!(
            "Invalid response length",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        );
    }

    let code = split[0];
    let state = split[1];

    let (ik, sk, _, host) = get_duo_keys_email(email, conn).await?;

    let Some(ctx) = extract_context(state, conn).await else {
        err!(
            "Error validating duo authentication",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        )
    };

    // Context validation steps
    let matching_usernames = crypto::ct_eq(email, &ctx.user_email);

    // Probably redundant, but we're double-checking them anyway.
    let matching_states = crypto::ct_eq(state, &ctx.state);
    let unexpired_context = ctx.exp > Utc::now().timestamp();

    if !(matching_usernames && matching_states && unexpired_context) {
        err!(
            "Error validating duo authentication",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        )
    }

    let callback_url = match make_callback_url(client_id) {
        Ok(url) => url,
        Err(e) => return Err(e),
    };

    let client = DuoClient::new(ik, sk, host, callback_url);

    match client.health_check().await {
        Ok(()) => {}
        Err(e) => return Err(e),
    }

    let d: Digest = digest(&SHA512_256, format!("{}{device_identifier}", ctx.nonce).as_bytes());
    let hash: String = HEXLOWER.encode(d.as_ref());

    match client.exchange_authz_code_for_result(code, email, hash.as_str()).await {
        Ok(()) => Ok(()),
        Err(_) => {
            err!(
                "Error validating duo authentication",
                ErrorEvent {
                    event: EventType::UserFailedLogIn2fa
                }
            )
        }
    }
}
