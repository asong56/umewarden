use chrono::Utc;
use num_traits::FromPrimitive;
use rocket::{Route, form::{Form, FromForm}, serde::json::Json};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{
        ApiResult, EmptyResult, JsonResult,
        core::{
            accounts::{PreloginData, RegisterData, kdf_upgrade, prelogin, register},
            two_factor::{
                authenticator, duo, duo_oidc, email, enforce_2fa_policy, is_twofactor_provider_usable, webauthn,
                yubikey,
            },
        },
        master_password_policy,
        push::register_push_device,
    },
    auth,
    auth::{AuthMethod, ClientHeaders, ClientIp, ClientVersion},
    crypto,
    db::{
        DbConn,
        models::{
            AuthRequest, AuthRequestId, Device, DeviceId, Invitation, TwoFactor, TwoFactorIncomplete, TwoFactorType,
            User, UserId,
        },
    },
    error::{EventType, MapResult},
    mail,
    util,
};

pub fn routes() -> Vec<Route> {
    routes![login, post_prelogin, prelogin_password, identity_register, register_verification_email, register_finish]
}

#[post("/connect/token", data = "<data>")]
async fn login(
    data: Form<ConnectData>,
    client_header: ClientHeaders,
    client_version: Option<ClientVersion>,
    conn: DbConn,
) -> JsonResult {
    let data: ConnectData = data.into_inner();

    let mut user_id: Option<UserId> = None;

    let login_result = match data.grant_type.as_ref() {
        "refresh_token" => {
            check_is_some(data.refresh_token.as_ref(), "refresh_token cannot be blank")?;
            refresh_login(data, &conn, &client_header.ip).await
        }
        "password" => {
            check_is_some(data.client_id.as_ref(), "client_id cannot be blank")?;
            check_is_some(data.password.as_ref(), "password cannot be blank")?;
            check_is_some(data.scope.as_ref(), "scope cannot be blank")?;
            check_is_some(data.username.as_ref(), "username cannot be blank")?;

            check_is_some(data.device_identifier.as_ref(), "device_identifier cannot be blank")?;
            check_is_some(data.device_name.as_ref(), "device_name cannot be blank")?;
            check_is_some(data.device_type.as_ref(), "device_type cannot be blank")?;

            password_login(data, &mut user_id, &conn, &client_header.ip, client_version.as_ref()).await
        }
        "client_credentials" => {
            check_is_some(data.client_id.as_ref(), "client_id cannot be blank")?;
            check_is_some(data.client_secret.as_ref(), "client_secret cannot be blank")?;
            check_is_some(data.scope.as_ref(), "scope cannot be blank")?;

            check_is_some(data.device_identifier.as_ref(), "device_identifier cannot be blank")?;
            check_is_some(data.device_name.as_ref(), "device_name cannot be blank")?;
            check_is_some(data.device_type.as_ref(), "device_type cannot be blank")?;

            api_key_login(data, &mut user_id, &conn, &client_header.ip).await
        }
        "authorization_code" => err!("SSO sign-in is not available"),
        t => err!("Invalid type", t),
    };

    login_result
}

async fn refresh_login(data: ConnectData, conn: &DbConn, ip: &ClientIp) -> JsonResult {
    // 400 + {"error":"invalid_grant"} is what the client specifically checks for here:
    // https://github.com/bitwarden/clients/blob/2ee158e720a5e7dbe3641caf80b569e97a1dd91b/libs/common/src/services/api.service.ts#L1786-L1797

    let Some(refresh_token) = data.refresh_token else {
        err_json!(json!({"error": "invalid_grant"}), "Missing refresh_token")
    };

    // org membership claim kept commented out, unused today but may be needed again -
    // see https://github.com/dani-garcia/vaultwarden/issues/4156
    // let members = Membership::find_confirmed_by_user(&user.uuid, conn).await;
    match auth::refresh_tokens(ip, &refresh_token, data.client_id, conn).await {
        Err(err) => {
            err_json!(
                json!({"error": "invalid_grant"}),
                format!("Unable to refresh login credentials: {}", err.message())
            )
        }
        Ok((mut device, auth_tokens)) => {
            device.save(true, conn).await?;

            let result = json!({
                "refresh_token": auth_tokens.refresh_token(),
                "access_token": auth_tokens.access_token(),
                "expires_in": auth_tokens.expires_in(),
                "token_type": "Bearer",
                "scope": auth_tokens.scope(),
            });

            Ok(Json(result))
        }
    }
}

async fn password_login(
    data: ConnectData,
    user_id: &mut Option<UserId>,
    conn: &DbConn,
    ip: &ClientIp,
    client_version: Option<&ClientVersion>,
) -> JsonResult {
    AuthMethod::Password.check_scope(data.scope.as_ref())?;

    crate::ratelimit::check_limit_login(&ip.ip)?;

    let username = data.username.as_ref().unwrap().trim();
    let Some(mut user) = User::find_by_mail(username, conn).await else {
        err!("Username or password is incorrect. Try again", format!("IP: {}. Username: {username}.", ip.ip))
    };

    *user_id = Some(user.uuid.clone());

    if !user.enabled {
        err!(
            "This user has been disabled",
            format!("IP: {}. Username: {username}.", ip.ip),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    let password = data.password.as_ref().unwrap();

    if let Some(ref auth_request_id) = data.auth_request {
        let Some(auth_request) = AuthRequest::find_by_uuid_and_user(auth_request_id, &user.uuid, conn).await else {
            err!(
                "Auth request not found. Try again.",
                format!("IP: {}. Username: {username}.", ip.ip),
                ErrorEvent {
                    event: EventType::UserFailedLogIn,
                }
            )
        };

        let expiration_time = auth_request.creation_date + chrono::Duration::minutes(5);
        let request_expired = Utc::now().naive_utc() >= expiration_time;

        if auth_request.user_uuid != user.uuid
            || !auth_request.approved.unwrap_or(false)
            || request_expired
            || ip.ip.to_string() != auth_request.request_ip
            || !auth_request.check_access_code(password)
        {
            err!(
                "Username or access code is incorrect. Try again",
                format!("IP: {}. Username: {username}.", ip.ip),
                ErrorEvent {
                    event: EventType::UserFailedLogIn,
                }
            )
        }
    } else if !user.check_valid_password(password) {
        err!(
            "Username or password is incorrect. Try again",
            format!("IP: {}. Username: {username}.", ip.ip),
            ErrorEvent {
                event: EventType::UserFailedLogIn,
            }
        )
    }

    if data.auth_request.is_none() {
        kdf_upgrade(&mut user, password, conn).await?;
    }

    let now = Utc::now().naive_utc();

    if user.verified_at.is_none() && CONFIG.mail_enabled() && CONFIG.signups_verify() {
        if user.last_verifying_at.is_none()
            || now.signed_duration_since(user.last_verifying_at.unwrap()).num_seconds()
                > CONFIG.signups_verify_resend_time().cast_signed()
        {
            let resend_limit = CONFIG.signups_verify_resend_limit().cast_signed();
            if resend_limit == 0 || user.login_verify_count < resend_limit {
                // resend verification if required and we haven't reminded them in a while
                user.last_verifying_at = Some(now);
                user.login_verify_count += 1;

                if let Err(e) = user.save(conn).await {
                    error!("Error updating user: {e:#?}");
                }

                if let Err(e) = mail::send_verify_email(&user.email, &user.uuid).await {
                    error!("Error auto-sending email verification email: {e:#?}");
                }
            }
        }

        err!(
            "Please verify your email before trying again.",
            format!("IP: {}. Username: {username}.", ip.ip),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    let mut device = get_device(&data, conn, &user).await?;

    let twofactor_token = twofactor_auth(&mut user, &data, &mut device, ip, client_version, conn).await?;

    let auth_tokens = auth::AuthTokens::new(&device, &user, AuthMethod::Password, data.client_id);

    authenticated_response(&user, &mut device, auth_tokens, twofactor_token, conn, ip).await
}

async fn authenticated_response(
    user: &User,
    device: &mut Device,
    auth_tokens: auth::AuthTokens,
    twofactor_token: Option<String>,
    conn: &DbConn,
    ip: &ClientIp,
) -> JsonResult {
    if CONFIG.mail_enabled() && device.is_new() {
        let now = Utc::now().naive_utc();
        if let Err(e) = mail::send_new_device_logged_in(&user.email, &ip.ip.to_string(), &now, device).await {
            error!("Error sending new device email: {e:#?}");

            if CONFIG.require_device_email() {
                err!(
                    "Could not send login notification email. Please contact your administrator.",
                    ErrorEvent {
                        event: EventType::UserFailedLogIn
                    }
                )
            }
        }
    }

    if !device.is_new() {
        register_push_device(device, conn).await?;
    }

    // Save to update `device.updated_at` to track usage and toggle new status
    device.save(true, conn).await?;

    let master_password_policy = master_password_policy(user, conn).await;

    let has_master_password = !user.password_hash.is_empty();
    let master_password_unlock = if has_master_password {
        json!({
            "Kdf": {
                "KdfType": user.client_kdf_type,
                "Iterations": user.client_kdf_iter,
                "Memory": user.client_kdf_memory,
                "Parallelism": user.client_kdf_parallelism
            },
            // inconsistently named upstream; will be replaced by a "wrapped" variant:
            // https://github.com/bitwarden/android/blob/release/2025.12-rc41/network/src/main/kotlin/com/bitwarden/network/model/MasterPasswordUnlockDataJson.kt#L22-L26
            "MasterKeyEncryptedUserKey": user.akey,
            "MasterKeyWrappedUserKey": user.akey,
            "Salt": user.email
        })
    } else {
        Value::Null
    };

    let account_keys = if user.private_key.is_some() {
        json!({
            "publicKeyEncryptionKeyPair": {
                "wrappedPrivateKey": user.private_key,
                "publicKey": user.public_key,
                "Object": "publicKeyEncryptionKeyPair"
            },
            "Object": "privateKeys"
        })
    } else {
        Value::Null
    };

    let mut result = json!({
        "access_token": auth_tokens.access_token(),
        "expires_in": auth_tokens.expires_in(),
        "token_type": "Bearer",
        "refresh_token": auth_tokens.refresh_token(),
        "PrivateKey": user.private_key,
        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "KdfMemory": user.client_kdf_memory,
        "KdfParallelism": user.client_kdf_parallelism,
        "ResetMasterPassword": false, // TODO: Same as above
        "ForcePasswordReset": false,
        "MasterPasswordPolicy": master_password_policy,
        "scope": auth_tokens.scope(),
        "AccountKeys": account_keys,
        "UserDecryptionOptions": {
            "HasMasterPassword": has_master_password,
            "MasterPasswordUnlock": master_password_unlock,
            "Object": "userDecryptionOptions"
        },
    });

    if !user.akey.is_empty() {
        result["Key"] = Value::String(user.akey.clone());
    }

    if let Some(token) = twofactor_token {
        result["TwoFactorToken"] = Value::String(token);
    }

    info!("User {} logged in successfully. IP: {}", user.display_name(), ip.ip);
    Ok(Json(result))
}

async fn api_key_login(data: ConnectData, user_id: &mut Option<UserId>, conn: &DbConn, ip: &ClientIp) -> JsonResult {
    crate::ratelimit::check_limit_login(&ip.ip)?;

    match data.scope.as_ref() {
        Some(scope) if scope == &AuthMethod::UserApiKey.scope() => user_api_key_login(data, user_id, conn, ip).await,
        _ => err!("Scope not supported"),
    }
}

async fn user_api_key_login(
    data: ConnectData,
    user_id: &mut Option<UserId>,
    conn: &DbConn,
    ip: &ClientIp,
) -> JsonResult {
    let client_id = data.client_id.as_ref().unwrap();
    let Some(client_user_id) = client_id.strip_prefix("user.") else {
        err!("Malformed client_id", format!("IP: {}.", ip.ip))
    };
    let client_user_id: UserId = client_user_id.into();
    let Some(user) = User::find_by_uuid(&client_user_id, conn).await else {
        err!("Invalid client_id", format!("IP: {}.", ip.ip))
    };

    *user_id = Some(user.uuid.clone());

    if !user.enabled {
        err!(
            "This user has been disabled (API key login)",
            format!("IP: {}. Username: {}.", ip.ip, user.email),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    let client_secret = data.client_secret.as_ref().unwrap();
    if !user.check_valid_api_key(client_secret) {
        err!(
            "Incorrect client_secret",
            format!("IP: {}. Username: {}.", ip.ip, user.email),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    let mut device = get_device(&data, conn, &user).await?;

    if CONFIG.mail_enabled() && device.is_new() {
        let now = Utc::now().naive_utc();
        if let Err(e) = mail::send_new_device_logged_in(&user.email, &ip.ip.to_string(), &now, &device).await {
            error!("Error sending new device email: {e:#?}");

            if CONFIG.require_device_email() {
                err!(
                    "Could not send login notification email. Please contact your administrator.",
                    ErrorEvent {
                        event: EventType::UserFailedLogIn
                    }
                )
            }
        }
    }

    // org membership claim disabled here too, see the note above
    // let orgs = Membership::find_confirmed_by_user(&user.uuid, conn).await;
    let access_claims = auth::LoginJwtClaims::default(&device, &user, &AuthMethod::UserApiKey, data.client_id);

    // Save to update `device.updated_at` to track usage and toggle new status
    device.save(true, conn).await?;

    info!("User {} logged in successfully via API key. IP: {}", user.email, ip.ip);

    let has_master_password = !user.password_hash.is_empty();
    let master_password_unlock = if has_master_password {
        json!({
            "Kdf": {
                "KdfType": user.client_kdf_type,
                "Iterations": user.client_kdf_iter,
                "Memory": user.client_kdf_memory,
                "Parallelism": user.client_kdf_parallelism
            },
            // This field is named inconsistently and will be removed and replaced by the "wrapped" variant in the apps.
            // https://github.com/bitwarden/android/blob/release/2025.12-rc41/network/src/main/kotlin/com/bitwarden/network/model/MasterPasswordUnlockDataJson.kt#L22-L26
            "MasterKeyEncryptedUserKey": user.akey,
            "MasterKeyWrappedUserKey": user.akey,
            "Salt": user.email
        })
    } else {
        Value::Null
    };

    let account_keys = if user.private_key.is_some() {
        json!({
            "publicKeyEncryptionKeyPair": {
                "wrappedPrivateKey": user.private_key,
                "publicKey": user.public_key,
                "Object": "publicKeyEncryptionKeyPair"
            },
            "Object": "privateKeys"
        })
    } else {
        Value::Null
    };

    // no refresh_token returned - CLI just repeats the client_credentials flow on expiry
    let result = json!({
        "access_token": access_claims.token(),
        "expires_in": access_claims.expires_in(),
        "token_type": "Bearer",
        "Key": user.akey,
        "PrivateKey": user.private_key,

        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "KdfMemory": user.client_kdf_memory,
        "KdfParallelism": user.client_kdf_parallelism,
        "ResetMasterPassword": false, // TODO: according to official server seems something like: user.password_hash.is_empty(), but would need testing
        "ForcePasswordReset": false,
        "scope": AuthMethod::UserApiKey.scope(),
        "AccountKeys": account_keys,
        "UserDecryptionOptions": {
            "HasMasterPassword": has_master_password,
            "MasterPasswordUnlock": master_password_unlock,
            "Object": "userDecryptionOptions"
        },
    });

    Ok(Json(result))
}

/// Retrieves an existing device or creates a new device from ConnectData and the User
async fn get_device(data: &ConnectData, conn: &DbConn, user: &User) -> ApiResult<Device> {
    // iOS sends "iOS" (a string) here instead of a number; anything unparseable -> 14 (Unknown Browser)
    let device_type = util::try_parse_string(data.device_type.as_ref()).unwrap_or(14);
    let device_id = data.device_identifier.clone().expect("No device id provided");
    let device_name = data.device_name.clone().expect("No device name provided");

    if let Some(device) = Device::find_by_uuid_and_user(&device_id, &user.uuid, conn).await {
        Ok(device)
    } else {
        let mut device = Device::new(device_id, user.uuid.clone(), device_name, device_type);
        device.save(false, conn).await?;
        Ok(device)
    }
}

async fn twofactor_auth(
    user: &mut User,
    data: &ConnectData,
    device: &mut Device,
    ip: &ClientIp,
    client_version: Option<&ClientVersion>,
    conn: &DbConn,
) -> ApiResult<Option<String>> {
    let twofactors = TwoFactor::find_by_user(&user.uuid, conn).await;

    if twofactors.is_empty() {
        enforce_2fa_policy(user, &user.uuid, device.atype, &ip.ip, conn).await?;
        return Ok(None);
    }

    TwoFactorIncomplete::mark_incomplete(&user.uuid, &device.uuid, &device.name, device.atype, ip, conn).await?;

    let twofactor_ids: Vec<_> = twofactors
        .iter()
        .filter_map(|tf| {
            let provider_type = TwoFactorType::from_i32(tf.atype)?;
            (tf.enabled && is_twofactor_provider_usable(&provider_type, Some(&tf.data))).then_some(tf.atype)
        })
        .collect();
    if twofactor_ids.is_empty() {
        err!("No enabled and usable two factor providers are available for this account")
    }

    let selected_id = data.two_factor_provider.unwrap_or(twofactor_ids[0]); // If we aren't given a two factor provider, assume the first one
    if ![TwoFactorType::Remember as i32, TwoFactorType::RecoveryCode as i32].contains(&selected_id)
        && !twofactor_ids.contains(&selected_id)
    {
        err_json!(
            json_err_twofactor(&twofactor_ids, &user.uuid, data, client_version, conn).await?,
            "Invalid two factor provider"
        )
    }

    let Some(ref twofactor_code) = data.two_factor_token else {
        err_json!(
            json_err_twofactor(&twofactor_ids, &user.uuid, data, client_version, conn).await?,
            "2FA token not provided"
        )
    };

    let selected_twofactor = twofactors.into_iter().find(|tf| tf.atype == selected_id && tf.enabled);

    let selected_data = selected_data(selected_twofactor);

    match TwoFactorType::from_i32(selected_id) {
        Some(TwoFactorType::Authenticator) => {
            authenticator::validate_totp_code_str(&user.uuid, twofactor_code, &selected_data?, ip, conn).await?;
        }
        Some(TwoFactorType::Webauthn) => webauthn::validate_webauthn_login(&user.uuid, twofactor_code, conn).await?,
        Some(TwoFactorType::YubiKey) => yubikey::validate_yubikey_login(twofactor_code, &selected_data?).await?,
        Some(TwoFactorType::Duo) => {
            if CONFIG.duo_use_iframe() {
                duo::validate_duo_login(&user.email, twofactor_code, conn).await?;
            } else {
                duo_oidc::validate_duo_login(
                    &user.email,
                    twofactor_code,
                    data.client_id.as_ref().unwrap(),
                    data.device_identifier.as_ref().unwrap(),
                    conn,
                )
                .await?;
            }
        }
        Some(TwoFactorType::Email) => {
            email::validate_email_code_str(&user.uuid, twofactor_code, &selected_data?, &ip.ip, conn).await?;
        }
        Some(TwoFactorType::Remember) => {
            match device.twofactor_remember {
                // valid remember-token JWT skips the 2FA prompt entirely; invalid falls through to it
                Some(ref token)
                    if !CONFIG.disable_2fa_remember()
                        && (crypto::ct_eq(token, twofactor_code)
                            && auth::decode_2fa_remember(twofactor_code)
                                .is_ok_and(|t| t.sub == device.uuid && t.user_uuid == user.uuid)) => {}
                _ => {
                    if device.twofactor_remember.is_some() {
                        device.delete_twofactor_remember();
                        // must save now: the err_json!() below returns early, skipping the later save
                        device.save(true, conn).await?;
                    }
                    err_json!(
                        json_err_twofactor(&twofactor_ids, &user.uuid, data, client_version, conn).await?,
                        "2FA Remember token not provided or expired"
                    )
                }
            }
        }
        Some(TwoFactorType::RecoveryCode) => {
            if !user.check_valid_recovery_code(twofactor_code) {
                err!("Recovery code is incorrect. Try again.")
            }

            TwoFactor::delete_all_by_user(&user.uuid, conn).await?;
            enforce_2fa_policy(user, &user.uuid, device.atype, &ip.ip, conn).await?;


            user.totp_recover = None;
            user.save(conn).await?;
        }
        _ => err!(
            "Invalid two factor provider",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        ),
    }

    TwoFactorIncomplete::mark_complete(&user.uuid, &device.uuid, conn).await?;

    let remember = data.two_factor_remember.unwrap_or(0);
    let two_factor = if !CONFIG.disable_2fa_remember() && remember == 1 {
        Some(device.refresh_twofactor_remember())
    } else {
        None
    };
    Ok(two_factor)
}

fn selected_data(tf: Option<TwoFactor>) -> ApiResult<String> {
    tf.map(|t| t.data).map_res("Two factor doesn't exist")
}

async fn json_err_twofactor(
    providers: &[i32],
    user_id: &UserId,
    data: &ConnectData,
    client_version: Option<&ClientVersion>,
    conn: &DbConn,
) -> ApiResult<Value> {
    let mut result = json!({
        "error" : "invalid_grant",
        "error_description" : "Two factor required.",
        "TwoFactorProviders" : providers.iter().map(ToString::to_string).collect::<Vec<String>>(),
        "TwoFactorProviders2" : {}, // { "0" : null }
        "MasterPasswordPolicy": {
            "Object": "masterPasswordPolicy"
        }
    });

    for provider in providers {
        result["TwoFactorProviders2"][provider.to_string()] = Value::Null;

        match TwoFactorType::from_i32(*provider) {
            Some(TwoFactorType::Webauthn) if CONFIG.is_webauthn_2fa_supported() => {
                let request = webauthn::generate_webauthn_login(user_id, conn).await?;
                result["TwoFactorProviders2"][provider.to_string()] = request.0;
            }

            Some(TwoFactorType::Duo) => {
                let email = if let Some(u) = User::find_by_uuid(user_id, conn).await {
                    u.email
                } else {
                    err!("User does not exist")
                };

                if CONFIG.duo_use_iframe() {
                        let (signature, host) = duo::generate_duo_signature(&email, conn).await?;
                    result["TwoFactorProviders2"][provider.to_string()] = json!({
                        "Host": host,
                        "Signature": signature,
                    });
                } else {
                        let auth_url = duo_oidc::get_duo_auth_url(
                        &email,
                        data.client_id.as_ref().unwrap(),
                        data.device_identifier.as_ref().unwrap(),
                        conn,
                    )
                    .await?;

                    result["TwoFactorProviders2"][provider.to_string()] = json!({
                        "AuthUrl": auth_url,
                    });
                }
            }

            Some(tf_type @ TwoFactorType::YubiKey) => {
                let Some(twofactor) = TwoFactor::find_by_user_and_type(user_id, tf_type as i32, conn).await else {
                    err!("No YubiKey devices registered")
                };

                let yubikey_metadata: yubikey::YubikeyMetadata = serde_json::from_str(&twofactor.data)?;

                result["TwoFactorProviders2"][provider.to_string()] = json!({
                    "Nfc": yubikey_metadata.nfc,
                });
            }

            Some(tf_type @ TwoFactorType::Email) => {
                let Some(twofactor) = TwoFactor::find_by_user_and_type(user_id, tf_type as i32, conn).await else {
                    err!("No twofactor email registered")
                };

                // clients since 2025.5.0 call /api/two-factor/send-email-login instead of this path
                let disabled_send = if let Some(cv) = client_version {
                    let ver_match = semver::VersionReq::parse(">=2025.5.0").unwrap();
                    ver_match.matches(&cv.0)
                } else {
                    false
                };

                if providers.len() == 1 && !disabled_send {
                    email::send_token(user_id, conn).await?;
                }

                let email_data = email::EmailTokenData::from_json(&twofactor.data)?;
                result["TwoFactorProviders2"][provider.to_string()] = json!({
                    "Email": email::obscure_email(&email_data.email),
                });
            }

            None
            | Some(
                TwoFactorType::Authenticator
                | TwoFactorType::EmailVerificationChallenge
                | TwoFactorType::OrganizationDuo
                | TwoFactorType::ProtectedActions
                | TwoFactorType::RecoveryCode
                | TwoFactorType::Remember
                | TwoFactorType::U2f
                | TwoFactorType::U2fLoginChallenge
                | TwoFactorType::U2fRegisterChallenge
                | TwoFactorType::Webauthn
                | TwoFactorType::WebauthnLoginChallenge
                | TwoFactorType::WebauthnRegisterChallenge,
            ) => { /* Nothing special to do for these providers */ }
        }
    }

    Ok(result)
}

#[post("/accounts/prelogin", data = "<data>")]
async fn post_prelogin(data: Json<PreloginData>, conn: DbConn) -> Json<Value> {
    prelogin(data, conn).await
}

#[post("/accounts/prelogin/password", data = "<data>")]
async fn prelogin_password(data: Json<PreloginData>, conn: DbConn) -> Json<Value> {
    prelogin(data, conn).await
}

#[post("/accounts/register", data = "<data>")]
async fn identity_register(data: Json<RegisterData>, conn: DbConn) -> JsonResult {
    register(data, false, conn).await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterVerificationData {
    email: String,
    name: Option<String>,
}

#[derive(rocket::Responder)]
enum RegisterVerificationResponse {
    #[response(status = 204)]
    NoContent(()),
    Token(Json<String>),
}

#[post("/accounts/register/send-verification-email", data = "<data>")]
async fn register_verification_email(
    data: Json<RegisterVerificationData>,
    ip: ClientIp,
    conn: DbConn,
) -> ApiResult<RegisterVerificationResponse> {
    crate::ratelimit::check_limit_unauthenticated(&ip.ip)?;

    let data = data.into_inner();

    if !(CONFIG.is_signup_allowed(&data.email)
        || (!CONFIG.mail_enabled() && Invitation::find_by_mail(&data.email, &conn).await.is_some()))
    {
        err!("Registration not allowed or user already exists")
    }

    let should_send_mail = CONFIG.mail_enabled() && CONFIG.signups_verify();

    let token_claims = auth::generate_register_verify_claims(data.email.clone(), data.name.clone(), should_send_mail);
    let token = auth::encode_jwt(&token_claims);

    if should_send_mail {
        let user = User::find_by_mail(&data.email, &conn).await;
        if user.as_ref().is_some_and(|u| u.private_key.is_some()) {
            // mail-sending paths are noticeably slower than non-mail ones; randomized sleep
            // is a partial mitigation for the resulting timing side channel
            use rand::{RngExt, rngs::SmallRng};
            let mut rng: SmallRng = rand::make_rng();
            let sleep_ms: u64 = rng.random_range(900..=1100);
            tokio::time::sleep(tokio::time::Duration::from_millis(sleep_ms)).await;
        } else {
            mail::send_register_verify_email(&data.email, &token).await?;
        }

        Ok(RegisterVerificationResponse::NoContent(()))
    } else {
        // token returned directly when verification isn't required; client uses it to finish registration
        Ok(RegisterVerificationResponse::Token(Json(token)))
    }
}

#[post("/accounts/register/finish", data = "<data>")]
async fn register_finish(data: Json<RegisterData>, conn: DbConn) -> JsonResult {
    register(data, true, conn).await
}

// https://github.com/bitwarden/jslib/blob/master/common/src/models/request/tokenRequest.ts
// https://github.com/bitwarden/mobile/blob/master/src/Core/Models/Request/TokenRequest.cs
#[derive(Debug, Clone, Default, FromForm)]
struct ConnectData {
    #[field(name = uncased("grant_type"))]
    #[field(name = uncased("granttype"))]
    grant_type: String, // refresh_token, password, client_credentials (API key)

    #[field(name = uncased("refresh_token"))]
    #[field(name = uncased("refreshtoken"))]
    refresh_token: Option<String>,

    #[field(name = uncased("client_id"))]
    #[field(name = uncased("clientid"))]
    client_id: Option<String>, // web, cli, desktop, browser, mobile
    #[field(name = uncased("client_secret"))]
    #[field(name = uncased("clientsecret"))]
    client_secret: Option<String>,
    #[field(name = uncased("password"))]
    password: Option<String>,
    #[field(name = uncased("scope"))]
    scope: Option<String>,
    #[field(name = uncased("username"))]
    username: Option<String>,

    #[field(name = uncased("device_identifier"))]
    #[field(name = uncased("deviceidentifier"))]
    device_identifier: Option<DeviceId>,
    #[field(name = uncased("device_name"))]
    #[field(name = uncased("devicename"))]
    device_name: Option<String>,
    #[field(name = uncased("device_type"))]
    #[field(name = uncased("devicetype"))]
    device_type: Option<String>,
    #[allow(unused)]
    #[field(name = uncased("device_push_token"))]
    #[field(name = uncased("devicepushtoken"))]
    _device_push_token: Option<String>, // Unused; mobile device push not yet supported.

    #[field(name = uncased("two_factor_provider"))]
    #[field(name = uncased("twofactorprovider"))]
    two_factor_provider: Option<i32>,
    #[field(name = uncased("two_factor_token"))]
    #[field(name = uncased("twofactortoken"))]
    two_factor_token: Option<String>,
    #[field(name = uncased("two_factor_remember"))]
    #[field(name = uncased("twofactorremember"))]
    two_factor_remember: Option<i32>,
    #[field(name = uncased("authrequest"))]
    auth_request: Option<AuthRequestId>,
}
fn check_is_some<T>(value: Option<&T>, msg: &str) -> EmptyResult {
    if value.is_none() {
        err!(msg)
    }
    Ok(())
}

