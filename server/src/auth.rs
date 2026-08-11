use std::{
    env,
    net::IpAddr,
    sync::{LazyLock, OnceLock},
};

use chrono::{DateTime, TimeDelta, Utc};
use ipnet::IpNet;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, errors::ErrorKind};
use num_traits::FromPrimitive;
use openssl::rsa::Rsa;
use serde::{de::DeserializeOwned, ser::Serialize};

use rocket::{
    outcome::try_outcome,
    request::{FromRequest, Outcome, Request},
};

use crate::{
    CONFIG,
    api::ApiResult,
    config::PathType,
    db::{
        DbConn,
        models::{
            AttachmentId, CipherId, Device, DeviceId, DeviceType, MembershipId, OrganizationId, User, UserId,
            UserStampException,
        },
    },
    error::Error,
};

const JWT_ALGORITHM: Algorithm = Algorithm::RS256;

// Limit when BitWarden consider the token as expired
pub static BW_EXPIRATION: LazyLock<TimeDelta> = LazyLock::new(|| TimeDelta::try_minutes(5).unwrap());

pub static DEFAULT_REFRESH_VALIDITY: LazyLock<TimeDelta> = LazyLock::new(|| TimeDelta::try_days(30).unwrap());
pub static MOBILE_REFRESH_VALIDITY: LazyLock<TimeDelta> = LazyLock::new(|| TimeDelta::try_days(90).unwrap());
pub static DEFAULT_ACCESS_VALIDITY: LazyLock<TimeDelta> = LazyLock::new(|| TimeDelta::try_hours(2).unwrap());
static JWT_HEADER: LazyLock<Header> = LazyLock::new(|| Header::new(JWT_ALGORITHM));

pub static JWT_LOGIN_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|login", CONFIG.domain_origin()));
static JWT_INVITE_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|invite", CONFIG.domain_origin()));
static JWT_DELETE_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|delete", CONFIG.domain_origin()));
static JWT_VERIFYEMAIL_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|verifyemail", CONFIG.domain_origin()));
static JWT_ADMIN_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|admin", CONFIG.domain_origin()));
static JWT_FILE_DOWNLOAD_ISSUER: LazyLock<String> =
    LazyLock::new(|| format!("{}|file_download", CONFIG.domain_origin()));
static JWT_REGISTER_VERIFY_ISSUER: LazyLock<String> =
    LazyLock::new(|| format!("{}|register_verify", CONFIG.domain_origin()));
static JWT_2FA_REMEMBER_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|2faremember", CONFIG.domain_origin()));

static PRIVATE_RSA_KEY: OnceLock<EncodingKey> = OnceLock::new();
static PUBLIC_RSA_KEY: OnceLock<DecodingKey> = OnceLock::new();

pub async fn initialize_keys() -> Result<(), Error> {
    use std::io::Error as IoError;

    let rsa_key_filename = crate::storage::file_name(&CONFIG.private_rsa_key())
        .ok_or_else(|| IoError::other("Private RSA key path missing filename"))?;

    let operator = CONFIG.opendal_operator_for_path_type(&PathType::RsaKey).map_err(IoError::other)?;

    let priv_key_buffer = match operator.read(&rsa_key_filename).await {
        Ok(buffer) => Some(buffer),
        Err(e) if e.kind() == opendal::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };

    let (priv_key, priv_key_buffer) = if let Some(priv_key_buffer) = priv_key_buffer {
        (Rsa::private_key_from_pem(priv_key_buffer.to_vec().as_slice())?, priv_key_buffer.to_vec())
    } else {
        let rsa_key = Rsa::generate(2048)?;
        let priv_key_buffer = rsa_key.private_key_to_pem()?;
        operator.write(&rsa_key_filename, priv_key_buffer.clone()).await?;
        info!("Private key '{}' created correctly", CONFIG.private_rsa_key());
        (rsa_key, priv_key_buffer)
    };
    let pub_key_buffer = priv_key.public_key_to_pem()?;

    let enc = EncodingKey::from_rsa_pem(&priv_key_buffer)?;
    let dec: DecodingKey = DecodingKey::from_rsa_pem(&pub_key_buffer)?;
    if PRIVATE_RSA_KEY.set(enc).is_err() {
        err!("PRIVATE_RSA_KEY must only be initialized once")
    }
    if PUBLIC_RSA_KEY.set(dec).is_err() {
        err!("PUBLIC_RSA_KEY must only be initialized once")
    }
    Ok(())
}

pub fn encode_jwt<T: Serialize>(claims: &T) -> String {
    match jsonwebtoken::encode(&JWT_HEADER, claims, PRIVATE_RSA_KEY.wait()) {
        Ok(token) => token,
        Err(e) => panic!("Error encoding jwt {e}"),
    }
}

pub fn decode_jwt<T: DeserializeOwned>(token: &str, issuer: String) -> Result<T, Error> {
    let mut validation = jsonwebtoken::Validation::new(JWT_ALGORITHM);
    validation.leeway = 30; // 30 seconds
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.set_issuer(&[issuer]);

    let token = token.replace(char::is_whitespace, "");
    match jsonwebtoken::decode(&token, PUBLIC_RSA_KEY.wait(), &validation) {
        Ok(d) => Ok(d.claims),
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => err!("Token is invalid"),
            ErrorKind::InvalidIssuer => err!("Issuer is invalid"),
            ErrorKind::ExpiredSignature => err!("Token has expired"),
            _ => err!(format!("Error decoding JWT: {:?}", err)),
        },
    }
}

pub fn decode_refresh(token: &str) -> Result<RefreshJwtClaims, Error> {
    decode_jwt(token, JWT_LOGIN_ISSUER.to_string())
}

pub fn decode_login(token: &str) -> Result<LoginJwtClaims, Error> {
    decode_jwt(token, JWT_LOGIN_ISSUER.to_string())
}

pub fn decode_invite(token: &str) -> Result<InviteJwtClaims, Error> {
    decode_jwt(token, JWT_INVITE_ISSUER.to_string())
}

pub fn decode_delete(token: &str) -> Result<BasicJwtClaims, Error> {
    decode_jwt(token, JWT_DELETE_ISSUER.to_string())
}

pub fn decode_verify_email(token: &str) -> Result<BasicJwtClaims, Error> {
    decode_jwt(token, JWT_VERIFYEMAIL_ISSUER.to_string())
}

pub fn decode_admin(token: &str) -> Result<BasicJwtClaims, Error> {
    decode_jwt(token, JWT_ADMIN_ISSUER.to_string())
}

pub fn decode_file_download(token: &str) -> Result<FileDownloadClaims, Error> {
    decode_jwt(token, JWT_FILE_DOWNLOAD_ISSUER.to_string())
}

pub fn decode_register_verify(token: &str) -> Result<RegisterVerifyClaims, Error> {
    decode_jwt(token, JWT_REGISTER_VERIFY_ISSUER.to_string())
}

pub fn decode_2fa_remember(token: &str) -> Result<TwoFactorRememberClaims, Error> {
    decode_jwt(token, JWT_2FA_REMEMBER_ISSUER.to_string())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: UserId,

    pub premium: bool,
    pub name: String,
    pub email: String,
    pub email_verified: bool,

    // ---
    // Disabled these keys to be added to the JWT since they could cause the JWT to get too large
    // Also These key/value pairs are not used anywhere by either Vaultwarden or Bitwarden Clients
    // Because these might get used in the future, and they are added by the Bitwarden Server, lets keep it, but then commented out
    // See: https://github.com/dani-garcia/vaultwarden/issues/4156
    // ---
    // pub orgowner: Vec<String>,
    // pub orgadmin: Vec<String>,
    // pub orguser: Vec<String>,
    // pub orgmanager: Vec<String>,

    // user security_stamp
    pub sstamp: String,
    // device uuid
    pub device: DeviceId,
    // what kind of device, like FirefoxBrowser or Android derived from DeviceType
    pub devicetype: String,
    // the type of client_id, like web, cli, desktop, browser or mobile
    pub client_id: String,

    // [ "api", "offline_access" ]
    pub scope: Vec<String>,
    // [ "Application" ]
    pub amr: Vec<String>,
}

impl LoginJwtClaims {
    pub fn new(
        device: &Device,
        user: &User,
        nbf: i64,
        exp: i64,
        scope: Vec<String>,
        client_id: Option<String>,
        now: DateTime<Utc>,
    ) -> Self {
        // ---
        // Disabled these keys to be added to the JWT since they could cause the JWT to get too large
        // Also These key/value pairs are not used anywhere by either Vaultwarden or Bitwarden Clients
        // Because these might get used in the future, and they are added by the Bitwarden Server, lets keep it, but then commented out
        // ---
        // fn arg: orgs: Vec<super::UserOrganization>,
        // ---
        // let orgowner: Vec<_> = orgs.iter().filter(|o| o.atype == 0).map(|o| o.org_uuid.clone()).collect();
        // let orgadmin: Vec<_> = orgs.iter().filter(|o| o.atype == 1).map(|o| o.org_uuid.clone()).collect();
        // let orguser: Vec<_> = orgs.iter().filter(|o| o.atype == 2).map(|o| o.org_uuid.clone()).collect();
        // let orgmanager: Vec<_> = orgs.iter().filter(|o| o.atype == 3).map(|o| o.org_uuid.clone()).collect();

        if exp <= (now + *BW_EXPIRATION).timestamp() {
            warn!("Raise access_token lifetime to more than 5min.");
        }

        // Create the JWT claims struct, to send to the client
        Self {
            nbf,
            exp,
            iss: JWT_LOGIN_ISSUER.to_string(),
            sub: user.uuid.clone(),
            premium: true,
            name: user.name.clone(),
            email: user.email.clone(),
            email_verified: !CONFIG.mail_enabled() || user.verified_at.is_some(),

            // ---
            // Disabled these keys to be added to the JWT since they could cause the JWT to get too large
            // Also These key/value pairs are not used anywhere by either Vaultwarden or Bitwarden Clients
            // Because these might get used in the future, and they are added by the Bitwarden Server, lets keep it, but then commented out
            // See: https://github.com/dani-garcia/vaultwarden/issues/4156
            // ---
            // orgowner,
            // orgadmin,
            // orguser,
            // orgmanager,
            sstamp: user.security_stamp.clone(),
            device: device.uuid.clone(),
            devicetype: DeviceType::from_i32(device.atype).to_string(),
            client_id: client_id.unwrap_or("undefined".to_owned()),
            scope,
            amr: vec!["Application".into()],
        }
    }

    pub fn default(device: &Device, user: &User, auth_method: &AuthMethod, client_id: Option<String>) -> Self {
        let time_now = Utc::now();
        Self::new(
            device,
            user,
            time_now.timestamp(),
            (time_now + *DEFAULT_ACCESS_VALIDITY).timestamp(),
            auth_method.scope_vec(),
            client_id,
            time_now,
        )
    }

    pub fn token(&self) -> String {
        encode_jwt(&self)
    }

    pub fn expires_in(&self) -> i64 {
        self.exp - Utc::now().timestamp()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InviteJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: UserId,

    pub email: String,
    pub org_id: OrganizationId,
    pub member_id: MembershipId,
    pub invited_by_email: Option<String>,
}

pub fn generate_invite_claims(
    user_id: UserId,
    email: String,
    org_id: OrganizationId,
    member_id: MembershipId,
    invited_by_email: Option<String>,
) -> InviteJwtClaims {
    let time_now = Utc::now();
    let expire_hours = i64::from(CONFIG.invitation_expiration_hours());
    InviteJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_hours(expire_hours).unwrap()).timestamp(),
        iss: JWT_INVITE_ISSUER.to_string(),
        sub: user_id,
        email,
        org_id,
        member_id,
        invited_by_email,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileDownloadClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: CipherId,

    pub file_id: AttachmentId,
}

pub fn generate_file_download_claims(cipher_id: CipherId, file_id: AttachmentId) -> FileDownloadClaims {
    let time_now = Utc::now();
    FileDownloadClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_minutes(5).unwrap()).timestamp(),
        iss: JWT_FILE_DOWNLOAD_ISSUER.to_string(),
        sub: cipher_id,
        file_id,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterVerifyClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,

    pub name: Option<String>,
    pub verified: bool,
}

pub fn generate_register_verify_claims(email: String, name: Option<String>, verified: bool) -> RegisterVerifyClaims {
    let time_now = Utc::now();
    RegisterVerifyClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_minutes(30).unwrap()).timestamp(),
        iss: JWT_REGISTER_VERIFY_ISSUER.to_string(),
        sub: email,
        name,
        verified,
    }
}

#[derive(Serialize, Deserialize)]
pub struct TwoFactorRememberClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: DeviceId,
    // UserId
    pub user_uuid: UserId,
}

pub fn generate_2fa_remember_claims(device_uuid: DeviceId, user_uuid: UserId) -> TwoFactorRememberClaims {
    let time_now = Utc::now();
    TwoFactorRememberClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_days(30).unwrap()).timestamp(),
        iss: JWT_2FA_REMEMBER_ISSUER.to_string(),
        sub: device_uuid,
        user_uuid,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BasicJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,
}

impl BasicJwtClaims {
    pub fn expires_in(&self) -> i64 {
        self.exp - Utc::now().timestamp()
    }

    pub fn token(&self) -> String {
        encode_jwt(&self)
    }
}

pub fn generate_delete_claims(uuid: String) -> BasicJwtClaims {
    let time_now = Utc::now();
    let expire_hours = i64::from(CONFIG.invitation_expiration_hours());
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_hours(expire_hours).unwrap()).timestamp(),
        iss: JWT_DELETE_ISSUER.to_string(),
        sub: uuid,
    }
}

pub fn generate_verify_email_claims(user_id: &UserId) -> BasicJwtClaims {
    let time_now = Utc::now();
    let expire_hours = i64::from(CONFIG.invitation_expiration_hours());
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_hours(expire_hours).unwrap()).timestamp(),
        iss: JWT_VERIFYEMAIL_ISSUER.to_string(),
        sub: user_id.to_string(),
    }
}

pub fn generate_admin_claims() -> BasicJwtClaims {
    let time_now = Utc::now();
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_minutes(CONFIG.admin_session_lifetime()).unwrap()).timestamp(),
        iss: JWT_ADMIN_ISSUER.to_string(),
        sub: "admin_panel".to_owned(),
    }
}

//
// Bearer token authentication
//
pub struct Host {
    pub host: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Host {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();

        // Get host
        let host = if CONFIG.domain_set() {
            CONFIG.domain()
        } else if let Some(referer) = headers.get_one("Referer") {
            referer.to_owned()
        } else {
            // Try to guess from the headers
            let protocol = if let Some(proto) = headers.get_one("X-Forwarded-Proto") {
                proto
            } else if env::var("ROCKET_TLS").is_ok() {
                "https"
            } else {
                "http"
            };

            let host = if let Some(host) = headers.get_one("X-Forwarded-Host") {
                host
            } else {
                headers.get_one("Host").unwrap_or_default()
            };

            format!("{protocol}://{host}")
        };

        Outcome::Success(Host {
            host,
        })
    }
}

pub struct ClientHeaders {
    pub device_type: i32,
    pub ip: ClientIp,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Outcome::Success(ip) = ClientIp::from_request(request).await else {
            err_handler!("Error getting Client IP")
        };
        // When unknown or unable to parse, return 'UnknownBrowser'
        let device_type: i32 = request
            .headers()
            .get_one("device-type")
            .and_then(|d| d.parse().ok())
            .unwrap_or(DeviceType::UnknownBrowser as i32);

        Outcome::Success(ClientHeaders {
            device_type,
            ip,
        })
    }
}

pub struct Headers {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub ip: ClientIp,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Headers {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();

        let host = try_outcome!(Host::from_request(request).await).host;
        let Outcome::Success(ip) = ClientIp::from_request(request).await else {
            err_handler!("Error getting Client IP")
        };

        // Get access_token
        let access_token: &str = if let Some(a) = headers.get_one("Authorization") {
            if let Some(split) = a.rsplit("Bearer ").next() {
                split
            } else {
                err_handler!("No access token provided")
            }
        } else {
            err_handler!("No access token provided")
        };

        // Check JWT token is valid and get device and user from it
        let Ok(claims) = decode_login(access_token) else {
            err_handler!("Invalid claim")
        };

        let device_id = claims.device;
        let user_id = claims.sub;

        let Outcome::Success(conn) = DbConn::from_request(request).await else {
            err_handler!("Error getting DB")
        };

        let Some(device) = Device::find_by_uuid_and_user(&device_id, &user_id, &conn).await else {
            err_handler!("Invalid device id")
        };

        let Some(user) = User::find_by_uuid(&user_id, &conn).await else {
            err_handler!("Device has no user associated")
        };

        if user.security_stamp != claims.sstamp {
            if let Some(stamp_exception) =
                user.stamp_exception.as_deref().and_then(|s| serde_json::from_str::<UserStampException>(s).ok())
            {
                let Some(current_route) = request.route().and_then(|r| r.name.as_deref()) else {
                    err_handler!("Error getting current route for stamp exception")
                };

                // Check if the stamp exception has expired first.
                // Then, check if the current route matches any of the allowed routes.
                // After that check the stamp in exception matches the one in the claims.
                if Utc::now().timestamp() > stamp_exception.expire {
                    // If the stamp exception has been expired remove it from the database.
                    // This prevents checking this stamp exception for new requests.
                    let mut user = user;
                    user.reset_stamp_exception();
                    if let Err(e) = user.save(&conn).await {
                        error!("Error updating user: {e:#?}");
                    }
                    err_handler!("Stamp exception is expired")
                } else if !stamp_exception.routes.contains(&current_route.to_owned()) {
                    err_handler!("Invalid security stamp: Current route and exception route do not match")
                } else if stamp_exception.security_stamp != claims.sstamp {
                    err_handler!("Invalid security stamp for matched stamp exception")
                }
            } else {
                err_handler!("Invalid security stamp")
            }
        }

        Outcome::Success(Headers {
            host,
            device,
            user,
            ip,
        })
    }
}

//
// Client IP address detection
//
#[derive(Copy, Clone)]
pub struct ClientIp {
    pub ip: IpAddr,
}

/// Parses a single entry of `ip_header_trusted_proxies`, which can be a CIDR range or a plain IP.
pub fn parse_trusted_proxy(entry: &str) -> Option<IpNet> {
    let entry = entry.trim();
    match entry.parse::<IpNet>() {
        Ok(net) => Some(net),
        // Without a prefix length it is a single address, which is a valid way to write this.
        Err(_) => entry.parse::<IpAddr>().ok().map(IpNet::from),
    }
}

/// The client IP header can be set by anyone able to reach us, so only accept it from a proxy we trust.
fn ip_header_is_trusted(remote: Option<IpAddr>) -> bool {
    let trusted = CONFIG.ip_header_trusted_proxies();
    let trusted = trusted.trim();
    if trusted.eq_ignore_ascii_case("all") {
        return true;
    }

    let Some(remote) = remote else {
        return false;
    };
    // A dual stack listener reports IPv4 clients as IPv4-mapped IPv6, which `is_global()` reports as
    // non global. That is what we want when blocking outgoing requests, but here it would trust them.
    let remote = remote.to_canonical();
    if trusted.eq_ignore_ascii_case("local") {
        return !crate::util::is_global(remote);
    }
    trusted.split(',').filter_map(parse_trusted_proxy).any(|net| net.contains(&remote))
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientIp {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let remote = req.remote().map(|r| r.ip());

        let ip = if CONFIG._ip_header_enabled() && ip_header_is_trusted(remote) {
            req.headers().get_one(&CONFIG.ip_header()).and_then(|ip| {
                match ip.find(',') {
                    Some(idx) => &ip[..idx],
                    None => ip,
                }
                .parse()
                .map_err(|_| warn!("'{}' header is malformed: {ip}", CONFIG.ip_header()))
                .ok()
            })
        } else {
            if CONFIG._ip_header_enabled() && req.headers().get_one(&CONFIG.ip_header()).is_some() {
                // Log the canonical IP, which is what the user filter will need to match against
                let remote = remote.map(|ip| ip.to_canonical());
                debug!("Ignoring the '{}' header, {remote:?} is not a trusted proxy", CONFIG.ip_header());
            }
            None
        };

        let ip = ip.or(remote).unwrap_or_else(|| "0.0.0.0".parse().unwrap());

        Outcome::Success(ClientIp {
            ip,
        })
    }
}

#[derive(Copy, Clone)]
pub struct Secure {
    pub https: bool,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Secure {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();

        // Try to guess from the headers
        let protocol = match headers.get_one("X-Forwarded-Proto") {
            Some(proto) => proto,
            None => {
                if env::var("ROCKET_TLS").is_ok() {
                    "https"
                } else {
                    "http"
                }
            }
        };

        Outcome::Success(Secure {
            https: protocol == "https",
        })
    }
}

pub struct WsAccessTokenHeader {
    pub access_token: Option<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for WsAccessTokenHeader {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();

        // Get access_token
        let access_token = match headers.get_one("Authorization") {
            Some(a) => a.rsplit("Bearer ").next().map(String::from),
            None => None,
        };

        Outcome::Success(Self {
            access_token,
        })
    }
}

pub struct ClientVersion(pub semver::Version);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientVersion {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();

        let Some(version) = headers.get_one("Bitwarden-Client-Version") else {
            err_handler!("No Bitwarden-Client-Version header provided")
        };

        let Ok(version) = semver::Version::parse(version) else {
            err_handler!("Invalid Bitwarden-Client-Version header provided")
        };

        Outcome::Success(ClientVersion(version))
    }
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    OrgApiKey,
    Password,
    UserApiKey,
}

impl AuthMethod {
    pub fn scope(&self) -> String {
        match self {
            AuthMethod::OrgApiKey => "api.organization".to_owned(),
            AuthMethod::UserApiKey => "api".to_owned(),
            AuthMethod::Password => "api offline_access".to_owned(),
        }
    }

    pub fn scope_vec(&self) -> Vec<String> {
        self.scope().split_whitespace().map(str::to_owned).collect()
    }

    pub fn check_scope(&self, scope: Option<&String>) -> ApiResult<String> {
        let method_scope = self.scope();
        match scope {
            None => err!("Missing scope"),
            Some(scope) if scope == &method_scope => Ok(method_scope),
            Some(scope) => err!(format!("Scope ({scope}) not supported")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TokenWrapper {
    Access(String),
    Refresh(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: AuthMethod,

    pub device_token: String,

    pub token: Option<TokenWrapper>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthTokens {
    pub refresh_claims: RefreshJwtClaims,
    pub access_claims: LoginJwtClaims,
}

impl AuthTokens {
    pub fn refresh_token(&self) -> String {
        encode_jwt(&self.refresh_claims)
    }

    pub fn access_token(&self) -> String {
        self.access_claims.token()
    }

    pub fn expires_in(&self) -> i64 {
        self.access_claims.expires_in()
    }

    pub fn scope(&self) -> String {
        self.refresh_claims.sub.scope()
    }

    // Create refresh_token and access_token with default validity
    pub fn new(device: &Device, user: &User, sub: AuthMethod, client_id: Option<String>) -> Self {
        let time_now = Utc::now();

        let access_claims = LoginJwtClaims::default(device, user, &sub, client_id);

        let validity = if device.is_mobile() {
            *MOBILE_REFRESH_VALIDITY
        } else {
            *DEFAULT_REFRESH_VALIDITY
        };

        let refresh_claims = RefreshJwtClaims {
            nbf: time_now.timestamp(),
            exp: (time_now + validity).timestamp(),
            iss: JWT_LOGIN_ISSUER.to_string(),
            sub,
            device_token: device.refresh_token.clone(),
            token: None,
        };

        Self {
            refresh_claims,
            access_claims,
        }
    }
}

pub async fn refresh_tokens(
    ip: &ClientIp,
    refresh_token: &str,
    client_id: Option<String>,
    conn: &DbConn,
) -> ApiResult<(Device, AuthTokens)> {
    let refresh_claims = match decode_refresh(refresh_token) {
        Err(err) => {
            error!("Failed to decode refresh_token from {}: {err:?}", ip.ip);
            err_silent!("Invalid refresh token")
        }
        Ok(claims) => claims,
    };

    // Get device by refresh token
    let Some(mut device) = Device::find_by_refresh_token(&refresh_claims.device_token, conn).await else {
        err!("Invalid refresh token")
    };

    // Save to update `updated_at`.
    device.save(true, conn).await?;

    let Some(user) = User::find_by_uuid(&device.user_uuid, conn).await else {
        err!("Impossible to find user")
    };

    let auth_tokens = match refresh_claims.sub {
        AuthMethod::Password => AuthTokens::new(&device, &user, refresh_claims.sub, client_id),
        _ => err!("Invalid auth method, cannot refresh token"),
    };

    Ok((device, auth_tokens))
}
