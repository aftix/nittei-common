use jsonwebtoken::{
    decode, encode, errors::Result, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use ron;
use std::fmt::{self, Display, Formatter};

#[cfg(feature = "guards")]
use rocket::data::{Data, FromData, Outcome, ToByteUnit};
#[cfg(feature = "guards")]
use rocket::http::{ContentType, Status};
#[cfg(feature = "guards")]
use rocket::request::Request;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum AuthLevel {
    User,
    Mod,
    Admin,
}

impl From<i32> for AuthLevel {
    fn from(i: i32) -> Self {
        match i {
            1 => Self::Mod,
            2 => Self::Admin,
            _ => Self::User,
        }
    }
}

impl From<AuthLevel> for i32 {
    fn from(lvl: AuthLevel) -> Self {
        match lvl {
            AuthLevel::User => 0,
            AuthLevel::Mod => 1,
            AuthLevel::Admin => 2,
        }
    }
}

// Claim for JWT
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Claim {
    pub sub: String,     // User email
    pub user: String,    // User name
    pub iat: u64,        // Issued at
    pub exp: u64,        // Expires
    pub auth: AuthLevel, // User account level
}

// Session token, JWT
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct AuthToken {
    jwt: String,
}

impl Display for AuthToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.jwt)
    }
}

impl AuthToken {
    pub fn new(claim: &Claim, secret: &str) -> Result<Self> {
        let jwt = encode(
            &Header::new(Algorithm::HS512),
            claim,
            &EncodingKey::from_secret(secret.as_ref()),
        )?;
        Ok(Self { jwt })
    }

    pub fn from_jwt(jwt: &str) -> Self {
        Self {
            jwt: jwt.to_owned(),
        }
    }

    pub fn authenticate(self, secret: &str) -> Option<Claim> {
        let claim = decode::<Claim>(
            &self.jwt,
            &DecodingKey::from_secret(secret.as_ref()),
            &Validation::new(Algorithm::HS512),
        );

        if let Ok(claim) = claim {
            Some(claim.claims)
        } else {
            None
        }
    }
}

// FromData Error
#[derive(Debug)]
pub enum FromError {
    TooLarge,
    Io(std::io::Error),
    Ron(ron::Error),
}

// Remember me token, token should be stored with argon2 hash
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PersistToken {
    pub session: u64,
    pub token: u64,
}

// Register an account, starting a session on success
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub email: String,
}

#[cfg(feature = "guards")]
#[rocket::async_trait]
impl<'r> FromData<'r> for RegisterRequest {
    type Error = FromError;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self> {
        use rocket::outcome::Outcome::*;
        use FromError::*;
        // Check Content Type
        let ct = ContentType::new("application", "x-register-request");
        if req.content_type() != Some(&ct) {
            return Forward(data);
        }

        // Data size limit
        let limit = req
            .limits()
            .get("register-request")
            .unwrap_or((512 as usize).bytes());

        // Get the string out of the content
        let string = match data.open(limit).into_string().await {
            Ok(string) if string.is_complete() => string.into_inner(),
            Ok(_) => return Failure((Status::PayloadTooLarge, TooLarge)),
            Err(e) => return Failure((Status::InternalServerError, Io(e))),
        };

        // Parse the RON
        let ret = ron::de::from_str::<RegisterRequest>(&string);
        if let Err(e) = ret {
            return Failure((Status::BadRequest, Ron(e)));
        }
        let ret = ret.unwrap();

        Success(ret)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum RegisterResponse {
    Success(AuthToken, Claim),
    UsernameTaken,
    InvalidUsername,
    InvalidEmail,
    WeakPassword,
    EmailTaken,
    Lockout,
    InvalidRequest,
}

// Login to an account, returning a session on success
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[cfg(feature = "guards")]
#[rocket::async_trait]
impl<'r> FromData<'r> for LoginRequest {
    type Error = FromError;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self> {
        use rocket::outcome::Outcome::*;
        use FromError::*;
        // Check Content Type
        let ct = ContentType::new("application", "x-login-request");
        if req.content_type() != Some(&ct) {
            return Forward(data);
        }

        // Data size limit
        let limit = req
            .limits()
            .get("login-request")
            .unwrap_or((512 as usize).bytes());

        // Get the string out of the content
        let string = match data.open(limit).into_string().await {
            Ok(string) if string.is_complete() => string.into_inner(),
            Ok(_) => return Failure((Status::PayloadTooLarge, TooLarge)),
            Err(e) => return Failure((Status::InternalServerError, Io(e))),
        };

        // Parse the RON
        let ret = ron::de::from_str::<LoginRequest>(&string);
        if let Err(e) = ret {
            return Failure((Status::BadRequest, Ron(e)));
        }
        let ret = ret.unwrap();

        Success(ret)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum LoginResponse {
    Success(AuthToken, Claim),
    EmailInvalid,
    PasswordWrong,
    LockedOut,
    InvalidRequest,
}

// Renew a session, returning a new key on success
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum RenewResponse {
    Success(AuthToken),
    Expired,
    NotValid,
    InvalidRequest,
}

// End a session
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct DisableRequest {}

#[cfg(feature = "guards")]
#[rocket::async_trait]
impl<'r> FromData<'r> for DisableRequest {
    type Error = FromError;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self> {
        use rocket::outcome::Outcome::*;
        use FromError::*;
        // Check Content Type
        let ct = ContentType::new("application", "x-disable-request");
        if req.content_type() != Some(&ct) {
            return Forward(data);
        }

        // Data size limit
        let limit = req
            .limits()
            .get("disable-request")
            .unwrap_or((512 as usize).bytes());

        // Get the string out of the content
        let string = match data.open(limit).into_string().await {
            Ok(string) if string.is_complete() => string.into_inner(),
            Ok(_) => return Failure((Status::PayloadTooLarge, TooLarge)),
            Err(e) => return Failure((Status::InternalServerError, Io(e))),
        };

        // Parse the RON
        let ret = ron::de::from_str::<DisableRequest>(&string);
        if let Err(e) = ret {
            return Failure((Status::BadRequest, Ron(e)));
        }
        let ret = ret.unwrap();

        Success(ret)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum DisableResponse {
    Success,
    InvalidSession,
    InvalidRequest,
}

// End All sessions
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct DisableAllRequest {}

#[cfg(feature = "guards")]
#[rocket::async_trait]
impl<'r> FromData<'r> for DisableAllRequest {
    type Error = FromError;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self> {
        use rocket::outcome::Outcome::*;
        use FromError::*;
        // Check Content Type
        let ct = ContentType::new("application", "x-disable-all-request");
        if req.content_type() != Some(&ct) {
            return Forward(data);
        }

        // Data size limit
        let limit = req
            .limits()
            .get("disable-all-request")
            .unwrap_or((512 as usize).bytes());

        // Get the string out of the content
        let string = match data.open(limit).into_string().await {
            Ok(string) if string.is_complete() => string.into_inner(),
            Ok(_) => return Failure((Status::PayloadTooLarge, TooLarge)),
            Err(e) => return Failure((Status::InternalServerError, Io(e))),
        };

        // Parse the RON
        let ret = ron::de::from_str::<DisableAllRequest>(&string);
        if let Err(e) = ret {
            return Failure((Status::BadRequest, Ron(e)));
        }
        let ret = ret.unwrap();

        Success(ret)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum DisableAllResponse {
    Success,
    InvalidSession,
    InvalidRequest,
}

// Request a remember me token
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PersistRequest {
    pub email: String,
    pub password: String,
}

#[cfg(feature = "guards")]
#[rocket::async_trait]
impl<'r> FromData<'r> for PersistRequest {
    type Error = FromError;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self> {
        use rocket::outcome::Outcome::*;
        use FromError::*;
        // Check Content Type
        let ct = ContentType::new("application", "x-persist-request");
        if req.content_type() != Some(&ct) {
            return Forward(data);
        }

        // Data size limit
        let limit = req
            .limits()
            .get("persist-request")
            .unwrap_or((512 as usize).bytes());

        // Get the string out of the content
        let string = match data.open(limit).into_string().await {
            Ok(string) if string.is_complete() => string.into_inner(),
            Ok(_) => return Failure((Status::PayloadTooLarge, TooLarge)),
            Err(e) => return Failure((Status::InternalServerError, Io(e))),
        };

        // Parse the RON
        let ret = ron::de::from_str::<PersistRequest>(&string);
        if let Err(e) = ret {
            return Failure((Status::BadRequest, Ron(e)));
        }
        let ret = ret.unwrap();

        Success(ret)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum PersistResponse {
    Success(PersistToken),
    InvalidUser,
    InvalidPassword,
    InvalidRequest,
    Lockout,
}

// Request to login with remember me token
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PersistLoginRequest {
    pub email: String,
    pub token: PersistToken,
}

#[cfg(feature = "guards")]
#[rocket::async_trait]
impl<'r> FromData<'r> for PersistLoginRequest {
    type Error = FromError;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self> {
        use rocket::outcome::Outcome::*;
        use FromError::*;
        // Check Content Type
        let ct = ContentType::new("application", "x-persist-login-request");
        if req.content_type() != Some(&ct) {
            return Forward(data);
        }

        // Data size limit
        let limit = req
            .limits()
            .get("persist-request")
            .unwrap_or((512 as usize).bytes());

        // Get the string out of the content
        let string = match data.open(limit).into_string().await {
            Ok(string) if string.is_complete() => string.into_inner(),
            Ok(_) => return Failure((Status::PayloadTooLarge, TooLarge)),
            Err(e) => return Failure((Status::InternalServerError, Io(e))),
        };

        // Parse the RON
        let ret = ron::de::from_str::<PersistLoginRequest>(&string);
        if let Err(e) = ret {
            return Failure((Status::BadRequest, Ron(e)));
        }
        let ret = ret.unwrap();

        Success(ret)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum PersistLoginResponse {
    Success(AuthToken, Claim),
    Lockout,
    InvalidSession,
    InvalidToken,
}

// Disable all remember me tokens
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PersistResetRequest {
    pub email: String,
    pub password: String,
}

#[cfg(feature = "guards")]
#[rocket::async_trait]
impl<'r> FromData<'r> for PersistResetRequest {
    type Error = FromError;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self> {
        use rocket::outcome::Outcome::*;
        use FromError::*;
        // Check Content Type
        let ct = ContentType::new("application", "x-persist-reset-request");
        if req.content_type() != Some(&ct) {
            return Forward(data);
        }

        // Data size limit
        let limit = req
            .limits()
            .get("persist-reset-request")
            .unwrap_or((512 as usize).bytes());

        // Get the string out of the content
        let string = match data.open(limit).into_string().await {
            Ok(string) if string.is_complete() => string.into_inner(),
            Ok(_) => return Failure((Status::PayloadTooLarge, TooLarge)),
            Err(e) => return Failure((Status::InternalServerError, Io(e))),
        };

        // Parse the RON
        let ret = ron::de::from_str::<PersistResetRequest>(&string);
        if let Err(e) = ret {
            return Failure((Status::BadRequest, Ron(e)));
        }
        let ret = ret.unwrap();

        Success(ret)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum PersistResetRespone {
    Success,
    InvalidUser,
    InvalidPassword,
    Lockout,
    InvalidRequest,
}

// Request a password reset code to be sent to verified email
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct ResetCodeRequest {
    pub email: String,
}

#[cfg(feature = "guards")]
#[rocket::async_trait]
impl<'r> FromData<'r> for ResetCodeRequest {
    type Error = FromError;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self> {
        use rocket::outcome::Outcome::*;
        use FromError::*;
        // Check Content Type
        let ct = ContentType::new("application", "x-reset-code-request");
        if req.content_type() != Some(&ct) {
            return Forward(data);
        }

        // Data size limit
        let limit = req
            .limits()
            .get("reset-code-request")
            .unwrap_or((512 as usize).bytes());

        // Get the string out of the content
        let string = match data.open(limit).into_string().await {
            Ok(string) if string.is_complete() => string.into_inner(),
            Ok(_) => return Failure((Status::PayloadTooLarge, TooLarge)),
            Err(e) => return Failure((Status::InternalServerError, Io(e))),
        };

        // Parse the RON
        let ret = ron::de::from_str::<ResetCodeRequest>(&string);
        if let Err(e) = ret {
            return Failure((Status::BadRequest, Ron(e)));
        }
        let ret = ret.unwrap();

        Success(ret)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum ResetCodeResponse {
    Success,
    InvalidUser,
    EmailUnverified,
    Lockout,
    InvalidRequest,
}

// Request a password reset from an emailed code
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct ResetRequest {
    pub email: String,
    pub resetcode: String,
    pub password: String,
}

#[cfg(feature = "guards")]
#[rocket::async_trait]
impl<'r> FromData<'r> for ResetRequest {
    type Error = FromError;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self> {
        use rocket::outcome::Outcome::*;
        use FromError::*;
        // Check Content Type
        let ct = ContentType::new("application", "x-register-request");
        if req.content_type() != Some(&ct) {
            return Forward(data);
        }

        // Data size limit
        let limit = req
            .limits()
            .get("register-request")
            .unwrap_or((512 as usize).bytes());

        // Get the string out of the content
        let string = match data.open(limit).into_string().await {
            Ok(string) if string.is_complete() => string.into_inner(),
            Ok(_) => return Failure((Status::PayloadTooLarge, TooLarge)),
            Err(e) => return Failure((Status::InternalServerError, Io(e))),
        };

        // Parse the RON
        let ret = ron::de::from_str::<ResetRequest>(&string);
        if let Err(e) = ret {
            return Failure((Status::BadRequest, Ron(e)));
        }
        let ret = ret.unwrap();

        Success(ret)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum ResetResponse {
    Success,
    InvalidUser,
    InvalidCode,
    InvalidPassword,
    Lockout,
    InvalidRequest,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct VerifyRequest {
    pub verifycode: u128,
}

#[cfg(feature = "guards")]
#[rocket::async_trait]
impl<'r> FromData<'r> for VerifyRequest {
    type Error = FromError;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self> {
        use rocket::outcome::Outcome::*;
        use FromError::*;
        // Check Content Type
        let ct = ContentType::new("application", "x-verify-request");
        if req.content_type() != Some(&ct) {
            return Forward(data);
        }

        // Data size limit
        let limit = req
            .limits()
            .get("verify-request")
            .unwrap_or((512 as usize).bytes());

        // Get the string out of the content
        let string = match data.open(limit).into_string().await {
            Ok(string) if string.is_complete() => string.into_inner(),
            Ok(_) => return Failure((Status::PayloadTooLarge, TooLarge)),
            Err(e) => return Failure((Status::InternalServerError, Io(e))),
        };

        // Parse the RON
        let ret = ron::de::from_str::<VerifyRequest>(&string);
        if let Err(e) = ret {
            return Failure((Status::BadRequest, Ron(e)));
        }
        let ret = ret.unwrap();

        Success(ret)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum VerifyResponse {
    Success,
    BadCode,
    BadUser,
    ExpiredCode,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct MakeResetRequest {
    pub email: String,
}

#[cfg(feature = "guards")]
#[rocket::async_trait]
impl<'r> FromData<'r> for MakeResetRequest {
    type Error = FromError;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self> {
        use rocket::outcome::Outcome::*;
        use FromError::*;
        // Check Content Type
        let ct = ContentType::new("application", "x-make-reset-request");
        if req.content_type() != Some(&ct) {
            return Forward(data);
        }

        // Data size limit
        let limit = req
            .limits()
            .get("make-reset-request")
            .unwrap_or((512 as usize).bytes());

        // Get the string out of the content
        let string = match data.open(limit).into_string().await {
            Ok(string) if string.is_complete() => string.into_inner(),
            Ok(_) => return Failure((Status::PayloadTooLarge, TooLarge)),
            Err(e) => return Failure((Status::InternalServerError, Io(e))),
        };

        // Parse the RON
        let ret = ron::de::from_str::<MakeResetRequest>(&string);
        if let Err(e) = ret {
            return Failure((Status::BadRequest, Ron(e)));
        }
        let ret = ret.unwrap();

        Success(ret)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum MakeResetResponse {
    Success,
    EmailUnverified,
    BadEmail,
}
