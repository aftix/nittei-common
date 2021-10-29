use jsonwebtoken::{encode, errors::Result, Algorithm, EncodingKey, Header};

// Claim for JWT
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Claim {
    sub: String, // User
    iat: u64,    // Issued at
    exp: u64,    // Expires
}

// Session token, JWT
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct AuthToken {
    jwt: String,
}

impl AuthToken {
    pub fn new(claim: &Claim, secret: &str) -> Result<Self> {
        let jwt = encode(
            &Header::new(Algorithm::HS512),
            claim,
            &EncodingKey::from_secret(secret.as_bytes()),
        )?;
        Ok(Self { jwt })
    }

    pub fn jwt(&self) -> &str {
        self.jwt.as_str()
    }
}

// Remember me token, token should be stored with argon2 hash
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PersistToken {
    session: u64,
    token: u64,
}

// Register an account, starting a session on success
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct RegisterRequest {
    username: String,
    password: String,
    email: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum RegisterResponse {
    Success(AuthToken),
    UsernameTaken,
    WeakPassword,
    EmailTaken,
    Lockout,
    InvalidRequest,
}

// Login to an account, returning a session on success
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum LoginResponse {
    Success(AuthToken),
    UsernameInvalid,
    PasswordWrong,
    LockedOut,
    InvalidRequest,
}

// Renew a session, returning a new key on success
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct RenewRequest {
    session: AuthToken,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum RenewResponse {
    Success(AuthToken),
    Expired,
    NotValid,
    InvalidRequest,
}

// End a session
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct DisableRequest {
    session: AuthToken,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum DisableResponse {
    Success,
    InvalidSession,
    InvalidRequest,
}

// End All sessions
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct DisableAllRequest {
    session: AuthToken,
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
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum PersistResponse {
    Success(PersistToken),
    InvalidUser,
    InvalidPassword,
    InvalidRequest,
    Lockout,
}

// Disable all remember me tokens
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PersistResetRequest {
    username: String,
    password: String,
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
    username: String,
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
    username: String,
    resetcode: String,
    password: String,
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
