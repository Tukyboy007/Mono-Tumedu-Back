use argon2::Argon2;
use argon2::PasswordHasher;
use argon2::password_hash::{Error as PasswordHashError, SaltString};
use base64::Engine;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
pub struct JwtKeys {
    pub enc: EncodingKey,
    pub dec: DecodingKey,
}

impl JwtKeys {
    pub fn from_secret(secret: &str) -> Self {
        Self {
            enc: EncodingKey::from_secret(secret.as_bytes()),
            dec: DecodingKey::from_secret(secret.as_bytes()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub role: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String, // unique id to tie refresh tokens to DB records
}

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("invalid token")]
    InvalidToken,
}

pub fn now_ts() -> i64 {
    Utc::now().timestamp()
}

pub fn new_jti() -> String {
    let mut bytes = [0u8; 16];
    thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn sign_access(
    keys: &JwtKeys,
    user_id: Uuid,
    role: &str,
    ttl_secs: i64,
) -> Result<String, AuthError> {
    let iat = now_ts();
    let exp = iat + ttl_secs;
    let claims = Claims {
        sub: user_id,
        role: role.into(),
        iat,
        exp,
        jti: new_jti(),
    };
    jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &keys.enc)
        .map_err(|_| AuthError::InvalidToken)
}

pub fn sign_refresh(
    keys: &JwtKeys,
    user_id: Uuid,
    role: &str,
    ttl_secs: i64,
) -> Result<(String, Claims), AuthError> {
    let iat = now_ts();
    let exp = iat + ttl_secs;
    let claims = Claims {
        sub: user_id,
        role: role.into(),
        iat,
        exp,
        jti: new_jti(),
    };
    let token = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &keys.enc)
        .map_err(|_| AuthError::InvalidToken)?;
    Ok((token, claims))
}

pub fn verify(keys: &JwtKeys, token: &str) -> Result<Claims, AuthError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    jsonwebtoken::decode::<Claims>(token, &keys.dec, &validation)
        .map(|d| d.claims)
        .map_err(|_| AuthError::InvalidToken)
}

pub fn hash_password(raw: &str) -> Result<String, PasswordHashError> {
    let salt = SaltString::generate(&mut thread_rng());
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(raw.as_bytes(), &salt)?.to_string();
    Ok(hash)
}

pub fn verify_password(raw: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    if let Ok(parsed) = PasswordHash::new(hash) {
        Argon2::default()
            .verify_password(raw.as_bytes(), &parsed)
            .is_ok()
    } else {
        false
    }
}
