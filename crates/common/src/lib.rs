use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    Admin,
    User,
}

impl Default for Role {
    fn default() -> Self {
        Role::User
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub name: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, serde::Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub avatar_id: Option<i32>, // 👈 энд нэмсэн
    pub user_by_id: i64,
}

#[derive(Deserialize)]
pub struct UpdateEmailInput {
    pub new_email: String,
}

#[derive(Deserialize)]
pub struct UpdateNameInput {
    pub new_name: String,
}

#[derive(Deserialize)]
pub struct UpdatePasswordInput {
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct UpdateAvatarInput {
    pub avatar_id: i32,
}

#[derive(sqlx::FromRow, Debug, Clone, Serialize, Deserialize)]
pub struct OrderRow {
    pub id: i64,
    pub user_by_id: i64,
    pub test_id: i64,
    pub order_id: String,
    pub created_date: DateTime<Utc>,
    pub done: bool, // 👈 шинэ багана
}

#[derive(Debug, Serialize)]
pub struct OrderResponse {
    pub user_by_id: i64, // 👈 нэрийг user_by_id болголоо
    pub test_id: i64,
    pub created_date: chrono::DateTime<Utc>,
    pub order_id: String,
}

#[derive(Debug, Deserialize)]
pub struct OrderInput {
    pub test_id: i64,
    pub order_id: String,
}

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("internal error")]
    Internal,
    #[error("HashError")]
    HashError,
}

pub type AppResult<T> = Result<T, AppError>;
