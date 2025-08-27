use actix_web::{HttpResponse, ResponseError};
use common::AppError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HttpApiError {
    #[error("{0}")]
    App(#[from] AppError),
    #[error("db error")]
    Db(#[from] db::DbError),
    #[error("auth error")]
    Auth,
}

impl ResponseError for HttpApiError {
    fn error_response(&self) -> HttpResponse {
        match self {
            Self::App(AppError::NotFound) => HttpResponse::NotFound().finish(),
            Self::App(AppError::Conflict) => HttpResponse::Conflict().finish(),
            Self::App(AppError::Unauthorized) => HttpResponse::Unauthorized().finish(),
            Self::App(AppError::Forbidden) => HttpResponse::Forbidden().finish(),
            Self::App(AppError::BadRequest(msg)) => {
                HttpResponse::BadRequest().json(serde_json::json!({"error":msg}))
            }
            _ => HttpResponse::InternalServerError().finish(),
        }
    }
}
