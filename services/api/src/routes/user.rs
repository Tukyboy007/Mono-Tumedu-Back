use actix_web::{HttpRequest, HttpResponse, put, web};
use auth::hash_password;
use common::{UpdateAvatarInput, UpdateEmailInput, UpdateNameInput, UpdatePasswordInput};
use db::update_user_avatar;
use serde::Deserialize;

use crate::{error::HttpApiError, extractors::AuthUser, state::AppState};

#[put("/user/avatar")]
pub async fn update_avatar(
    req: HttpRequest,
    data: web::Data<AppState>,
    user: AuthUser, // 👈 access_token-аас user_by_id гарч ирнэ
    payload: web::Json<UpdateAvatarInput>,
) -> actix_web::Result<HttpResponse> {
    crate::auth_guard::check_access_and_csrf(&req)?;

    update_user_avatar(&data.db, user.user_by_id, payload.avatar_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("db error"))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": "Avatar updated successfully",
        "avatar_id": payload.avatar_id
    })))
}

/// Email update
#[put("/users/email")]
pub async fn update_email(
    req: HttpRequest,
    data: web::Data<AppState>,
    user: AuthUser,
    payload: web::Json<UpdateEmailInput>,
) -> actix_web::Result<HttpResponse> {
    crate::auth_guard::check_access_and_csrf(&req)?;
    let updated = db::update_user_email(&data.db, user.user_by_id, &payload.new_email)
        .await
        .map_err(HttpApiError::from)?;
    Ok(HttpResponse::Ok().json(updated))
}

/// Username update
#[put("/users/name")]
pub async fn update_name(
    req: HttpRequest,
    data: web::Data<AppState>,
    user: AuthUser,
    payload: web::Json<UpdateNameInput>,
) -> actix_web::Result<HttpResponse> {
    crate::auth_guard::check_access_and_csrf(&req)?;

    let updated = db::update_user_name(&data.db, user.user_by_id, &payload.new_name)
        .await
        .map_err(HttpApiError::from)?;
    Ok(HttpResponse::Ok().json(updated))
}

/// Password update
#[put("/users/password")]
pub async fn update_password(
    req: HttpRequest,
    data: web::Data<AppState>,
    user: AuthUser,
    payload: web::Json<UpdatePasswordInput>,
) -> actix_web::Result<HttpResponse> {
    crate::auth_guard::check_access_and_csrf(&req)?;
    let hash = hash_password(&payload.new_password)
        .map_err(|_| actix_web::error::ErrorInternalServerError("hash error"))?;

    let updated = db::update_user_password(&data.db, user.user_by_id, &hash)
        .await
        .map_err(HttpApiError::from)?;
    Ok(HttpResponse::Ok().json(updated))
}
