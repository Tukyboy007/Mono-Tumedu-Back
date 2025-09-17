use crate::{
    auth_guard::check_access_and_csrf,
    error::HttpApiError,
    extractors::{AuthUser, require_role},
    schemas::ItemIn,
    state::AppState,
};
use actix_web::{HttpRequest, HttpResponse, delete, get, post, put, web};
use common::{OrderInput, OrderResponse};
use db::{Db, check_order_done, find_orders_by_user, insert_order, mark_order_done};
use serde::Serialize;
use uuid::Uuid;

#[post("/orders")]
pub async fn create_order(
    req: HttpRequest,
    data: web::Data<AppState>,
    user: AuthUser,
    payload: web::Json<OrderInput>,
) -> actix_web::Result<HttpResponse> {
    crate::auth_guard::check_access_and_csrf(&req)?;

    // Хэрэглэгчийн бүх orders авах
    let existing_orders = find_orders_by_user(&data.db, user.user_by_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("db error"))?;

    // Давхцсан эсэхийг шалгах
    if existing_orders
        .iter()
        .any(|o| o.order_id == payload.order_id)
    {
        return Err(actix_web::error::ErrorConflict("already taken order_id"));
    }

    // Хэрэв давхцахгүй бол шинэ order үүсгэх
    let order = insert_order(
        &data.db,
        user.user_by_id,
        payload.test_id,
        &payload.order_id,
    )
    .await
    .map_err(|_| actix_web::error::ErrorInternalServerError("db insert error"))?;

    Ok(HttpResponse::Created().json(order))
}

#[get("/orders")]
pub async fn get_orders(
    req: HttpRequest,
    data: web::Data<AppState>,
    user: AuthUser, // 👈 access_token-аас задлаад орж ирнэ
) -> actix_web::Result<HttpResponse> {
    crate::auth_guard::check_access_and_csrf(&req)?;

    let orders = find_orders_by_user(&data.db, user.user_by_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("db error"))?;

    Ok(HttpResponse::Ok().json(orders))
}

#[derive(serde::Deserialize)]
pub struct UpdateOrderStatus {
    pub order_id: String,
    pub done: bool,
}

#[derive(serde::Deserialize)]
pub struct DoneInput {
    pub test_id: i64,
}

#[put("/orders/done")]
pub async fn update_order_done(
    req: HttpRequest,
    data: web::Data<AppState>,
    user: AuthUser,
    payload: web::Json<DoneInput>,
) -> actix_web::Result<HttpResponse> {
    crate::auth_guard::check_access_and_csrf(&req)?;

    let updated = mark_order_done(&data.db, user.user_by_id, payload.test_id)
        .await
        .map_err(HttpApiError::from)?;

    match updated {
        Some(order) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "false",
            "message": "Order marked as done",
            "order": order
        }))),
        None => Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "true",
            "message": "Order already done or not found"
        }))),
    }
}

#[derive(serde::Deserialize)]
pub struct CheckInput {
    pub test_id: i64,
}

#[get("/orders/check")]
pub async fn check_order(
    req: HttpRequest,
    data: web::Data<AppState>,
    user: AuthUser,
    payload: web::Query<CheckInput>,
) -> actix_web::Result<HttpResponse> {
    // crate::auth_guard::check_access_and_csrf(&req)?;

    let result = check_order_done(&data.db, user.user_by_id, payload.test_id)
        .await
        .map_err(HttpApiError::from)?;

    match result {
        Some(done) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": if done { "done" } else { "in_progress" },
            "test_id": payload.test_id,
            "user_by_id": user.user_by_id,
            "done": done
        }))),
        None => Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "not_found",
            "message": "Order not found for this test"
        }))),
    }
}
