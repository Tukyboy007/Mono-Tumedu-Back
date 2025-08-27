use crate::{extractors::require_role, schemas::ItemIn};
use actix_web::{HttpRequest, HttpResponse, delete, get, post, put, web};
use db::{Db, delete_item, get_item, insert_item, list_items, update_item};
use uuid::Uuid;

#[get("/items")]
pub async fn list(
    data: web::Data<Db>,
    who: Option<web::Query<OwnerFilter>>,
) -> actix_web::Result<HttpResponse> {
    let owner = who.and_then(|q| q.owner_id);
    let rows = list_items(&data, owner)
        .await
        .map_err(crate::error::HttpApiError::from)?;
    Ok(HttpResponse::Ok().json(rows))
}

#[derive(serde::Deserialize)]
pub struct OwnerFilter {
    pub owner_id: Option<Uuid>,
}

#[get("/items/{id}")]
pub async fn get(data: web::Data<Db>, path: web::Path<Uuid>) -> actix_web::Result<HttpResponse> {
    let id = path.into_inner();
    if let Some(row) = get_item(&data, id)
        .await
        .map_err(crate::error::HttpApiError::from)?
    {
        Ok(HttpResponse::Ok().json(row))
    } else {
        Err(actix_web::error::ErrorNotFound("not found"))
    }
}

#[post("/items")]
pub async fn create(
    data: web::Data<Db>,
    body: web::Json<ItemIn>,
    user: crate::extractors::AuthUser,
) -> actix_web::Result<HttpResponse> {
    let row = insert_item(
        &data,
        user.user_id,
        &body.title,
        body.description.as_deref(),
    )
    .await
    .map_err(crate::error::HttpApiError::from)?;
    Ok(HttpResponse::Created().json(row))
}

#[put("/items/{id}")]
pub async fn update(
    data: web::Data<Db>,
    path: web::Path<Uuid>,
    body: web::Json<ItemIn>,
    req: actix_web::HttpRequest,
) -> actix_web::Result<HttpResponse> {
    crate::extractors::require_role(&req, "User")?; // any logged-in user (or Admin)
    let id = path.into_inner();
    if let Some(row) = update_item(&data, id, &body.title, body.description.as_deref())
        .await
        .map_err(crate::error::HttpApiError::from)?
    {
        Ok(HttpResponse::Ok().json(row))
    } else {
        Err(actix_web::error::ErrorNotFound("not found"))
    }
}

#[delete("/items/{id}")]
pub async fn remove(
    data: web::Data<Db>,
    path: web::Path<Uuid>,
    req: HttpRequest,
) -> actix_web::Result<HttpResponse> {
    require_role(&req, "Admin")?; // only admin can delete
    let id = path.into_inner();
    let affected = delete_item(&data, id)
        .await
        .map_err(crate::error::HttpApiError::from)?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"deleted": affected})))
}
