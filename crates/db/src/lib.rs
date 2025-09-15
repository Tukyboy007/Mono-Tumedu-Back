use auth::hash_password;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;
#[derive(Debug, Clone)]
pub struct Db(pub PgPool);

#[derive(thiserror::Error, Debug)]
pub enum DbError {
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
}

pub async fn connect(database_url: &str, max: u32) -> Result<Db, DbError> {
    let pool = PgPoolOptions::new()
        .max_connections(max)
        .connect(database_url)
        .await?;
    Ok(Db(pool))
}

pub async fn migrate(db: &Db) -> Result<(), DbError> {
    sqlx::migrate!("./migrations").run(&db.0).await?;
    Ok(())
}

// ==== Models mirrored locally for convenience (could use `common`) ====
#[derive(sqlx::FromRow, Debug, Clone, Serialize)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub name: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Debug, Clone, Serialize)]
pub struct ItemRow {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ==== Users ====
pub async fn find_user_by_email(db: &Db, email: &str) -> Result<Option<UserRow>, DbError> {
    let row = sqlx::query_as::<_, UserRow>(
        "SELECT id,email,password_hash,name,role,created_at FROM users WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(&db.0)
    .await?;
    Ok(row)
}

pub async fn find_user_by_id(db: &Db, id: Uuid) -> Result<Option<UserRow>, DbError> {
    let row = sqlx::query_as::<_, UserRow>(
        "SELECT id,email,password_hash,name,role,created_at FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db.0)
    .await?;
    Ok(row)
}

pub async fn insert_user(
    db: &Db,
    email: &str,
    name: &str,
    password: Option<&str>,
    role: &str,
) -> Result<UserRow, DbError> {
    // Хэрэв password байхгүй бол default ашиглана
    let raw_pass = password.unwrap_or("12345");

    let hash = hash_password(raw_pass)
        .map_err(|e| DbError::from(sqlx::Error::Protocol(e.to_string().into())))?;

    let row = sqlx::query_as::<_, UserRow>(
        r#"
        INSERT INTO users (email, name, password_hash, role)
        VALUES ($1, $2, $3, $4)
        RETURNING id, email, password_hash, name, role, created_at
        "#,
    )
    .bind(email)
    .bind(name)
    .bind(hash)
    .bind(role)
    .fetch_one(&db.0)
    .await?;

    Ok(row)
}

// ==== Items ====
pub async fn list_items(db: &Db, owner: Option<Uuid>) -> Result<Vec<ItemRow>, DbError> {
    if let Some(owner_id) = owner {
        let rows = sqlx::query_as::<_, ItemRow>(
            "SELECT * FROM items WHERE owner_id = $1 ORDER BY created_at DESC",
        )
        .bind(owner_id)
        .fetch_all(&db.0)
        .await?;
        Ok(rows)
    } else {
        let rows = sqlx::query_as::<_, ItemRow>("SELECT * FROM items ORDER BY created_at DESC")
            .fetch_all(&db.0)
            .await?;
        Ok(rows)
    }
}

pub async fn get_item(db: &Db, id: Uuid) -> Result<Option<ItemRow>, DbError> {
    let row = sqlx::query_as::<_, ItemRow>("SELECT * FROM items WHERE id=$1")
        .bind(id)
        .fetch_optional(&db.0)
        .await?;
    Ok(row)
}

pub async fn insert_item(
    db: &Db,
    owner_id: Uuid,
    title: &str,
    description: Option<&str>,
) -> Result<ItemRow, DbError> {
    let row = sqlx::query_as::<_, ItemRow>(
        r#"INSERT INTO items (owner_id,title,description)
           VALUES ($1,$2,$3)
           RETURNING id, owner_id, title, description, created_at, updated_at"#,
    )
    .bind(owner_id)
    .bind(title)
    .bind(description)
    .fetch_one(&db.0)
    .await?;
    Ok(row)
}

pub async fn update_item(
    db: &Db,
    id: Uuid,
    title: &str,
    description: Option<&str>,
) -> Result<Option<ItemRow>, DbError> {
    let row = sqlx::query_as::<_, ItemRow>(
        r#"UPDATE items SET title=$2, description=$3, updated_at=NOW()
           WHERE id=$1
           RETURNING id, owner_id, title, description, created_at, updated_at"#,
    )
    .bind(id)
    .bind(title)
    .bind(description)
    .fetch_optional(&db.0)
    .await?;
    Ok(row)
}

pub async fn delete_item(db: &Db, id: Uuid) -> Result<u64, DbError> {
    let res = sqlx::query("DELETE FROM items WHERE id=$1")
        .bind(id)
        .execute(&db.0)
        .await?;
    Ok(res.rows_affected())
}

// ==== Refresh tokens (rotation) ====
#[derive(sqlx::FromRow, Debug, Clone, Serialize)]
pub struct RefreshRow {
    pub id: i64,
    pub user_id: Uuid,
    pub jti: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

pub async fn insert_refresh(
    db: &Db,
    user_id: Uuid,
    jti: &str,
    token_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<RefreshRow, DbError> {
    let row = sqlx::query_as::<_, RefreshRow>(
        r#"INSERT INTO refresh_tokens(user_id,jti,token_hash,expires_at)
        VALUES($1,$2,$3,$4) RETURNING id,user_id,jti,token_hash,expires_at,revoked,created_at"#,
    )
    .bind(user_id)
    .bind(jti)
    .bind(token_hash)
    .bind(expires_at)
    .fetch_one(&db.0)
    .await?;
    Ok(row)
}

pub async fn get_refresh_by_jti(db: &Db, jti: &str) -> Result<Option<RefreshRow>, DbError> {
    let row = sqlx::query_as::<_, RefreshRow>("SELECT * FROM refresh_tokens WHERE jti=$1")
        .bind(jti)
        .fetch_optional(&db.0)
        .await?;
    Ok(row)
}

pub async fn revoke_refresh(db: &Db, jti: &str) -> Result<u64, DbError> {
    let res = sqlx::query("UPDATE refresh_tokens SET revoked=true WHERE jti=$1")
        .bind(jti)
        .execute(&db.0)
        .await?;
    Ok(res.rows_affected())
}
