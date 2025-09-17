use chrono::{DateTime, Utc};
use common::OrderRow;
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

    #[error("conflict: {0}")]
    Conflict(String),
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
    pub user_by_id: i64, // 👈 шинэ багана
    pub email: String,
    pub password_hash: String,
    pub name: String,
    pub role: String,
    pub avatar_id: Option<i32>,
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

pub async fn find_user_by_email(db: &Db, email: &str) -> Result<Option<UserRow>, DbError> {
    println!("Looking for email: {}", email);

    let row = sqlx::query_as::<_, UserRow>(
        "SELECT id, user_by_id, email, password_hash, name, role, avatar_id, created_at 
         FROM users WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(&db.0)
    .await
    .map_err(DbError::from)?; // 👈 sqlx::Error → DbError руу хөрвүүлж байна

    if let Some(u) = &row {
        println!("User found: {:?}", u);
    } else {
        println!("No user found");
    }

    Ok(row)
}

pub async fn find_user_by_id(db: &Db, id: Uuid) -> Result<Option<UserRow>, DbError> {
    let row = sqlx::query_as::<_, UserRow>(
        "SELECT id, user_by_id, email, password_hash, name, role, avatar_id, created_at 
         FROM users WHERE id = $1",
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
    password_hash: Option<&str>,
    role: &str,
    avatar_id: i32,
) -> Result<UserRow, DbError> {
    let row = sqlx::query_as::<_, UserRow>(
        r#"
        INSERT INTO users (email, name, password_hash, role, avatar_id)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, user_by_id, email, password_hash, name, role, avatar_id, created_at
        "#,
    )
    .bind(email)
    .bind(name)
    .bind(password_hash.unwrap_or("default"))
    .bind(role)
    .bind(avatar_id)
    .fetch_one(&db.0)
    .await?;
    Ok(row)
}

pub async fn update_user_avatar(db: &Db, user_by_id: i64, avatar_id: i32) -> Result<(), DbError> {
    sqlx::query(
        r#"
        UPDATE users
        SET avatar_id = $1
        WHERE user_by_id = $2
        "#,
    )
    .bind(avatar_id)
    .bind(user_by_id)
    .execute(&db.0)
    .await
    .map_err(DbError::from)?;

    Ok(())
}
pub async fn update_user_email(
    db: &Db,
    user_by_id: i64,
    new_email: &str,
) -> Result<UserRow, DbError> {
    let row = sqlx::query_as::<_, UserRow>(
        r#"
        UPDATE users
        SET email = $1
        WHERE user_by_id = $2
        RETURNING id, user_by_id, email, password_hash, name, role, avatar_id, created_at
        "#,
    )
    .bind(new_email)
    .bind(user_by_id)
    .fetch_one(&db.0)
    .await?;
    Ok(row)
}
pub async fn update_user_name(
    db: &Db,
    user_by_id: i64,
    new_name: &str,
) -> Result<UserRow, DbError> {
    let row = sqlx::query_as::<_, UserRow>(
        r#"
        UPDATE users
        SET name = $1
        WHERE user_by_id = $2
        RETURNING id, user_by_id, email, password_hash, name, role, avatar_id, created_at
        "#,
    )
    .bind(new_name)
    .bind(user_by_id)
    .fetch_one(&db.0)
    .await?;
    Ok(row)
}
pub async fn update_user_password(
    db: &Db,
    user_by_id: i64,
    new_password_hash: &str,
) -> Result<UserRow, DbError> {
    let row = sqlx::query_as::<_, UserRow>(
        r#"
        UPDATE users
        SET password_hash = $1
        WHERE user_by_id = $2
        RETURNING id, user_by_id, email, password_hash, name, role, avatar_id, created_at
        "#,
    )
    .bind(new_password_hash)
    .bind(user_by_id)
    .fetch_one(&db.0)
    .await?;
    Ok(row)
}

// ==== Order ====

pub async fn insert_order(
    db: &Db,
    user_by_id: i64,
    test_id: i64,
    order_id: &str,
) -> Result<OrderRow, DbError> {
    let row = sqlx::query_as::<_, OrderRow>(
        r#"
        INSERT INTO users_order (user_by_id, test_id, order_id)
        VALUES ($1, $2, $3)
        RETURNING id, user_by_id, test_id, order_id, created_date, done
        "#,
    )
    .bind(user_by_id)
    .bind(test_id)
    .bind(order_id)
    .fetch_one(&db.0)
    .await
    .map_err(|e| {
        eprintln!("insert_order error: {:?}", e); // 👈 алдааг тодорхой log хийнэ
        DbError::from(e)
    })?;

    Ok(row)
}

pub async fn mark_order_done(
    db: &Db,
    user_by_id: i64,
    test_id: i64,
) -> Result<Option<OrderRow>, DbError> {
    let row = sqlx::query_as::<_, OrderRow>(
        r#"
        UPDATE users_order
        SET done = TRUE
        WHERE user_by_id = $1 AND test_id = $2 AND done = FALSE
        RETURNING id, user_by_id, test_id, order_id, created_date, done
        "#,
    )
    .bind(user_by_id)
    .bind(test_id)
    .fetch_optional(&db.0) // 👈 fetch_optional — update болоогүй байж болно
    .await
    .map_err(DbError::from)?;

    Ok(row)
}

pub async fn check_order_done(
    db: &Db,
    user_by_id: i64,
    test_id: i64,
) -> Result<Option<bool>, DbError> {
    let row = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT done
        FROM users_order
        WHERE user_by_id = $1 
          AND test_id = $2 
          AND done <> true
        "#,
    )
    .bind(user_by_id)
    .bind(test_id)
    .fetch_optional(&db.0)
    .await
    .map_err(DbError::from)?;

    Ok(row) // Some(true/false) эсвэл None
}

pub async fn find_orders_by_user(db: &Db, user_by_id: i64) -> Result<Vec<OrderRow>, DbError> {
    let rows = sqlx::query_as::<_, OrderRow>(
        r#"
        SELECT id, user_by_id, test_id, order_id, created_date, done
        FROM users_order
        WHERE user_by_id = $1
        ORDER BY created_date DESC
        "#,
    )
    .bind(user_by_id)
    .fetch_all(&db.0)
    .await
    .map_err(DbError::from)?;

    Ok(rows)
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
) -> Result<(), DbError> {
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (user_id, jti, token_hash, expires_at)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(user_id)
    .bind(jti)
    .bind(token_hash)
    .bind(expires_at)
    .execute(&db.0)
    .await?;

    Ok(())
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
