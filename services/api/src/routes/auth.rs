use crate::error::HttpApiError;
use crate::extractors::AuthUser;
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use auth::{hash_password, sign_access, sign_refresh, verify_password};
use chrono::{Duration, Utc};
use common::{AppError, LoginResponse};
use db::{find_user_by_email, get_refresh_by_jti, insert_refresh, insert_user, revoke_refresh};
use openidconnect::TokenResponse;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};
use reqwest::Client;
use serde_json::json;
use validator::Validate;

use crate::{
    schemas::{LoginInput, RegisterInput, TokenPair},
    state::AppState,
};

// ── Constants
const ACCESS_COOKIE: &str = "access_token";
const REFRESH_COOKIE: &str = "refresh_token";
const CSRF_COOKIE: &str = "csrf_token";

// ── Cookie helpers
use actix_web::cookie::{Cookie, SameSite, time::Duration as CookieDuration};
use std::{net::IpAddr, str::FromStr};

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn is_ip(host: &str) -> bool {
    IpAddr::from_str(host).is_ok()
}

fn site_mode(data: &AppState) -> SameSite {
    if data.cookie_secure {
        SameSite::None // HTTPS дээр cross-site cookie
    } else {
        SameSite::Lax // dev/http
    }
}

// ⬇️ lifetime алдааг засахын тулд name нь 'static байх ёстой
fn build_cookie(
    name: &'static str,
    val: String,
    http_only: bool,
    data: &AppState,
) -> Cookie<'static> {
    let mut b = Cookie::build(name, val)
        .path("/")
        .http_only(http_only)
        .secure(data.cookie_secure)
        .same_site(site_mode(data));

    // IP эсвэл хоосон байвал Domain ТАВИХГҮЙ
    if !data.cookie_domain.is_empty() && !is_ip(&data.cookie_domain) {
        b = b.domain(data.cookie_domain.clone());
    }
    b.finish()
}

fn access_cookie(value: String, data: &AppState) -> Cookie<'static> {
    build_cookie(ACCESS_COOKIE, value, true, data)
}
fn refresh_cookie(value: String, data: &AppState, ttl_secs: i64) -> Cookie<'static> {
    let mut c = build_cookie(REFRESH_COOKIE, value, true, data);
    c.set_max_age(CookieDuration::seconds(ttl_secs));
    c
}
fn csrf_cookie(value: String, data: &AppState) -> Cookie<'static> {
    build_cookie(CSRF_COOKIE, value, false, data)
}
fn clear_cookie(name: &'static str, data: &AppState, http_only: bool) -> Cookie<'static> {
    let mut c = build_cookie(name, "".into(), http_only, data);
    c.set_max_age(CookieDuration::seconds(0));
    c
}

// ── Handlers

#[post("/auth/register")]
pub async fn register(
    data: web::Data<AppState>,
    payload: web::Json<RegisterInput>,
) -> actix_web::Result<HttpResponse> {
    payload
        .validate()
        .map_err(|e| actix_web::error::ErrorBadRequest(e.to_string()))?;

    if find_user_by_email(&data.db, &payload.email)
        .await
        .map_err(HttpApiError::from)?
        .is_some()
    {
        return Err(actix_web::error::ErrorConflict("email taken"));
    }

    let hash = hash_password(&payload.password)
        .map_err(|_| actix_web::error::ErrorInternalServerError("hash"))?;

    let default_avatar = 123; // 👈 default avatar ID (config эсвэл .env-с авч болно)

    let user = insert_user(
        &data.db,
        &payload.email,
        &payload.name,
        Some(&hash),
        "User",
        default_avatar,
    )
    .await
    .map_err(HttpApiError::from)?;

    Ok(HttpResponse::Created().json(json!({
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "avatar_id": user.avatar_id
    })))
}
#[post("/auth/login")]
pub async fn login(
    data: web::Data<AppState>,
    payload: web::Json<LoginInput>,
) -> actix_web::Result<HttpResponse> {
    let db_user = find_user_by_email(&data.db, &payload.email)
        .await
        .map_err(HttpApiError::from)?
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("invalid creds"))?;

    if !verify_password(&payload.password, &db_user.password_hash) {
        return Err(actix_web::error::ErrorUnauthorized("invalid creds"));
    }
    println!("db_user = {:?}", db_user);

    // JWT гаргаж авахдаа UUID + user_by_id хоёуланг нь дамжуулж болно
    let access = sign_access(
        &data.jwt,
        db_user.id,
        db_user.user_by_id,
        &db_user.role,
        data.access_ttl,
    )
    .map_err(|_| actix_web::error::ErrorInternalServerError("jwt"))?;
    let (refresh_token, claims) = sign_refresh(
        &data.jwt,
        db_user.id,
        db_user.user_by_id,
        &db_user.role,
        data.refresh_ttl,
    )
    .map_err(|_| actix_web::error::ErrorInternalServerError("jwt"))?;

    let token_hash = format!("sha256:{}", sha256_hex(&refresh_token));
    let expires_at = Utc::now() + Duration::seconds(data.refresh_ttl);
    insert_refresh(&data.db, db_user.id, &claims.jti, &token_hash, expires_at)
        .await
        .map_err(HttpApiError::from)?;

    let csrf_token = auth::new_jti();

    let resp_body = LoginResponse {
        access_token: access.clone(),
        email: db_user.email.clone(),
        name: db_user.name.clone(),
        role: db_user.role.clone(),
        avatar_id: db_user.avatar_id,
        user_by_id: db_user.user_by_id, // 👈 нэмэгдсэн талбар
    };

    let mut resp = HttpResponse::Ok().json(resp_body);
    resp.add_cookie(&access_cookie(access, &data)).ok();
    resp.add_cookie(&refresh_cookie(refresh_token, &data, data.refresh_ttl))
        .ok();
    resp.add_cookie(&csrf_cookie(csrf_token, &data)).ok();

    Ok(resp)
}

#[post("/auth/refresh")]
pub async fn refresh(
    req: HttpRequest,
    data: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let refresh_cookie_val = req
        .cookie(REFRESH_COOKIE)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("no refresh"))?;
    let token = refresh_cookie_val.value().to_string();

    let claims = auth::verify(&data.jwt, &token)
        .map_err(|_| actix_web::error::ErrorUnauthorized("bad refresh"))?;

    // DB шалгалт
    if let Some(row) = get_refresh_by_jti(&data.db, &claims.jti)
        .await
        .map_err(HttpApiError::from)?
    {
        if row.revoked {
            return Err(actix_web::error::ErrorUnauthorized("revoked"));
        }
        let given_hash = format!("sha256:{}", sha256_hex(&token));
        if given_hash != row.token_hash {
            return Err(actix_web::error::ErrorUnauthorized("mismatch"));
        }
    } else {
        return Err(actix_web::error::ErrorUnauthorized("missing"));
    }

    // rotate
    revoke_refresh(&data.db, &claims.jti)
        .await
        .map_err(HttpApiError::from)?;
    let access = sign_access(
        &data.jwt,
        claims.sub,
        claims.user_by_id,
        &claims.role,
        data.access_ttl,
    )
    .map_err(|_| actix_web::error::ErrorInternalServerError("jwt"))?;

    let (refresh_new, claims_new) = sign_refresh(
        &data.jwt,
        claims.sub,
        claims.user_by_id,
        &claims.role,
        data.refresh_ttl,
    )
    .map_err(|_| actix_web::error::ErrorInternalServerError("jwt"))?;

    let token_hash = format!("sha256:{}", sha256_hex(&refresh_new));
    let expires_at = Utc::now() + Duration::seconds(data.refresh_ttl);
    insert_refresh(
        &data.db,
        claims.sub,
        &claims_new.jti,
        &token_hash,
        expires_at,
    )
    .await
    .map_err(HttpApiError::from)?;

    let mut resp = HttpResponse::Ok().json(TokenPair {
        access_token: access.clone(),
    });
    resp.add_cookie(&refresh_cookie(refresh_new, &data, data.refresh_ttl))
        .ok();
    Ok(resp)
}

#[post("/auth/logout")]
pub async fn logout(
    req: HttpRequest,
    data: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    if let Some(c) = req.cookie(REFRESH_COOKIE) {
        if let Ok(claims) = auth::verify(&data.jwt, c.value()) {
            revoke_refresh(&data.db, &claims.jti)
                .await
                .map_err(HttpApiError::from)?;
        }
    }
    let mut resp = HttpResponse::Ok().finish();
    resp.add_cookie(&clear_cookie(ACCESS_COOKIE, &data, true))
        .ok();
    resp.add_cookie(&clear_cookie(REFRESH_COOKIE, &data, true))
        .ok();
    resp.add_cookie(&clear_cookie(CSRF_COOKIE, &data, false))
        .ok();
    Ok(resp)
}

#[get("/auth/google/start")]
pub async fn google_start(data: web::Data<AppState>) -> actix_web::Result<HttpResponse> {
    let http = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| actix_web::error::ErrorInternalServerError("http client"))?;

    let provider = CoreProviderMetadata::discover_async(
        IssuerUrl::new("https://accounts.google.com".to_string()).unwrap(),
        &http,
    )
    .await
    .map_err(|_| actix_web::error::ErrorBadGateway("oidc discover"))?;

    let client = CoreClient::from_provider_metadata(
        provider,
        ClientId::new(data.google_client_id.clone()),
        Some(ClientSecret::new(data.google_client_secret.clone())),
    )
    .set_redirect_uri(
        RedirectUrl::new(data.google_redirect_url.clone())
            .map_err(|_| actix_web::error::ErrorInternalServerError("redirect url"))?,
    );

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let state = CsrfToken::new_random();
    let nonce = Nonce::new_random();
    let state_for_auth = state.clone();
    let nonce_for_auth = nonce.clone();

    let (auth_url, _, _) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            move || state_for_auth,
            move || nonce_for_auth,
        )
        .add_scope(Scope::new("openid".into()))
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("profile".into()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    data.oauth_state.insert(
        state.secret().to_string(),
        (nonce.secret().to_string(), pkce_verifier),
    );

    Ok(HttpResponse::Found()
        .append_header(("Location", auth_url.to_string()))
        .finish())
}

#[derive(serde::Deserialize)]
struct GoogleCb {
    code: String,
    state: String,
}

#[get("/auth/google/callback")]
pub async fn google_callback(
    data: web::Data<AppState>,
    q: web::Query<GoogleCb>,
) -> actix_web::Result<HttpResponse> {
    // ---- OIDC flow ----
    let (nonce_str, pkce_verifier): (String, PkceCodeVerifier) = data
        .oauth_state
        .remove(&q.state)
        .ok_or_else(|| actix_web::error::ErrorBadRequest("bad state"))?
        .1;

    let http = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| actix_web::error::ErrorInternalServerError("http client"))?;

    let provider = CoreProviderMetadata::discover_async(
        IssuerUrl::new("https://accounts.google.com".to_string()).unwrap(),
        &http,
    )
    .await
    .map_err(|_| actix_web::error::ErrorBadGateway("oidc discover"))?;

    let client = CoreClient::from_provider_metadata(
        provider,
        ClientId::new(data.google_client_id.clone()),
        Some(ClientSecret::new(data.google_client_secret.clone())),
    )
    .set_redirect_uri(
        RedirectUrl::new(data.google_redirect_url.clone())
            .map_err(|_| actix_web::error::ErrorInternalServerError("redirect url"))?,
    );

    let req = client
        .exchange_code(AuthorizationCode::new(q.code.clone()))
        .map_err(|_| actix_web::error::ErrorBadRequest("bad code"))?
        .set_pkce_verifier(pkce_verifier);

    let token_resp = req
        .request_async(&http)
        .await
        .map_err(|_| actix_web::error::ErrorBadGateway("token"))?;

    let id_token = token_resp
        .id_token()
        .ok_or_else(|| actix_web::error::ErrorBadGateway("no id_token"))?;

    let claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(nonce_str))
        .map_err(|_| actix_web::error::ErrorUnauthorized("bad id token"))?;

    let email = claims
        .email()
        .map(|e| e.as_str().to_string())
        .unwrap_or_default();
    let verified = claims.email_verified().unwrap_or(false);
    let name = claims
        .name()
        .and_then(|n| n.get(None))
        .map(|s| s.as_str().to_string())
        .unwrap_or_default();

    if !verified || email.is_empty() {
        return Err(actix_web::error::ErrorForbidden("email not verified"));
    }

    // ---- DB upsert ----
    let default_avatar: i32 = 123;
    let db_user = if let Some(u) = find_user_by_email(&data.db, &email)
        .await
        .map_err(HttpApiError::from)?
    {
        u
    } else {
        let default_password = "password123";
        let hash =
            hash_password(default_password).map_err(|_| HttpApiError::App(AppError::HashError))?;

        insert_user(&data.db, &email, &name, Some(&hash), "User", default_avatar)
            .await
            .map_err(HttpApiError::from)?
    };

    // ---- JWT + refresh ----
    let access = sign_access(
        &data.jwt,
        db_user.id,
        db_user.user_by_id,
        &db_user.role,
        data.access_ttl,
    )
    .map_err(|_| actix_web::error::ErrorInternalServerError("jwt"))?;

    let (refresh_token, rclaims) = sign_refresh(
        &data.jwt,
        db_user.id,
        db_user.user_by_id,
        &db_user.role,
        data.refresh_ttl,
    )
    .map_err(|_| actix_web::error::ErrorInternalServerError("jwt"))?;

    let token_hash = format!("sha256:{}", sha256_hex(&refresh_token));
    let expires_at = Utc::now() + Duration::seconds(data.refresh_ttl);
    insert_refresh(&data.db, db_user.id, &rclaims.jti, &token_hash, expires_at)
        .await
        .map_err(HttpApiError::from)?;

    let csrf = auth::new_jti();

    // ---- Response (login-тэй адил JSON) ----
    let frontend_redirect = std::env::var("FRONTEND_REDIRECT_URL")
        .unwrap_or_else(|_| "http://localhost:3000/profile".to_string());

    let mut resp = HttpResponse::Found()
        .append_header(("Location", frontend_redirect))
        .finish();

    resp.add_cookie(&access_cookie(access, &data)).ok();
    resp.add_cookie(&refresh_cookie(refresh_token, &data, data.refresh_ttl))
        .ok();
    resp.add_cookie(&csrf_cookie(csrf, &data)).ok();

    Ok(resp)
}
#[get("/auth/me")]
pub async fn me(
    data: web::Data<AppState>,
    auth_user: Option<web::ReqData<AuthUser>>,
    req: actix_web::HttpRequest,
) -> actix_web::Result<HttpResponse> {
    let user = match auth_user {
        Some(u) => u.into_inner(),
        None => return Err(actix_web::error::ErrorUnauthorized("not logged in")),
    };

    if let Some(csrf_cookie) = req.cookie("csrf_token") {
        if let Some(header_val) = req.headers().get("X-CSRF-Token") {
            let header_str = header_val.to_str().unwrap_or("");
            if header_str != csrf_cookie.value() {
                return Err(actix_web::error::ErrorUnauthorized("bad csrf token"));
            }
        } else {
            return Err(actix_web::error::ErrorUnauthorized("missing csrf header"));
        }
    }

    if let Some(db_user) = db::find_user_by_id(&data.db, user.user_id)
        .await
        .map_err(HttpApiError::from)?
    {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "id": db_user.id,
            "user_by_id": db_user.user_by_id,   // 👈 нэмсэн
            "email": db_user.email,
            "name": db_user.name,
            "role": db_user.role,
            "avatar_id": db_user.avatar_id     // 👈 нэмсэн
        })));
    }

    Err(actix_web::error::ErrorUnauthorized("not found"))
}
