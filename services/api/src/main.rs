use std::sync::Arc;

use actix_cors::Cors;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::HttpMessage;
use actix_web::dev::Service;
use actix_web::http::header;
use actix_web::{App, HttpResponse, HttpServer, middleware::Logger, web};
use dashmap::DashMap;

use tracing_subscriber::EnvFilter;

mod error;
mod extractors;
mod middleware;
mod routes;
mod schemas;
mod state;
use state::{AppState, Settings};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let s = Settings::from_env();
    let db = db::connect(&s.database_url, 10).await.expect("db");
    db::migrate(&db).await.expect("migrations");

    let state = AppState {
        db: db.clone(),
        jwt: auth::JwtKeys::from_secret(&s.jwt_secret),
        access_ttl: s.access_ttl_seconds.unwrap_or(900),
        refresh_ttl: s.refresh_ttl_seconds.unwrap_or(60 * 60 * 24 * 7),
        cookie_domain: s.cookie_domain.unwrap_or_else(|| "localhost".into()),
        cookie_secure: s.cookie_secure.unwrap_or(false),

        oauth_state: Arc::new(DashMap::new()),

        google_client_id: std::env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID"),
        google_client_secret: std::env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET"),
        google_redirect_url: std::env::var("GOOGLE_REDIRECT_URL")
            .unwrap_or_else(|_| "http://localhost:8080/auth/google/callback".into()),
    };
    let governor_conf = GovernorConfigBuilder::default()
        .burst_size(10)
        .finish()
        .unwrap();

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_method()
            .allow_any_header()
            .allowed_origin_fn(|origin, _req_head| {
                origin.as_bytes().starts_with(b"http://localhost:3000")
                    || origin.as_bytes().starts_with(b"http://192.168.99.204:3000")
            })
            .supports_credentials()
            .max_age(3600);

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .wrap(Governor::new(&governor_conf))
            .wrap(middleware::Csrf)
            .app_data(web::Data::new(state.clone()))
            .app_data(web::Data::new(state.db.clone()))
            .service(routes::auth::register)
            .service(routes::auth::login)
            .service(routes::auth::refresh)
            .service(routes::auth::logout)
            .service(routes::items::list)
            .service(routes::items::get)
            .service(routes::items::create)
            .service(routes::items::update)
            .service(routes::items::remove)
            .service(routes::auth::google_start)
            .service(routes::auth::google_callback)
            .service(routes::auth::me)
            .default_service(web::to(|| async { HttpResponse::NotFound().finish() }))
            .wrap_fn(|req, srv| {
                // JWT auth extractor: read Bearer or cookie, set AuthUser ext if valid
                let jwt = req.app_data::<web::Data<AppState>>().unwrap().jwt.clone();
                let req_mut = req;
                let auth_header = req_mut
                    .headers()
                    .get("Authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let token_opt = if let Some(h) = auth_header {
                    h.strip_prefix("Bearer ").map(|s| s.to_string())
                } else {
                    None
                };
                let token = token_opt.or_else(|| {
                    req_mut
                        .cookie("access_token")
                        .map(|c| c.value().to_string())
                });
                if let Some(tok) = token {
                    if let Ok(claims) = auth::verify(&jwt, &tok) {
                        req_mut
                            .extensions_mut()
                            .insert(crate::extractors::AuthUser {
                                user_id: claims.sub,
                                role: claims.role,
                            });
                    }
                }
                srv.call(req_mut)
            })
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
