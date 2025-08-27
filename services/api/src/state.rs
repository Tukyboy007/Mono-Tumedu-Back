use dashmap::DashMap;
use openidconnect::PkceCodeVerifier;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: db::Db, // танай alias
    pub jwt: auth::JwtKeys,
    pub access_ttl: i64,
    pub refresh_ttl: i64,
    pub cookie_domain: String,
    pub cookie_secure: bool,

    pub oauth_state: Arc<DashMap<String, (String /*nonce*/, PkceCodeVerifier)>>,

    // OIDC тохиргоо — client биш, зөвхөн стрингүүд хадгална
    pub google_client_id: String,
    pub google_client_secret: String,
    pub google_redirect_url: String,
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub database_url: String,
    pub jwt_secret: String,
    pub access_ttl_seconds: Option<i64>,
    pub refresh_ttl_seconds: Option<i64>,
    pub cookie_domain: Option<String>,
    pub cookie_secure: Option<bool>,
}

impl Settings {
    pub fn from_env() -> Self {
        let _ = dotenvy::dotenv();

        let cfg = config::Config::builder()
            .add_source(
                config::Environment::default()
                    // .separator("_")  // <= ҮҮНИЙГ БҮҮ АШИГЛА
                    .try_parsing(true),
            )
            .build()
            .expect("config");

        cfg.try_deserialize::<Settings>()
            .expect("deserialize settings")
    }
}
