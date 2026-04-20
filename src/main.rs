//! ![axum-template](https://github.com/user-attachments/assets/a16843e7-7537-4c73-a550-52a37b6fbf73)
//!
//! ## Overview
//! Portfolio/blog website template for a company that does software/games/interactive projects
//!
//! This template provides:
//! - [x] Axum server with middleware
//! - [x] Askama templates
//! - [x] Containerization (with compose)
//! - [x] Portfolio projects management
//! - [x] Blog with markdown support
//! - [x] Admin panel with authentication
//! - [x] SQLite backend (default)
//! - [x] SurrealDB backend (optional, behind feature flag)
//!
//! # Running
//! ```bash
//! # SQLite3 backend:
//! make run
//!
//! # SurrealDB backend
//! make surreal
//! ```
//!
//! ## Configuration
//! Edit `config.toml` to configure:
//! - Server host/port
//! - Database path
//! - Admin credentials (password is argon2 hashed)
//! - Site name and tagline

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    middleware::{from_fn, from_fn_with_state},
    routing::get,
};
use itertools::Itertools;
use tokio::net::TcpListener;
use tower_http::{services::ServeDir, trace::TraceLayer};

mod api;
mod config;
mod db;
use db::Db;
mod error;
mod handlers;
mod how_to;
mod middleware;
mod state;

async fn auth_cleanup(auth: Arc<middleware::TokenManager>) {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    loop {
        interval.tick().await;
        auth.cleanup().await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_init();

    let config = Arc::new(config::Config::load("config.toml")?);
    let config_addr = config.address();

    let db = db::create_db(&config).await?;
    db.init().await?;

    let token_manager = Arc::new(middleware::TokenManager::new(
        config.auth.token_ttl,
        config.admin_credentials(),
    ));
    let auth = token_manager.clone();
    tokio::spawn(auth_cleanup(auth.clone()));

    let state = state::AppState {
        db: Arc::<dyn Db>::from(db),
        config,
        token_manager,
    };

    let serve_dir = ServeDir::new("static").not_found_service(ServeDir::new("templates/404.html"));
    let router = Router::new()
        .route("/", get(handlers::home))
        .route("/projects", get(handlers::projects))
        .route("/projects/{slug}", get(handlers::project_detail))
        .route("/blog", get(handlers::blog))
        .route("/blog/{slug}", get(handlers::post_detail))
        .route("/about", get(handlers::about))
        .route("/contact", get(handlers::contact))
        .nest("/api", api::router())
        .nest("/admin", handlers::admin::router(state.clone()))
        .nest_service("/static", serve_dir.clone())
        .fallback(handlers::to_404)
        .layer(from_fn_with_state(state.clone(), middleware::auth))
        .layer(from_fn(middleware::custom_log))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let addr: SocketAddr = config_addr.parse().expect("invalid address");
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(address = %addr, "listening");

    axum::serve(listener, router.into_make_service()).await?;
    Ok(())
}

fn tracing_init() {
    use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

    const NAME: &str = env!("CARGO_PKG_NAME");
    let name = NAME.replace('_', "-");

    let fallback_log_level: EnvFilter = match cfg!(debug_assertions) {
        true => format!(
            "debug,\
            {name}=debug,\
            tower_http=debug,\
            sqlx=info,\
            rusqlite=debug,\
            axum::rejection=trace,\
            tower_http::trace::on_response=trace,\
            tower_http::trace::on_request=trace"
        )
        .into(),
        _ => "info".into(),
    };
    let log_level = EnvFilter::try_from_default_env().unwrap_or(fallback_log_level);

    let fmt = fmt::format().with_line_number(true);
    let sub_fmt = tracing_subscriber::fmt::layer().event_format(fmt);
    tracing_subscriber::registry()
        .with(sub_fmt)
        .with(log_level.clone())
        .init();

    let pretty = log_level.to_string().split(',').rev().join("\n");
    tracing::info!(level=%pretty, "set up logging.");
}

///// use openssl to generate ssl certs
///// openssl req -newkey rsa:2048 -new -nodes -keyout key.pem -out csr.pem
/////
///// or for dev purposes
/////
///// openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem -addext "subjectAltName = DNS:mydnsname.com"
// fn _load_rustls_config() -> rustls::ServerConfig {
//     use std::{fs::File, io::BufReader};
//
//     use rustls::{pki_types::PrivateKeyDer, ServerConfig};
//     use rustls_pemfile::{certs, pkcs8_private_keys};
//
//     rustls::crypto::aws_lc_rs::default_provider()
//         .install_default()
//         .unwrap();
//
//     // init server config builder with safe defaults
//     let config = ServerConfig::builder().with_no_client_auth();
//
//     // load TLS key/cert files
//     let cert_file = &mut BufReader::new(File::open("cert.pem").unwrap());
//     let key_file = &mut BufReader::new(File::open("key.pem").unwrap());
//
//     // convert files to key/cert objects
//     let cert_chain = certs(cert_file).collect::<Result<Vec<_>, _>>().unwrap();
//     let mut keys = pkcs8_private_keys(key_file)
//         .map(|key| key.map(PrivateKeyDer::Pkcs8))
//         .collect::<Result<Vec<_>, _>>()
//         .unwrap();
//
//     // exit if no keys could be parsed
//     if keys.is_empty() {
//         eprintln!("Could not locate PKCS 8 private keys.");
//         std::process::exit(1);
//     }
//
//     config.with_single_cert(cert_chain, keys.remove(0)).unwrap()
// }
