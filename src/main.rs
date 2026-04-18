//! ![axum-template](https://github.com/user-attachments/assets/a16843e7-7537-4c73-a550-52a37b6fbf73)
//!
//! ## Overview
//! Template to have something to get-go in some situations
//!
//! This template provides:
//! - [x] Axum server(with middleware)
//! - [x] Askama templates
//! - [x] Containerization(with compose)
//! - [x] Greeter page with query param name
//! - [x] Sqlite backend
//! - [ ] SurrealDB backend
//!
//! # Running
//! ```bash
//! # Sqlite3 backend:
//! make run
//!
//! # surrealdb backend
//! make surreal
//!
//! ```
//!
//! You can peek into Makefile for build details
//!
//! ## Afterthoughts and issues
//!
//! I found axum to be the most ergonomic web framework out there, and while there might be not
//! enough examples at the moment, it is quite a breeze to use.
//! Some caveats tho:
//! - static files was sure one noticeable pain in the rear to figure out
//! - surrealdb sure adds complexity, I'm adding it under a feature because sqlite integration is
//!     so much less crates to compile(190+ vs 500+)
//!

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    middleware::{from_fn, from_fn_with_state},
    routing::{delete, get, patch, post},
};
use tokio::net::TcpListener;
use tower_http::{services::ServeDir, trace::TraceLayer};

mod db;
mod error;
mod form_zip;
mod handlers;
mod middleware;

#[derive(Clone)]
struct AppState {
    token_manager: Arc<middleware::TokenManager>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_init();

    let token_manager = Arc::new(middleware::TokenManager::new(3600));
    let auth = token_manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            auth.cleanup().await;
        }
    });

    // init DB in the background
    tokio::spawn(async move {
        if let Err(e) = db::init().await {
            tracing::error!(error=?e, "failed to connect to DB");
        }
    });

    let state = AppState { token_manager };

    // Static asset service
    let serve_dir = ServeDir::new("static").not_found_service(ServeDir::new("templates/404.html"));
    let router = Router::new()
        .route("/", get(handlers::home))
        .route("/hello", get(handlers::hello))
        .route("/posts", get(handlers::posts))
        .route("/add-post", post(handlers::add_post))
        .route("/update-post/:id", patch(handlers::update_post))
        .route("/delete-post/:id", delete(handlers::delete_post))
        .route("/fetch-zip", get(handlers::fetch_zip))
        .nest_service("/static", serve_dir.clone())
        .fallback(handlers::handle_404)
        .layer(from_fn_with_state(state.clone(), middleware::auth))
        .layer(from_fn(middleware::auth_basic))
        .layer(from_fn(middleware::custom_log))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
        .into_make_service();

    let host = std::env::var("TEMPLATE_HOST").unwrap_or("0.0.0.0:7777".to_owned());
    let addr: SocketAddr = host.parse().expect("invalid TEMPLATE_HOST");
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(address = %addr, "listening");

    axum::serve(listener, router).await.unwrap();
    Ok(())
}

fn tracing_init() {
    use tracing::Level;
    use tracing_subscriber::{
        EnvFilter, filter, fmt, layer::SubscriberExt, util::SubscriberInitExt,
    };

    const NAME: &str = env!("CARGO_PKG_NAME");

    let event_format = fmt::format().with_line_number(true);
    let sub_fmt = tracing_subscriber::fmt::layer().event_format(event_format);

    let fallback_log_level: EnvFilter = match cfg!(debug_assertions) {
        true => format!("info,{NAME}=debug").into(),
        _ => "info".into(),
    };
    let log_level = EnvFilter::try_from_default_env().unwrap_or(fallback_log_level);

    let fltr = filter::Targets::new()
        .with_target("tower_http::trace::on_response", Level::TRACE)
        //.with_target("tower_http::trace::on_request", Level::TRACE)
        .with_target("tower_http::trace::make_span", Level::DEBUG)
        .with_default(Level::INFO);

    tracing::info!(%log_level, "Using tracing");
    tracing_subscriber::registry()
        .with(sub_fmt)
        .with(log_level)
        .with(fltr)
        .init();
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
