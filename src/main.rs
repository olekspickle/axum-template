//! ![axum-template](https://github.com/alekspickle/axum-template/assets/22867443/2e34e8b3-0340-4f2f-9cf0-bcad18552991)
//!
//! ## Overview
//! Template to have something to get-go in some situations
//!
//! This template provides:
//! - Axum server(with middleware)
//! - Templates
//! - Containerization
//!
use std::net::SocketAddr;

use axum::{middleware::from_fn, routing::get, Router};
use tokio::net::TcpListener;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::info;

mod error;
mod form_zip;
mod handlers;
mod middleware;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_init();

    // Static asset service
    let serve_dir = ServeDir::new("static").not_found_service(ServeDir::new("./"));
    let router = Router::new()
        .route("/", get(handlers::index))
        .route("/main", get(handlers::main))
        .route("/fetch", get(handlers::fetch))
        .route("/fetch-zip", get(handlers::fetch_zip))
        .fallback(handlers::handle_404)
        .nest_service("/static", serve_dir.clone())
        .layer(from_fn(middleware::auth))
        .layer(from_fn(middleware::log))
        .layer(TraceLayer::new_for_http())
        .into_make_service();

    let addr = SocketAddr::from(([0, 0, 0, 0], 7777));
    let listener = TcpListener::bind(addr).await?;
    info!("listening on {}", addr);

    axum::serve(listener, router).await.unwrap();
    Ok(())
}

fn tracing_init() {
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    const NAME: &str = env!("CARGO_PKG_NAME");
    let fallback_log_level: EnvFilter = match cfg!(debug_assertions) {
        true => format!("info,{NAME}=debug").into(),
        _ => "info".into(),
    };
    let log_level = EnvFilter::try_from_default_env().unwrap_or(fallback_log_level);
    info!(%log_level, "Using tracing");
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(log_level)
        .init();
}
