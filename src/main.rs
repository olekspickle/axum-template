//!
//! ## Overview
//! Template to have something to get-go in some situations
//!
//! This template provides:
//! - Axum server
//! - Templates
//! - Containerization
//!

use axum::{routing::get, Router};
use std::net::SocketAddr;
use tower_http::{services::ServeDir, trace::TraceLayer};

mod handlers;

#[tokio::main]
async fn main() {
    tracing_init();

    // Static asset service
    let serve_dir = ServeDir::new("static").not_found_service(ServeDir::new("./"));
    let app = Router::new()
        .route("/", get(handlers::index))
        // Some pages to route from
        .route("/first", get(handlers::first))
        .route("/second", get(handlers::second))
        .route("/third", get(handlers::third))
        // Have static assets be also served
        .nest_service("/static", serve_dir.clone())
        .fallback(handlers::handle_404);

    let addr = SocketAddr::from(([127, 0, 0, 1], 7777));
    tracing::debug!("listening on {}", addr);
    let log_layer = TraceLayer::new_for_http();
    axum::Server::bind(&addr)
        .serve(app.layer(log_layer).into_make_service())
        .await
        .unwrap();
}

fn tracing_init() {
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    let fallback_log_level = format!("{}=debug,tower=debug", env!("CARGO_PKG_NAME"));
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| fallback_log_level.into()))
        .with(fmt::layer())
        .init();
}
