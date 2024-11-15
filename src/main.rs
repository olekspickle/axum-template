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
use itertools::Itertools;
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
        .route("/main", get(handlers::main))
        .route("/secondary", get(handlers::secondary))
        // Have static assets be also served
        .nest_service("/static", serve_dir.clone())
        .fallback(handlers::handle_404);

    let addr = SocketAddr::from(([0, 0, 0, 0], 7777));
    tracing::debug!("listening on {}", addr);
    let log_layer = TraceLayer::new_for_http();
    axum::Server::bind(&addr)
        .serve(app.layer(log_layer).into_make_service())
        .await
        .unwrap();
}

fn tracing_init() {
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    const NOISY_CRATES: &[&str] = &["hyper", "tower_http"];

    let noisy = NOISY_CRATES
        .into_iter()
        .map(|s| format!("{s}=info"))
        .join(",");
    let fallback_log_level: EnvFilter = match cfg!(debug_assertions) {
        true => format!("debug,{noisy}").into(),
        _ => format!("info,{noisy}").into(),
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| fallback_log_level))
        .init();
}
