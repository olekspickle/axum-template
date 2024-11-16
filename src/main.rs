//! ![axum-template](https://github.com/alekspickle/axum-template/assets/22867443/2e34e8b3-0340-4f2f-9cf0-bcad18552991)
//!
//! ## Overview
//! Template to have something to get-go in some situations
//!
//! This template provides:
//! - [x] Axum server(with middleware)
//! - [x] Askama templates
//! - [x] Containerization(with compose)
//! - [ ] SurrealDB backend
//!
//! ## Afterthoughts and issues
//! I found axum to be the most ergonomic web framework out there, and while there might be not
//! enough examples at the moment, it it quite a breeze to use
//! - static files was sure one pain in the back to figure out
//! - surrealdb sure adds complexity, if you want example of sqlite with connection pool example,
//!     check out my other template: [actix-template](https://github.com/alekspickle/actix-template)
//!
use std::net::SocketAddr;

use axum::{middleware::from_fn, routing::get, Router};
use tokio::net::TcpListener;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::info;

mod db;
mod error;
mod form_zip;
mod handlers;
mod middleware;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_init();

    // Static asset service
    let serve_dir = ServeDir::new("static").not_found_service(ServeDir::new("templates/404.html"));
    let router = Router::new()
        .route("/", get(handlers::index))
        .route("/hello/:id", get(handlers::home))
        .route("/posts", get(handlers::posts))
        //.route("/add-post", get(handlers::add_posts))
        //.route("/delete-post", get(handlers::delete_post))
        .route("/fetch-zip", get(handlers::fetch_zip))
        .nest_service("/static", serve_dir.clone())
        .fallback(handlers::handle_404)
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

    let event_format = fmt::format().with_line_number(true);
    let sub_fmt = tracing_subscriber::fmt::layer().event_format(event_format);
    let fallback_log_level: EnvFilter = match cfg!(debug_assertions) {
        true => format!("info,{NAME}=debug").into(),
        _ => "info".into(),
    };
    let log_level = EnvFilter::try_from_default_env().unwrap_or(fallback_log_level);
    info!(%log_level, "Using tracing");
    tracing_subscriber::registry()
        .with(sub_fmt)
        .with(log_level)
        .init();
}
