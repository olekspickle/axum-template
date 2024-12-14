//! ![axum-template](https://private-user-images.githubusercontent.com/22867443/395807393-714f8d47-1e8e-4544-8516-67270985d916.gif?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzQxOTc1MzcsIm5iZiI6MTczNDE5NzIzNywicGF0aCI6Ii8yMjg2NzQ0My8zOTU4MDczOTMtNzE0ZjhkNDctMWU4ZS00NTQ0LTg1MTYtNjcyNzA5ODVkOTE2LmdpZj9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNDEyMTQlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjQxMjE0VDE3MjcxN1omWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPTc4MzhmOWQ4YWNlMGExZTliYmFjODMxNGQ1MWE1M2IyNWU0OGUzODVhNjY2MzJiY2JmM2FlNDU5YzE5OTc0ZjgmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0In0.I16zH9fwBo7N99jlqEtMzHl0ZjFOGrWX0UlXZs0xNFc)
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
//! I found axum to be the most ergonomic web framework out there, and while there might be not
//! enough examples at the moment, it is quite a breeze to use
//! - static files was sure one noticeable pain in the rear to figure out
//! - surrealdb sure adds complexity, I'm adding it under a feature because sqlite integration is
//!     so much less crates to compile(190+ vs 500+)
//!
use axum::{
    middleware::from_fn,
    routing::{delete, get, patch, post},
    Router,
};
use std::net::SocketAddr;
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

    // init DB in the background
    tokio::spawn(async move {
        let res = db::init().await;
        if let Err(e) = res {
            eprintln!("connection error: {}", e);
        }
    });

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
    use tracing::Level;
    use tracing_subscriber::{
        filter, fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
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

    info!(%log_level, "Using tracing");
    tracing_subscriber::registry()
        .with(sub_fmt)
        .with(log_level)
        .with(fltr)
        .init();
}
