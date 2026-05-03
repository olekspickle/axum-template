//! ![axum-template demo](https://github.com/user-attachments/assets/a16843e7-7537-4c73-a550-52a37b6fbf73)
//! Axum Template - Portfolio/blog website template
//!
//! ## Overview
//! Portfolio/blog website template for a company that does software/games projects
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
//! - [x] RBAC (User/Editor/Admin)
//! - [x] HttpOnly cookie support
//! - [x] Rate limiting on login
//! - [x] Enable HTTPS
//! - [x] Add login page template
//! - [x] Audit logging
//! - [x] Secure cookie flag
//! - [x] Password reset flow
//! - [x] Remember me checkbox with longer token TTL
//!
//! ## Quick start
//! Install [cargo-generate] and run:
//! ```bash
//! cargo generate olekspickle/axum-template -n my-project
//! ```
//!
//! # Running
//! ```bash
//! # SQLite3 backend:
//! make run
//!
//! # SurrealDB backend
//! make surreal
//! ```
//! You can peek into Makefile for build details
//!
//! ## Configuration
//! Edit `config.toml` to configure:
//! - Server host/port
//! - Database path
//! - Admin credentials (password is argon2 hashed)
//! - Site name and tagline
//!
//! ### Afterthoughts and issues
//! I found axum to be the most ergonomic web framework out there, and while there might be not
//! enough examples at the moment, it is quite a breeze to use
//! - static files was sure one noticeable pain in the rear to figure out
//! - surrealdb sure adds complexity, I'm adding it under a feature because sqlite integration is
//!   so much less crates to compile(190+ vs 500+)
//!
//! [cargo-generate]: https://github.com/cargo-generate/cargo-generate
//!

pub mod api;
pub mod config;
pub mod db;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod state;
pub mod tls;

pub use config::Config;
pub use db::Db;
pub use middleware::TokenManager;
pub use state::AppState;

use axum::{
    Router,
    middleware::{from_fn, from_fn_with_state},
    routing::{get, post},
};
use tower_http::{services::ServeDir, trace::TraceLayer};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub fn app_router(state: AppState) -> Router<()> {
    let serve_dir = ServeDir::new("static").not_found_service(ServeDir::new("templates/404.html"));
    let doc = api::ApiDoc::openapi();
    let swagger = SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", doc);

    let api_router =
        api::router().layer(from_fn_with_state(state.clone(), middleware::require_role));

    let admin_state = AppState {
        required_role: middleware::Role::Admin,
        ..state.clone()
    };
    let admin_router = handlers::admin::router(admin_state);

    Router::new()
        .merge(swagger)
        .route("/", get(handlers::home))
        .route("/projects", get(handlers::projects))
        .route("/projects/{slug}", get(handlers::project_detail))
        .route("/blog", get(handlers::blog))
        .route("/blog/{slug}", get(handlers::post_detail))
        .route("/about", get(handlers::about))
        .route("/contact", get(handlers::contact))
        .nest("/admin", admin_router)
        .nest("/api", api_router)
        .route("/login", post(handlers::admin::login))
        .route("/login", get(handlers::admin::login_page))
        .nest_service("/static", serve_dir.clone())
        .fallback(handlers::to_404)
        .layer(TraceLayer::new_for_http())
        .layer(from_fn(middleware::custom_log))
        .layer(from_fn_with_state(state.clone(), middleware::rate_limit))
        .with_state(state)
}
