#![doc = include_str!("../README.md")]

pub mod api;
pub mod config;
pub mod db;
pub mod error;
pub mod handlers;
pub mod how_to;
pub mod middleware;
pub mod state;
pub mod tls;

pub use config::Config;
pub use db::Db;
pub use middleware::TokenManager;
pub use state::AppState;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware::{from_fn, from_fn_with_state},
    routing::{get, post},
};
use tower_http::{
    catch_panic::CatchPanicLayer, compression::CompressionLayer, services::ServeDir,
    trace::TraceLayer,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Enough for any form/JSON payload the app accepts; uploads opt out on their own route.
const DEFAULT_BODY_LIMIT: usize = 256 * 1024;

pub fn app_router(state: AppState) -> Router<()> {
    let serve_dir = ServeDir::new("static").not_found_service(ServeDir::new("templates/404.html"));
    let doc = api::ApiDoc::openapi();
    let swagger = SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", doc);

    let admin_state = state.clone().with_role(middleware::Role::Admin);
    let editor_state = state.clone().with_role(middleware::Role::Editor);

    // Reads need any authenticated caller, writes need at least Editor.
    let api_router = api::read_router()
        .layer(from_fn_with_state(state.clone(), middleware::require_role))
        .merge(
            api::write_router().layer(from_fn_with_state(editor_state, middleware::require_role)),
        );

    // The API schema describes admin-only endpoints, so it is not public either.
    let swagger = Router::new().merge(swagger).layer(from_fn_with_state(
        admin_state.clone(),
        middleware::require_role,
    ));

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
        .layer(DefaultBodyLimit::max(DEFAULT_BODY_LIMIT))
        .layer(TraceLayer::new_for_http())
        .layer(from_fn(middleware::custom_log))
        .layer(from_fn_with_state(state.clone(), middleware::rate_limit))
        .layer(from_fn_with_state(
            state.clone(),
            middleware::security_headers,
        ))
        .layer(CompressionLayer::new())
        .layer(CatchPanicLayer::new())
        .with_state(state)
}
