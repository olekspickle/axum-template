pub mod posts;
pub mod projects;

use utoipa::OpenApi;

use crate::state::AppState;

/// Swagger UI doc
#[derive(OpenApi)]
#[openapi(
    paths(
        projects::list_projects,
        projects::get_project,
        projects::create_project,
        projects::update_project,
        projects::delete_project,
        posts::list_posts,
        posts::get_post,
        posts::create_post,
        posts::update_post,
        posts::delete_post,
    ),
    components(schemas(projects::ProjectResponse, posts::PostResponse))
)]
pub struct ApiDoc;

pub fn router() -> axum::Router<AppState> {
    use axum::routing::{delete, get, patch, post};

    axum::Router::new()
        .route("/v1/projects", get(projects::list_projects))
        .route("/v1/projects", post(projects::create_project))
        .route("/v1/projects/{id}", get(projects::get_project))
        .route("/v1/projects/{id}", patch(projects::update_project))
        .route("/v1/projects/{id}", delete(projects::delete_project))
        .route("/v1/posts", get(posts::list_posts))
        .route("/v1/posts", post(posts::create_post))
        .route("/v1/posts/{id}", get(posts::get_post))
        .route("/v1/posts/{id}", patch(posts::update_post))
        .route("/v1/posts/{id}", delete(posts::delete_post))
}
