pub mod posts;
pub mod projects;

use axum::routing::get;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use crate::state::AppState;

#[derive(OpenApi)]
#[openapi(
    paths(
        projects::list_projects,
        projects::get_project,
        posts::list_posts,
        posts::get_post,
    ),
    components(
        schemas(projects::ProjectResponse, posts::PostResponse)
    ),
)]
pub struct ApiDoc;

#[utoipa::path(get, path = "/api-docs/openapi.json")]
pub async fn openapi_json() -> axum::Json<utoipa::openapi::OpenApi> {
    axum::Json(ApiDoc::openapi())
}

pub fn router() -> axum::Router<AppState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .route("/api/v1/projects", get(projects::list_projects))
        .route("/api/v1/projects/{slug}", get(projects::get_project))
        .route("/api/v1/posts", get(posts::list_posts))
        .route("/api/v1/posts/{slug}", get(posts::get_post))
        .into()
}
