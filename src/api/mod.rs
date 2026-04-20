pub mod posts;
pub mod projects;

use utoipa::OpenApi;
use axum::routing::get;
use utoipa_axum::router::OpenApiRouter;
use utoipa_swagger_ui::SwaggerUi;

use crate::state::AppState;

#[derive(OpenApi)]
#[openapi(
    nest((path = projects::ENDPOINT, api = projects::ProjectsApi)),
    nest((path = posts::ENDPOINT, api = posts::PostsApi)),
)]
pub struct ApiDoc;

#[utoipa::path(get, path = "/api-docs/openapi.json")]
async fn openapi_json() -> axum::Json<utoipa::openapi::OpenApi> {
    axum::Json(ApiDoc::openapi())
}

pub fn router() -> axum::Router<AppState> {
    let (router, doc) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .route("/api/v1/projects", get(projects::list_projects))
        .route("/api/v1/projects/{slug}", get(projects::get_project))
        .route("/api/v1/posts", get(posts::list_posts))
        .route("/api/v1/posts/{slug}", get(posts::get_post))
        .split_for_parts();

    router.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", doc))
}
