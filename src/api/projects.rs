use axum::{Router, extract::State, response::Json, routing::get};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::db::Project;
use crate::state::AppState;

pub const ENDPOINT: &str = "/api/v1/projects";

#[derive(OpenApi)]
#[openapi(
    paths(list_projects, get_project),
    components(schemas(ProjectResponse))
)]
pub struct ProjectsApi;

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ProjectResponse {
    pub id: String,
    pub title: String,
    pub slug: String,
    pub description: String,
    pub category: String,
    pub thumbnail_url: String,
    pub images: Vec<String>,
    pub tech_stack: Vec<String>,
    pub demo_url: Option<String>,
    pub repo_url: Option<String>,
    pub featured: bool,
}

impl From<Project> for ProjectResponse {
    fn from(p: Project) -> Self {
        Self {
            id: p.id,
            title: p.title,
            slug: p.slug,
            description: p.description,
            category: p.category,
            thumbnail_url: p.thumbnail_url,
            images: p.images,
            tech_stack: p.tech_stack,
            demo_url: p.demo_url,
            repo_url: p.repo_url,
            featured: p.featured,
        }
    }
}

#[utoipa::path(
    get,
    path = ENDPOINT,
    responses(
        (status = 200, description = "List of projects", body = Vec<ProjectResponse>),
    )
)]
pub async fn list_projects(State(state): State<AppState>) -> Json<Vec<ProjectResponse>> {
    let projects = state.db.get_projects().await.unwrap_or_default();
    Json(projects.into_iter().map(Into::into).collect())
}

#[utoipa::path(
    get,
    path = "/api/v1/projects/{slug}",
    responses(
        (status = 200, description = "Project details", body = ProjectResponse),
        (status = 404, description = "Project not found"),
    )
)]
pub async fn get_project(
    State(state): State<AppState>,
    axum::extract::Path(slug): axum::extract::Path<String>,
) -> Json<Option<ProjectResponse>> {
    let project = state
        .db
        .get_project(&slug)
        .await
        .ok()
        .flatten()
        .map(Into::into);
    Json(project)
}

pub fn router() -> Router<AppState> {
    Router::<AppState>::new()
        .route(ENDPOINT, get(list_projects))
        .route("/api/v1/projects/:slug", get(get_project))
        .route(
            "/openapi.json",
            get(|| async { axum::Json(ProjectsApi::openapi()) }),
        )
}
