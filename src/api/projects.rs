use axum::{
    extract::{Path, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    db::{NewProject, Project},
    state::AppState,
};

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
    path = "/api/v1/projects",
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
    path = "/api/v1/projects/{id}",
    responses(
        (status = 200, description = "Project details", body = ProjectResponse),
        (status = 404, description = "Project not found"),
    )
)]
pub async fn get_project(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Option<ProjectResponse>> {
    let project = state
        .db
        .get_project(&id)
        .await
        .ok()
        .flatten()
        .map(Into::into);
    Json(project)
}

#[utoipa::path(
    post,
    path = "/api/v1/projects",
    request_body = NewProject,
    responses(
        (status = 201, description = "Project created"),
        (status = 400, description = "Invalid request"),
    )
)]
pub async fn create_project(
    State(state): State<AppState>,
    Json(form): Json<NewProject>,
) -> Json<serde_json::Value> {
    match state.db.create_project(form).await {
        Ok(id) => Json(serde_json::json!({ "id": id })),
        Err(e) => Json(serde_json::json!({ "error": e.to_string() })),
    }
}

#[utoipa::path(
    patch,
    path = "/api/v1/projects/{id}",
    request_body = NewProject,
    responses(
        (status = 200, description = "Project updated"),
        (status = 404, description = "Project not found"),
    )
)]
pub async fn update_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(form): Json<NewProject>,
) -> Json<serde_json::Value> {
    match state.db.update_project(&id, form).await {
        Ok(_) => Json(serde_json::json!({ "success": true })),
        Err(e) => Json(serde_json::json!({ "error": e.to_string() })),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/projects/{id}",
    responses(
        (status = 200, description = "Project deleted"),
        (status = 404, description = "Project not found"),
    )
)]
pub async fn delete_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    state.db.delete_project(&id).await.ok();
    Json(serde_json::json!({ "success": true }))
}
