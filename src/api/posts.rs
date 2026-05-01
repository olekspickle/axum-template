use axum::{
    extract::{Path, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    db::{NewPost, Post},
    state::AppState,
};

#[derive(Serialize, Deserialize, ToSchema)]
pub struct PostResponse {
    pub id: String,
    pub title: String,
    pub slug: String,
    pub excerpt: String,
    pub cover_image: String,
    pub tags: Vec<String>,
    pub author: String,
    pub published: bool,
}

impl From<Post> for PostResponse {
    fn from(p: Post) -> Self {
        Self {
            id: p.id,
            title: p.title,
            slug: p.slug,
            excerpt: p.excerpt,
            cover_image: p.cover_image,
            tags: p.tags,
            author: p.author,
            published: p.published,
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/posts",
    responses(
        (status = 200, description = "List of published posts", body = Vec<PostResponse>),
    )
)]
pub async fn list_posts(State(state): State<AppState>) -> Json<Vec<PostResponse>> {
    let posts = state.db.get_published_posts().await.unwrap_or_default();
    Json(posts.into_iter().map(Into::into).collect())
}

#[utoipa::path(
    get,
    path = "/api/v1/posts/{id}",
    responses(
        (status = 200, description = "Post details", body = PostResponse),
        (status = 404, description = "Post not found"),
    )
)]
pub async fn get_post(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Option<PostResponse>> {
    let post = state.db.get_post(&id).await.ok().flatten().map(Into::into);
    Json(post)
}

#[utoipa::path(
    post,
    path = "/api/v1/posts",
    request_body = NewPost,
    responses(
        (status = 201, description = "Post created"),
        (status = 400, description = "Invalid request"),
    )
)]
pub async fn create_post(
    State(state): State<AppState>,
    Json(form): Json<NewPost>,
) -> Json<serde_json::Value> {
    match state.db.create_post(form).await {
        Ok(id) => Json(serde_json::json!({ "id": id })),
        Err(e) => Json(serde_json::json!({ "error": e.to_string() })),
    }
}

#[utoipa::path(
    patch,
    path = "/api/v1/posts/{id}",
    request_body = NewPost,
    responses(
        (status = 200, description = "Post updated"),
        (status = 404, description = "Post not found"),
    )
)]
pub async fn update_post(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(form): Json<NewPost>,
) -> Json<serde_json::Value> {
    match state.db.update_post(&id, form).await {
        Ok(_) => Json(serde_json::json!({ "success": true })),
        Err(e) => Json(serde_json::json!({ "error": e.to_string() })),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/posts/{id}",
    responses(
        (status = 200, description = "Post deleted"),
        (status = 404, description = "Post not found"),
    )
)]
pub async fn delete_post(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    state.db.delete_post(&id).await.ok();
    Json(serde_json::json!({ "success": true }))
}
