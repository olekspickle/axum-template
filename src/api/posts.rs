use axum::{Router, extract::State, response::Json, routing::get};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::db::Post;
use crate::state::AppState;

pub const ENDPOINT: &str = "/api/v1/posts";

#[derive(OpenApi)]
#[openapi(paths(list_posts, get_post), components(schemas(PostResponse)))]
pub struct PostsApi;

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
    path = ENDPOINT,
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
    path = "/api/v1/posts/{slug}",
    responses(
        (status = 200, description = "Post details", body = PostResponse),
        (status = 404, description = "Post not found"),
    )
)]
pub async fn get_post(
    State(state): State<AppState>,
    axum::extract::Path(slug): axum::extract::Path<String>,
) -> Json<Option<PostResponse>> {
    let post = state
        .db
        .get_post(&slug)
        .await
        .ok()
        .flatten()
        .map(Into::into);
    Json(post)
}

pub fn router() -> Router<AppState> {
    Router::<AppState>::new()
        .route(ENDPOINT, get(list_posts))
        .route("/api/v1/posts/:slug", get(get_post))
}
