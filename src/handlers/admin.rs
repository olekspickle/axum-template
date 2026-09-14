use std::collections::HashMap;
use std::path::Path as StdPath;
use std::str::FromStr;

use argon2::{Argon2, password_hash::PasswordHasher};
use askama::Template;
use axum::{
    Form, Router,
    extract::{DefaultBodyLimit, Path, Query, State, multipart::Multipart},
    http::{StatusCode, header::HeaderName},
    middleware::from_fn_with_state,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tower_http::limit::RequestBodyLimitLayer;

use crate::{
    db::{NewPost, NewProject, NewTeamMember, Post, Project, TeamMember},
    middleware::{self, Role},
    state::AppState,
};

pub async fn login_page() -> impl IntoResponse {
    let template = admin_templates::Login {
        title: "Login".to_string(),
    };
    HtmlTemplate(template)
}

pub fn router(state: AppState) -> Router<AppState> {
    let public = Router::<AppState>::new()
        .route("/forgot-password", get(forgot_password_page))
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", get(reset_password_page))
        .route("/reset-password", post(reset_password));

    let protected = Router::<AppState>::new()
        .route("/", get(admin_dashboard))
        .route(
            "/projects",
            get(admin_projects_list).post(admin_save_project),
        )
        .route("/projects/search", get(admin_search_projects))
        .route("/projects/new", get(admin_new_project))
        .route("/projects/{slug}", get(admin_edit_project))
        .route("/posts", get(admin_posts_list).post(admin_save_post))
        .route("/posts/search", get(admin_search_posts))
        .route("/posts/new", get(admin_new_post))
        .route("/posts/{slug}", get(admin_edit_post))
        .route("/team", get(admin_team_list))
        .route("/team", post(admin_create_team_member))
        .route("/team/search", get(admin_search_team))
        .route("/team/{id}", delete(admin_delete_team_member))
        .route("/logout", post(admin_logout))
        .route("/preview", post(admin_preview))
        // Only this route opts out of the global body limit.
        .merge(
            Router::<AppState>::new()
                .route("/upload", post(upload_media))
                .layer(DefaultBodyLimit::disable())
                .layer(RequestBodyLimitLayer::new(MAX_UPLOAD_BYTES)),
        )
        .layer(from_fn_with_state(state, middleware::require_role));

    public.merge(protected)
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
    remember: Option<String>,
}

pub async fn login(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    let long = form.remember.as_deref() == Some("on");
    // Try admin login first
    if let Some(token) = state
        .token_manager
        .login(&form.username, &form.password, long)
        .await
    {
        tracing::info!(username = %form.username, role = "Admin", "login successful");
        let mut response = (
            StatusCode::OK,
            [(HeaderName::from_static("hx-redirect"), "/admin")],
        )
            .into_response();
        set_auth_cookie(&mut response, &token, &state, long);
        return response;
    }

    // Try team member login
    if let Ok(Some(member)) = state.db.get_team_member(&form.username).await
        && let Some(hash) = &member.password_hash
    {
        use argon2::{PasswordHash, PasswordVerifier};
        if let Ok(parsed) = PasswordHash::new(hash)
            && argon2::Argon2::default()
                .verify_password(form.password.as_bytes(), &parsed)
                .is_ok()
        {
            // Determine role based on team member's role field
            let role = Role::from_str(member.role.as_str()).unwrap_or_default();
            tracing::info!(username = %form.username, ?role, "login successful");
            let token = state
                .token_manager
                .generate_user_token(member.name, role, long)
                .await;
            let mut response = (
                StatusCode::OK,
                [(HeaderName::from_static("hx-redirect"), "/admin/")],
            )
                .into_response();
            set_auth_cookie(&mut response, &token, &state, long);
            return response;
        }
    }

    tracing::warn!(username = %form.username, "login failed: invalid credentials");
    (
        StatusCode::UNAUTHORIZED,
        Html(r#"<div id="error-message" class="text-red-600 text-sm">Invalid credentials</div>"#),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct PreviewForm {
    content: String,
}

pub async fn admin_preview(Form(form): Form<PreviewForm>) -> impl IntoResponse {
    Html(crate::handlers::render_markdown(&form.content))
}

fn set_auth_cookie(response: &mut Response, token: &str, state: &AppState, long: bool) {
    use axum::http::header::SET_COOKIE;
    let max_age = if long {
        state.config.auth.token_ttl * 30 * 24
    } else {
        state.config.auth.token_ttl
    };
    let cookie = if state.https {
        format!(
            "token={}; HttpOnly; SameSite=Strict; Max-Age={}; Path=/; Secure",
            token, max_age
        )
    } else {
        format!(
            "token={}; HttpOnly; SameSite=Strict; Max-Age={}; Path=/",
            token, max_age
        )
    };
    response
        .headers_mut()
        .insert(SET_COOKIE, cookie.parse().unwrap());
}

pub async fn admin_dashboard(State(_state): State<AppState>) -> impl IntoResponse {
    let template = admin_templates::AdminDashboard {
        title: "Admin Dashboard".to_string(),
    };
    HtmlTemplate(template)
}

pub async fn admin_projects_list(State(state): State<AppState>) -> impl IntoResponse {
    let projects = state.db.get_projects().await.unwrap_or_default();
    let template = admin_templates::AdminProjectsList {
        title: "Manage Projects".to_string(),
        projects,
    };
    HtmlTemplate(template)
}

pub async fn admin_new_project() -> impl IntoResponse {
    let template = admin_templates::AdminProjectEdit {
        title: "New Project".to_string(),
        project: None,
    };
    HtmlTemplate(template)
}

pub async fn admin_edit_project(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let project = state.db.get_project_by_slug(&slug).await.ok().flatten();
    let template = admin_templates::AdminProjectEdit {
        title: "Edit Project".to_string(),
        project,
    };
    HtmlTemplate(template)
}

pub async fn admin_posts_list(State(state): State<AppState>) -> impl IntoResponse {
    let posts = state.db.get_posts().await.unwrap_or_default();
    let template = admin_templates::AdminPostsList {
        title: "Manage Posts".to_string(),
        posts,
    };
    HtmlTemplate(template)
}

pub async fn admin_new_post() -> impl IntoResponse {
    let template = admin_templates::AdminPostEdit {
        title: "New Post".to_string(),
        post: None,
    };
    HtmlTemplate(template)
}

pub async fn admin_edit_post(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let post = state.db.get_post_by_slug(&slug).await.ok().flatten();
    let template = admin_templates::AdminPostEdit {
        title: "Edit Post".to_string(),
        post,
    };
    HtmlTemplate(template)
}

pub async fn admin_search_projects(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let q = params.get("q").cloned().unwrap_or_default().to_lowercase();
    let projects = state.db.get_projects().await.unwrap_or_default();
    let projects: Vec<Project> = if q.is_empty() {
        projects
    } else {
        projects
            .into_iter()
            .filter(|p| {
                p.title.to_lowercase().contains(&q)
                    || p.slug.to_lowercase().contains(&q)
                    || p.category.to_lowercase().contains(&q)
            })
            .collect()
    };
    let template = admin_templates::AdminProjectRows { projects };
    HtmlTemplate(template)
}

pub async fn admin_search_posts(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let q = params.get("q").cloned().unwrap_or_default().to_lowercase();
    let posts = state.db.get_posts().await.unwrap_or_default();
    let posts: Vec<Post> = if q.is_empty() {
        posts
    } else {
        posts
            .into_iter()
            .filter(|p| {
                p.title.to_lowercase().contains(&q)
                    || p.author.to_lowercase().contains(&q)
                    || p.excerpt.to_lowercase().contains(&q)
                    || p.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect()
    };
    let template = admin_templates::AdminPostRows { posts };
    HtmlTemplate(template)
}

pub async fn admin_search_team(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let q = params.get("q").cloned().unwrap_or_default().to_lowercase();
    let members = state.db.get_team_members().await.unwrap_or_default();
    let members: Vec<TeamMember> = if q.is_empty() {
        members
    } else {
        members
            .into_iter()
            .filter(|m| {
                m.name.to_lowercase().contains(&q)
                    || m.role.to_lowercase().contains(&q)
                    || m.bio.to_lowercase().contains(&q)
            })
            .collect()
    };
    let template = admin_templates::AdminTeamRows { members };
    HtmlTemplate(template)
}

#[derive(Deserialize)]
pub struct ProjectForm {
    id: Option<String>,
    title: String,
    slug: String,
    description: String,
    category: String,
    thumbnail_url: String,
    #[serde(default)]
    images: String,
    #[serde(default)]
    tech_stack: String,
    demo_url: Option<String>,
    repo_url: Option<String>,
    featured: Option<String>,
}

impl ProjectForm {
    fn into_new_project(self) -> NewProject {
        NewProject {
            title: self.title,
            slug: self.slug,
            description: self.description,
            category: self.category,
            thumbnail_url: self.thumbnail_url,
            images: split_csv(self.images),
            tech_stack: split_csv(self.tech_stack),
            demo_url: optional_url(self.demo_url),
            repo_url: optional_url(self.repo_url),
            featured: self.featured.is_some(),
        }
    }
}

#[derive(Deserialize)]
pub struct PostForm {
    id: Option<String>,
    title: String,
    slug: String,
    content: String,
    #[serde(default)]
    excerpt: String,
    cover_image: String,
    #[serde(default)]
    tags: String,
    author: String,
    published: Option<String>,
}

impl PostForm {
    fn into_new_post(self) -> NewPost {
        let excerpt = if self.excerpt.trim().is_empty() {
            self.content.chars().take(200).collect()
        } else {
            self.excerpt
        };
        NewPost {
            title: self.title,
            slug: self.slug,
            content: self.content,
            excerpt,
            cover_image: self.cover_image,
            tags: split_csv(self.tags),
            author: self.author,
            published: self.published.is_some(),
        }
    }
}

fn split_csv(value: String) -> Vec<String> {
    value
        .split(',')
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn optional_url(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

pub async fn admin_save_project(
    State(state): State<AppState>,
    form: Result<Form<ProjectForm>, axum::extract::rejection::FormRejection>,
) -> impl IntoResponse {
    let form = match form {
        Ok(form) => form.0,
        Err(_) => return error_fragment("Invalid form data"),
    };

    let id = form.id.clone();
    let new_project = form.into_new_project();
    let result = match id {
        Some(id) => state.db.update_project(&id, new_project).await,
        None => state.db.create_project(new_project).await.map(|_| ()),
    };

    match result {
        Ok(_) => redirect_fragment("/admin/projects"),
        Err(e) => error_fragment(&format!("Failed to save project: {e}")),
    }
}

pub async fn admin_save_post(
    State(state): State<AppState>,
    form: Result<Form<PostForm>, axum::extract::rejection::FormRejection>,
) -> impl IntoResponse {
    let form = match form {
        Ok(form) => form.0,
        Err(_) => return error_fragment("Invalid form data"),
    };

    let id = form.id.clone();
    let new_post = form.into_new_post();
    let result = match id {
        Some(id) => state.db.update_post(&id, new_post).await,
        None => state.db.create_post(new_post).await.map(|_| ()),
    };

    match result {
        Ok(_) => redirect_fragment("/admin/posts"),
        Err(e) => error_fragment(&format!("Failed to save post: {e}")),
    }
}

fn redirect_fragment(path: &str) -> Response {
    (
        StatusCode::OK,
        [(HeaderName::from_static("hx-redirect"), path)],
    )
        .into_response()
}

fn error_fragment(message: &str) -> Response {
    Html(format!(
        r#"<div id="error-message" class="text-red-600 text-sm mt-2">{message}</div>"#
    ))
    .into_response()
}

pub async fn admin_team_list(State(state): State<AppState>) -> impl IntoResponse {
    let members = state.db.get_team_members().await.unwrap_or_default();
    let template = admin_templates::AdminTeamList {
        title: "Manage Team".to_string(),
        members,
    };
    HtmlTemplate(template)
}

pub async fn admin_create_team_member(
    State(state): State<AppState>,
    Form(form): Form<NewTeamMember>,
) -> impl IntoResponse {
    match state.db.create_team_member(form).await {
        Ok(_) => Redirect::to("/admin/team").into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create team member: {}", e),
        )
            .into_response(),
    }
}

pub async fn admin_delete_team_member(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    state.db.delete_team_member(&id).await.ok();
    StatusCode::OK
}

pub async fn admin_logout(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Some(token) = middleware::extract_token(&headers, &axum::http::Extensions::default()) {
        state.token_manager.invalidate(&token).await;
    }
    // Clear the cookie
    let cookie = if state.https {
        "token=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/; Secure"
    } else {
        "token=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/"
    };
    let mut response = (
        StatusCode::OK,
        [(HeaderName::from_static("hx-redirect"), "/login")],
    )
        .into_response();
    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, cookie.parse().unwrap());
    response
}

/// Per-request cap for the upload route. The admin UI posts one file at a time.
const MAX_UPLOAD_BYTES: usize = 250 * 1024 * 1024;

/// Extensions we are willing to write and later serve from our own origin.
/// `svg`/`html` are deliberately absent - both can execute script.
const ALLOWED_UPLOAD_EXT: [&str; 9] = [
    "jpg", "jpeg", "png", "gif", "webp", "avif", "mp4", "webm", "mov",
];

/// Upload names end up in a filesystem path, so reduce them to a flat safe token.
fn sanitize_slug(slug: &str) -> String {
    let cleaned: String = slug
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' | '-' | '_' => c,
            'A'..='Z' => c.to_ascii_lowercase(),
            _ => '-',
        })
        .take(64)
        .collect();

    let cleaned = cleaned.trim_matches('-').to_string();
    if cleaned.is_empty() {
        "upload".to_string()
    } else {
        cleaned
    }
}

fn upload_error(status: StatusCode, message: &str) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        status,
        axum::Json(serde_json::json!({ "success": false, "error": message })),
    )
}

pub async fn upload_media(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut slug = String::new();
    let mut file_count: u32 = 0;
    let mut upload_count: u32 = 0;

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "malformed multipart upload");
                return upload_error(StatusCode::BAD_REQUEST, "malformed multipart body");
            }
        };

        let name = field.name().unwrap_or_default().to_string();

        if name == "slug" {
            slug = sanitize_slug(&field.text().await.unwrap_or_default());
        } else if name == "file_count" {
            if let Ok(text) = field.text().await
                && let Ok(count) = text.parse()
            {
                file_count = count;
            }
        } else if name == "file" {
            let Some(filename) = field.file_name().map(str::to_string) else {
                continue;
            };

            let ext = StdPath::new(&filename)
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_lowercase())
                .unwrap_or_default();

            if !ALLOWED_UPLOAD_EXT.contains(&ext.as_str()) {
                tracing::warn!(%filename, %ext, "rejected upload: extension not allowed");
                return upload_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "file type not allowed");
            }

            let Ok(data) = field.bytes().await else {
                continue;
            };

            let hash = hex::encode(Sha256::digest(&data));

            if let Some(existing_path) = media_index_lookup(&state, &hash).await {
                tracing::info!(path = %existing_path, hash = %hash, "file already exists");
                return (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "success": true,
                        "existing": true,
                        "path": existing_path,
                        "slug": slug
                    })),
                );
            }

            let slug = if slug.is_empty() {
                "upload".to_string()
            } else {
                slug.clone()
            };
            let dir = StdPath::new("static/media").join(format_dir(&ext));
            if let Err(e) = std::fs::create_dir_all(&dir) {
                tracing::error!(error = %e, dir = %dir.display(), "failed to create media dir");
                return upload_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to store file");
            }

            let mut n = file_count.saturating_add(upload_count);
            let mut final_path = dir.join(format!("{slug}-{n}.{ext}"));
            let mut attempts = 0;
            while final_path.exists() {
                n = n.saturating_add(1);
                attempts += 1;
                if attempts > 10_000 {
                    return upload_error(
                        StatusCode::CONFLICT,
                        "could not find a free filename for this slug",
                    );
                }
                final_path = dir.join(format!("{slug}-{n}.{ext}"));
            }

            let path = final_path.clone();
            let write = tokio::task::spawn_blocking(move || std::fs::write(&path, &data)).await;
            match write {
                Ok(Ok(())) => {
                    tracing::info!(path = %final_path.display(), hash = %hash, "uploaded media");
                    upload_count += 1;
                    media_index_insert(&state, hash, final_path.display().to_string()).await;
                }
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "failed to write file");
                    return upload_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to store file");
                }
                Err(e) => {
                    tracing::error!(error = %e, "upload task failed");
                    return upload_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to store file");
                }
            }
        }
    }

    (
        StatusCode::OK,
        axum::Json(
            serde_json::json!({ "success": true, "count": upload_count, "file_count": file_count, "slug": slug }),
        ),
    )
}

fn format_dir(ext: &str) -> &'static str {
    match ext {
        "gif" => "gif",
        "avif" => "avif",
        "webp" => "webp",
        "mp4" | "webm" | "mov" | "avi" => "video",
        _ => "img",
    }
}

/// Look a digest up in the media index, building it once on first use instead of
/// re-reading every media file on every upload.
async fn media_index_lookup(state: &AppState, hash: &str) -> Option<String> {
    if let Some(index) = state.media_index.read().await.as_ref() {
        return index.get(hash).cloned();
    }

    let built = tokio::task::spawn_blocking(scan_media_dir)
        .await
        .unwrap_or_default();
    let found = built.get(hash).cloned();
    *state.media_index.write().await = Some(built);
    found
}

async fn media_index_insert(state: &AppState, hash: String, path: String) {
    if let Some(index) = state.media_index.write().await.as_mut() {
        index.insert(hash, path);
    }
}

fn scan_media_dir() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let media_dir = StdPath::new("static/media");

    if let Ok(entries) = std::fs::read_dir(media_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir()
                && let Ok(sub_entries) = std::fs::read_dir(&path)
            {
                for sub_entry in sub_entries.flatten() {
                    let file_path = sub_entry.path();
                    if file_path.is_file()
                        && let Ok(data) = std::fs::read(&file_path)
                    {
                        let hash = hex::encode(Sha256::digest(&data));
                        if let Some(path_str) = file_path.to_str() {
                            map.insert(hash, path_str.to_string());
                        }
                    }
                }
            }
        }
    }

    map
}

#[derive(Deserialize)]
pub struct ForgotPasswordForm {
    username: String,
}

pub async fn forgot_password_page() -> impl IntoResponse {
    let template = admin_templates::ForgotPassword {
        title: "Forgot Password".to_string(),
    };
    HtmlTemplate(template)
}

pub async fn forgot_password(
    State(state): State<AppState>,
    Form(form): Form<ForgotPasswordForm>,
) -> impl IntoResponse {
    // Check if user exists (admin or team member)
    let is_admin = state.config.auth.admin_username == form.username;
    let is_team = matches!(state.db.get_team_member(&form.username).await, Ok(Some(_)));

    if is_admin || is_team {
        let reset_token = state
            .token_manager
            .generate_reset_token(&form.username)
            .await;
        // The token is a credential: it goes to the account owner over a side channel,
        // never back to whoever submitted this form. Wire an email sender here; until
        // then debug builds print it to the server console for local testing.
        if cfg!(debug_assertions) {
            tracing::info!(
                username = %form.username,
                reset_url = %format!("/admin/reset-password?token={reset_token}"),
                "password reset requested (debug build only)"
            );
        } else {
            tracing::info!(username = %form.username, "password reset requested");
        }
    }

    // Same response either way, so the form can't be used to enumerate usernames.
    Html(
        r#"<div id="success-message" class="text-green-600 text-sm">If account exists, reset instructions sent</div>"#,
    )
    .into_response()
}

#[derive(Deserialize)]
pub struct ResetPasswordForm {
    token: String,
    new_password: String,
    confirm_password: String,
}

pub async fn reset_password_page(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let token = params.get("token").cloned().unwrap_or_default();
    let template = admin_templates::ResetPassword {
        title: "Reset Password".to_string(),
        token,
    };
    HtmlTemplate(template)
}

/// Long enough that an offline guess against the argon2 hash is not worthwhile.
const MIN_PASSWORD_LEN: usize = 12;

pub async fn reset_password(
    State(state): State<AppState>,
    Form(form): Form<ResetPasswordForm>,
) -> impl IntoResponse {
    if form.new_password != form.confirm_password {
        return error_fragment("Passwords do not match");
    }

    if form.new_password.chars().count() < MIN_PASSWORD_LEN {
        return error_fragment(&format!(
            "Password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }

    let Some(username) = state.token_manager.consume_reset_token(&form.token).await else {
        return error_fragment("Invalid or expired reset token");
    };

    // Admin credentials come from config.toml / ADMIN_PASSWORD env, not the DB - no in-memory reset
    if state.config.auth.admin_username == username {
        return error_fragment(
            "Admin password is managed in config.toml / ADMIN_PASSWORD env - edit it and restart",
        );
    }

    match state.db.get_team_member(&username).await {
        Ok(Some(_)) => {}
        Ok(None) => return error_fragment("Invalid or expired reset token"),
        Err(e) => {
            tracing::error!(error = %e, "password reset lookup failed");
            return error_fragment("Could not reset password, try again later");
        }
    }

    let hash = match Argon2::default().hash_password(form.new_password.as_bytes()) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            tracing::error!(error = %e, "password hashing failed");
            return error_fragment("Could not reset password, try again later");
        }
    };

    if let Err(e) = state.db.update_team_member_password(&username, &hash).await {
        tracing::error!(error = %e, "failed to store new password");
        return error_fragment("Could not reset password, try again later");
    }

    tracing::info!(username = %username, "password reset successful");
    (
        StatusCode::OK,
        [(HeaderName::from_static("hx-redirect"), "/login")],
    )
        .into_response()
}

struct HtmlTemplate<T>(T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: askama::Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template: {}", err),
            )
                .into_response(),
        }
    }
}

pub mod admin_templates {
    use super::*;

    #[derive(Template)]
    #[template(path = "admin/dashboard.html")]
    pub struct AdminDashboard {
        pub title: String,
    }

    #[derive(Template)]
    #[template(path = "admin/projects.html")]
    pub struct AdminProjectsList {
        pub title: String,
        pub projects: Vec<Project>,
    }

    #[derive(Template)]
    #[template(path = "admin/_project-rows.html")]
    pub struct AdminProjectRows {
        pub projects: Vec<Project>,
    }

    #[derive(Template)]
    #[template(path = "admin/project-edit.html")]
    pub struct AdminProjectEdit {
        pub title: String,
        pub project: Option<Project>,
    }

    #[derive(Template)]
    #[template(path = "admin/posts.html")]
    pub struct AdminPostsList {
        pub title: String,
        pub posts: Vec<Post>,
    }

    #[derive(Template)]
    #[template(path = "admin/_post-rows.html")]
    pub struct AdminPostRows {
        pub posts: Vec<Post>,
    }

    #[derive(Template)]
    #[template(path = "admin/post-edit.html")]
    pub struct AdminPostEdit {
        pub title: String,
        pub post: Option<Post>,
    }

    #[derive(Template)]
    #[template(path = "admin/team.html")]
    pub struct AdminTeamList {
        pub title: String,
        pub members: Vec<TeamMember>,
    }

    #[derive(Template)]
    #[template(path = "admin/_team-rows.html")]
    pub struct AdminTeamRows {
        pub members: Vec<TeamMember>,
    }

    #[derive(Template)]
    #[template(path = "admin/login.html")]
    pub struct Login {
        pub title: String,
    }

    #[derive(Template)]
    #[template(path = "admin/forgot-password.html")]
    pub struct ForgotPassword {
        pub title: String,
    }

    #[derive(Template)]
    #[template(path = "admin/reset-password.html")]
    pub struct ResetPassword {
        pub title: String,
        pub token: String,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_cannot_escape_the_media_directory() {
        assert_eq!(sanitize_slug("../../etc/cron.d/pwn"), "etc-cron-d-pwn");
        assert_eq!(sanitize_slug("../.."), "upload");
        assert_eq!(sanitize_slug("a/b\\c"), "a-b-c");
        assert_eq!(sanitize_slug(""), "upload");

        for slug in ["../../etc/passwd", "..", "foo/../../bar", "%2e%2e/x"] {
            let sanitized = sanitize_slug(slug);
            assert!(!sanitized.contains('/'), "{slug} -> {sanitized}");
            assert!(!sanitized.contains('\\'), "{slug} -> {sanitized}");
            assert!(!sanitized.contains(".."), "{slug} -> {sanitized}");
        }
    }

    #[test]
    fn slugs_keep_ordinary_names() {
        assert_eq!(sanitize_slug("My Post Title"), "my-post-title");
        assert_eq!(sanitize_slug("release_v1-2"), "release_v1-2");
    }

    #[test]
    fn only_known_media_types_are_accepted() {
        assert!(ALLOWED_UPLOAD_EXT.contains(&"png"));
        for dangerous in ["html", "svg", "php", "js", "bin"] {
            assert!(
                !ALLOWED_UPLOAD_EXT.contains(&dangerous),
                "{dangerous} must not be uploadable"
            );
        }
    }
}
