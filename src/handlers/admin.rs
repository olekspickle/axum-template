use std::path::Path as StdPath;

use askama::Template;
use axum::{
    Form, Router,
    extract::{DefaultBodyLimit, Path, State, multipart::Multipart},
    http::StatusCode,
    middleware::from_fn_with_state,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tower_http::limit::RequestBodyLimitLayer;

use crate::{
    db::{NewTeamMember, Post, Project, TeamMember},
    middleware,
    state::AppState,
};

pub async fn login_page() -> impl IntoResponse {
    let template = admin_templates::Login {
        title: "Login".to_string(),
    };
    HtmlTemplate(template)
}

pub fn router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route("/", get(admin_dashboard))
        .route("/projects", get(admin_projects_list))
        .route("/projects/new", get(admin_new_project))
        .route("/projects/{slug}", get(admin_edit_project))
        .route("/posts", get(admin_posts_list))
        .route("/posts/new", get(admin_new_post))
        .route("/posts/{slug}", get(admin_edit_post))
        .route("/upload", post(upload_media))
        .route("/team", get(admin_team_list))
        .route("/team", post(admin_create_team_member))
        .route("/team/{id}", delete(admin_delete_team_member))
        .route("/logout", post(admin_logout))
        .route("/forgot-password", get(forgot_password_page))
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", get(reset_password_page))
        .route("/reset-password", post(reset_password))
        .layer(from_fn_with_state(state, middleware::require_role))
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(250 * 1024 * 1024)) // 250Mb per file limit
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
            axum::Json(serde_json::json!({ "token": token })),
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
            let role = match member.role.to_lowercase().as_str() {
                "admin" => middleware::Role::Admin,
                "editor" => middleware::Role::Editor,
                _ => middleware::Role::User,
            };
            let role_str = match role {
                middleware::Role::Admin => "Admin",
                middleware::Role::Editor => "Editor",
                middleware::Role::User => "User",
            };
            tracing::info!(username = %form.username, %role_str, "login successful");
            let token = state
                .token_manager
                .generate_user_token(member.name, role, long)
                .await;
            let mut response = (
                StatusCode::OK,
                axum::Json(serde_json::json!({ "token": token })),
            )
                .into_response();
            set_auth_cookie(&mut response, &token, &state, long);
            return response;
        }
    }

    tracing::warn!(username = %form.username, "login failed: invalid credentials");
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": "Invalid credentials" })),
    )
        .into_response()
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
    Redirect::to("/admin/team").into_response()
}

pub async fn admin_logout(
    State(state): State<AppState>,
    axum::extract::Json(payload): axum::extract::Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Some(token) = payload.get("token").and_then(|t| t.as_str()) {
        state.token_manager.invalidate(token).await;
    }
    // Clear the cookie
    let cookie = if state.https {
        "token=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/; Secure"
    } else {
        "token=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/"
    };
    let mut response = Redirect::to("/admin/login").into_response();
    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, cookie.parse().unwrap());
    response
}

pub async fn upload_media(
    State(_state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut slug = String::new();
    let mut file_count: u32 = 0;
    let mut upload_count: u32 = 0;

    let hash_map = build_hash_map();

    while let Some(field) = multipart.next_field().await.expect("invalid multipart") {
        let name = field.name().unwrap_or_default().to_string();

        if name == "slug" {
            slug = field.text().await.unwrap_or_default();
        } else if name == "file_count" {
            if let Ok(text) = field.text().await
                && let Ok(count) = text.parse()
            {
                file_count = count;
            }
        } else if name == "file" {
            let Some(filename) = field.file_name() else {
                continue;
            };

            let ext = StdPath::new(filename)
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_lowercase())
                .unwrap_or_else(|| "bin".to_string());

            let Ok(data) = field.bytes().await else {
                continue;
            };

            let hash = hex::encode(Sha256::digest(&data));

            if let Some(existing_path) = hash_map.get(&hash) {
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

            let mut n = file_count + upload_count;
            let mut final_path;
            loop {
                final_path = format!("static/media/{}/{}-{}.{}", format_dir(&ext), slug, n, ext);
                if !std::path::Path::new(&final_path).exists() {
                    break;
                }
                n += 1;
            }

            let _ = std::fs::write(&final_path, &data)
                .map(|_| {
                    tracing::info!(path = %final_path, hash = %hash, "uploaded media");
                    upload_count += 1;
                })
                .inspect_err(|e| tracing::error!(error = %e, "failed to write file"));
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

fn build_hash_map() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let media_dir = std::path::Path::new("static/media");

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
    let is_team = state
        .db
        .get_team_member(&form.username)
        .await
        .ok()
        .flatten()
        .is_some();

    if is_admin || is_team {
        let reset_token = state
            .token_manager
            .generate_reset_token(&form.username)
            .await;
        tracing::info!(username = %form.username, token = %reset_token, "password reset requested");
        // In production: send email with reset link
        // For now, return token in response (dev only)
        return (
            StatusCode::OK,
            axum::Json(serde_json::json!({
                "message": "Password reset requested",
                "reset_token": reset_token // Remove in production
            })),
        )
            .into_response();
    }

    // Always return success to prevent username enumeration
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({ "message": "If account exists, reset instructions sent" })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct ResetPasswordForm {
    token: String,
    new_password: String,
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

pub async fn reset_password(
    State(state): State<AppState>,
    Form(form): Form<ResetPasswordForm>,
) -> impl IntoResponse {
    if let Some(username) = state.token_manager.consume_reset_token(&form.token).await {
        use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
        let salt = SaltString::generate(&mut rand::thread_rng());
        let password_hash = Argon2::default()
            .hash_password(form.new_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        // Update password in DB or admin credentials
        if state.config.auth.admin_username == username {
            // For admin, update in config (runtime only, not persisted)
            tracing::warn!(username = %username, "admin password reset (runtime only, not persisted)");
        } else if state.db.get_team_member(&username).await.is_ok() {
            state
                .db
                .update_team_member_password(&username, &password_hash)
                .await
                .expect("Failed to update password");
        }

        tracing::info!(username = %username, "password reset successful");
        return (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "message": "Password reset successful" })),
        )
            .into_response();
    }

    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({ "error": "Invalid or expired reset token" })),
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
