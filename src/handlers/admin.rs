use askama::Template;
use axum::{
    Form, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware::from_fn_with_state,
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{delete, get, patch, post},
};
use serde::Deserialize;

use crate::db::{NewPost, NewProject, NewTeamMember, Post, Project, TeamMember};
use crate::middleware;
use crate::state::AppState;

pub fn router(state: AppState) -> Router<AppState> {
    Router::<AppState>::new()
        .route("/login", post(admin_login))
        .route("/team/login", post(team_login))
        .route("/", get(admin_dashboard))
        .route("/projects", get(admin_projects_list))
        .route("/projects", post(admin_create_project))
        .route("/projects/{id}", get(admin_edit_project))
        .route("/projects/{id}", patch(admin_update_project))
        .route("/projects/{id}", delete(admin_delete_project))
        .route("/posts", get(admin_posts_list))
        .route("/posts", post(admin_create_post))
        .route("/posts/{id}", get(admin_edit_post))
        .route("/posts/{id}", patch(admin_update_post))
        .route("/posts/{id}", delete(admin_delete_post))
        .route("/team", get(admin_team_list))
        .route("/team", post(admin_create_team_member))
        .route("/team/{id}", delete(admin_delete_team_member))
        .route("/logout", post(admin_logout))
        .layer(from_fn_with_state(state.clone(), middleware::require_admin))
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

pub async fn admin_login(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    let token = state
        .token_manager
        .login(&form.username, &form.password)
        .await;

    match token {
        Some(token) => (StatusCode::OK, Json(serde_json::json!({ "token": token }))),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Invalid credentials" })),
        ),
    }
}

pub async fn team_login(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    let member = state.db.get_team_member(&form.username).await;

    match member {
        Ok(Some(member)) => {
            if let Some(hash) = &member.password_hash {
                use argon2::{PasswordHash, PasswordVerifier};
                let parsed_hash = PasswordHash::new(hash);
                if let Ok(parsed) = parsed_hash {
                    if argon2::Argon2::default()
                        .verify_password(form.password.as_bytes(), &parsed)
                        .is_ok()
                    {
                        let token = state.token_manager.generate_user_token(member.name).await;
                        return (StatusCode::OK, Json(serde_json::json!({ "token": token })));
                    }
                }
            }
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "Invalid credentials" })),
            )
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Invalid credentials" })),
        ),
    }
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

pub async fn admin_create_project(
    State(state): State<AppState>,
    Form(form): Form<NewProject>,
) -> impl IntoResponse {
    match state.db.create_project(form).await {
        Ok(_) => Redirect::to("/admin/projects").into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create project: {}", e),
        )
            .into_response(),
    }
}

pub async fn admin_edit_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let project = state.db.get_project(&id).await.ok().flatten();
    let template = admin_templates::AdminProjectEdit {
        title: "Edit Project".to_string(),
        project,
    };
    HtmlTemplate(template)
}

pub async fn admin_update_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Form(form): Form<NewProject>,
) -> impl IntoResponse {
    match state.db.update_project(&id, form).await {
        Ok(_) => Redirect::to("/admin/projects").into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update project: {}", e),
        )
            .into_response(),
    }
}

pub async fn admin_delete_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    state.db.delete_project(&id).await.ok();
    Redirect::to("/admin/projects").into_response()
}

pub async fn admin_posts_list(State(state): State<AppState>) -> impl IntoResponse {
    let posts = state.db.get_posts().await.unwrap_or_default();
    let template = admin_templates::AdminPostsList {
        title: "Manage Posts".to_string(),
        posts,
    };
    HtmlTemplate(template)
}

pub async fn admin_create_post(
    State(state): State<AppState>,
    Form(form): Form<NewPost>,
) -> impl IntoResponse {
    match state.db.create_post(form).await {
        Ok(_) => Redirect::to("/admin/posts").into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create post: {}", e),
        )
            .into_response(),
    }
}

pub async fn admin_edit_post(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let post = state.db.get_post(&id).await.ok().flatten();
    let template = admin_templates::AdminPostEdit {
        title: "Edit Post".to_string(),
        post,
    };
    HtmlTemplate(template)
}

pub async fn admin_update_post(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Form(form): Form<NewPost>,
) -> impl IntoResponse {
    match state.db.update_post(&id, form).await {
        Ok(_) => Redirect::to("/admin/posts").into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update post: {}", e),
        )
            .into_response(),
    }
}

pub async fn admin_delete_post(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    state.db.delete_post(&id).await.ok();
    Redirect::to("/admin/posts").into_response()
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
    Redirect::to("/admin/login").into_response()
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
}
