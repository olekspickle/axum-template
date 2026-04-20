use askama::Template;
use axum::{
    extract::{Path, State},
    http::{StatusCode, Uri},
    response::{Html, IntoResponse, Redirect, Response},
};
use pulldown_cmark::{Options, Parser, html};

use crate::state::AppState;

pub mod admin;

pub async fn home(State(state): State<AppState>) -> impl IntoResponse {
    let featured_projects = state.db.get_featured_projects().await.unwrap_or_default();
    let recent_posts = state.db.get_published_posts().await.unwrap_or_default();
    let team_members = state.db.get_team_members().await.unwrap_or_default();

    let template = templates::Home {
        title: "Home".to_string(),
        site_name: state.config.site.name.clone(),
        tagline: state.config.site.tagline.clone(),
        featured_projects,
        recent_posts,
        team_members,
    };
    HtmlTemplate(template)
}

pub async fn projects(State(state): State<AppState>) -> impl IntoResponse {
    let projects = state.db.get_projects().await.unwrap_or_default();
    let template = templates::Projects {
        title: "Projects".to_string(),
        projects,
    };
    HtmlTemplate(template)
}

pub async fn project_detail(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let project = state.db.get_project(&slug).await.ok().flatten();

    if let Some(project) = project {
        let template = templates::ProjectDetail {
            title: project.title.clone(),
            project,
        };
        return HtmlTemplate(template).into_response();
    }

    Redirect::to("/404").into_response()
}

pub async fn blog(State(state): State<AppState>) -> impl IntoResponse {
    let posts = state.db.get_published_posts().await.unwrap_or_default();
    let template = templates::Blog {
        title: "Blog".to_string(),
        posts,
    };
    HtmlTemplate(template)
}

pub async fn post_detail(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let post = state.db.get_post(&slug).await.ok().flatten();
    let content_html = post.as_ref().map(|p| render_markdown(&p.content));

    if let Some(post) = post {
        let template = templates::PostDetail {
            title: post.title.clone(),
            post,
            content_html: content_html.unwrap_or_default(),
        };
        return HtmlTemplate(template).into_response();
    }

    Redirect::to("/404").into_response()
}

pub async fn about(State(state): State<AppState>) -> impl IntoResponse {
    let team_members = state.db.get_team_members().await.unwrap_or_default();
    let template = templates::About {
        title: "About".to_string(),
        site_name: state.config.site.name.clone(),
        tagline: state.config.site.tagline.clone(),
        team_members,
    };
    HtmlTemplate(template)
}

pub async fn contact(State(_state): State<AppState>) -> impl IntoResponse {
    let template = templates::Contact {
        title: "Contact".to_string(),
    };
    HtmlTemplate(template)
}

fn render_markdown(content: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_FOOTNOTES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);

    let parser = Parser::new_ext(content, options);
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);
    html_output
}

pub async fn to_404(uri: Uri) -> impl IntoResponse {
    let template = templates::NotFoundTemplate {
        title: "[404]".to_string(),
        uri: uri.to_string(),
        site_name: "Our Company".to_string(),
        tagline: "We build amazing things".to_string(),
        featured_projects: vec![],
    };
    HtmlTemplate(template)
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

pub mod templates {
    use super::*;
    use crate::db::{Post, Project, TeamMember};

    #[derive(Template)]
    #[template(path = "home.html")]
    pub struct Home {
        pub title: String,
        pub site_name: String,
        pub tagline: String,
        pub featured_projects: Vec<Project>,
        pub recent_posts: Vec<Post>,
        pub team_members: Vec<TeamMember>,
    }

    #[derive(Template)]
    #[template(path = "projects.html")]
    pub struct Projects {
        pub title: String,
        pub projects: Vec<Project>,
    }

    #[derive(Template)]
    #[template(path = "project-detail.html")]
    pub struct ProjectDetail {
        pub title: String,
        pub project: Project,
    }

    #[derive(Template)]
    #[template(path = "blog.html")]
    pub struct Blog {
        pub title: String,
        pub posts: Vec<Post>,
    }

    #[derive(Template)]
    #[template(path = "post-detail.html")]
    pub struct PostDetail {
        pub title: String,
        pub post: Post,
        pub content_html: String,
    }

    #[derive(Template)]
    #[template(path = "about.html")]
    pub struct About {
        pub title: String,
        pub site_name: String,
        pub tagline: String,
        pub team_members: Vec<TeamMember>,
    }

    #[derive(Template)]
    #[template(path = "contact.html")]
    pub struct Contact {
        pub title: String,
    }

    #[derive(Template)]
    #[template(path = "404.html")]
    pub struct NotFoundTemplate {
        pub title: String,
        pub uri: String,
        pub site_name: String,
        pub tagline: String,
        pub featured_projects: Vec<Project>,
    }
}
