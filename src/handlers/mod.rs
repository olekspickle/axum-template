use askama::Template;
use axum::{
    extract::{Path, State},
    http::{StatusCode, Uri},
    response::{Html, IntoResponse, Redirect, Response},
};
use pulldown_cmark::{Options, Parser, html};

use crate::config::SiteParams;
use crate::state::AppState;

use crate::db::Post;
use axum::extract::Query;
use axum::http::HeaderMap;
use serde::Deserialize;

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
        site: state.config.site.clone(),
    };
    HtmlTemplate(template)
}

pub async fn projects(State(state): State<AppState>) -> impl IntoResponse {
    let projects = state.db.get_projects().await.unwrap_or_default();
    let template = templates::Projects {
        title: "Projects".to_string(),
        projects,
        site: state.config.site.clone(),
    };
    HtmlTemplate(template)
}

pub async fn project_detail(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let project = state.db.get_project_by_slug(&slug).await.ok().flatten();
    let description_html = project.as_ref().map(|p| render_markdown(&p.description));

    if let Some(project) = project {
        let template = templates::ProjectDetail {
            title: project.title.clone(),
            project,
            description_html: description_html.unwrap_or_default(),
            site: state.config.site.clone(),
        };
        return HtmlTemplate(template).into_response();
    }

    Redirect::to("/404").into_response()
}

const BLOG_POSTS_PER_PAGE: usize = 6;

#[derive(Debug, Default, Deserialize)]
pub struct BlogQuery {
    tag: Option<String>,
    page: Option<usize>,
}

fn collect_all_tags(posts: &[Post]) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    for post in posts {
        for tag in &post.tags {
            let lower = tag.to_lowercase();
            if !tags.iter().any(|t| t.eq_ignore_ascii_case(&lower)) {
                tags.push(tag.clone());
            }
        }
    }
    tags.sort_by_key(|t| t.to_lowercase());
    tags
}

fn filter_posts_by_tag(posts: Vec<Post>, tag: &str) -> Vec<Post> {
    posts
        .into_iter()
        .filter(|p| p.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)))
        .collect()
}

pub async fn blog(
    State(state): State<AppState>,
    Query(query): Query<BlogQuery>,
    headers: HeaderMap,
) -> Response {
    let is_hx = headers.get("hx-request").is_some();

    let all_posts = state.db.get_published_posts().await.unwrap_or_default();
    let all_tags = collect_all_tags(&all_posts);

    let posts = match &query.tag {
        Some(tag) => filter_posts_by_tag(all_posts, tag),
        None => all_posts,
    };
    let total = posts.len();
    let page = query.page.unwrap_or(1).max(1);
    let start = (page - 1).saturating_mul(BLOG_POSTS_PER_PAGE);
    let has_more = start + BLOG_POSTS_PER_PAGE < total;
    let page_posts: Vec<Post> = posts
        .into_iter()
        .skip(start)
        .take(BLOG_POSTS_PER_PAGE)
        .collect();

    if is_hx {
        if query.page.is_some() {
            return HtmlTemplate(templates::BlogMore {
                posts: page_posts,
                has_more,
                next_page: page + 1,
            })
            .into_response();
        }
        return HtmlTemplate(templates::BlogContent {
            title: "Blog".to_string(),
            posts: page_posts,
            has_more,
            next_page: page + 1,
            active_tag: query.tag,
            all_tags,
        })
        .into_response();
    }

    HtmlTemplate(templates::Blog {
        title: "Blog".to_string(),
        posts: page_posts,
        has_more,
        next_page: page + 1,
        active_tag: query.tag,
        all_tags,
        site: state.config.site.clone(),
    })
    .into_response()
}

pub async fn post_detail(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    // Published only - drafts stay behind /admin even when the slug is known.
    let post = state
        .db
        .get_published_post_by_slug(&slug)
        .await
        .ok()
        .flatten();
    let content_html = post.as_ref().map(|p| render_markdown(&p.content));

    if let Some(post) = post {
        let template = templates::PostDetail {
            title: post.title.clone(),
            post,
            content_html: content_html.unwrap_or_default(),
            site: state.config.site.clone(),
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
        site: state.config.site.clone(),
    };
    HtmlTemplate(template)
}

pub async fn contact(State(state): State<AppState>) -> impl IntoResponse {
    let template = templates::Contact {
        title: "Contact".to_string(),
        site: state.config.site.clone(),
    };
    HtmlTemplate(template)
}

/// Schemes a rendered link or image may use. Everything else (`javascript:`,
/// `data:`, `vbscript:`, ...) is dropped so post content can't run script.
const SAFE_URL_SCHEMES: [&str; 5] = ["http", "https", "mailto", "tel", "video"];

fn is_safe_url(url: &str) -> bool {
    let url = url.trim();
    match url.split_once(':') {
        // Relative path, anchor or query - no scheme to vet.
        None => true,
        // A colon after a path separator isn't a scheme (e.g. `/a/b:c`).
        Some((scheme, _)) if scheme.contains(['/', '?', '#']) => true,
        Some((scheme, _)) => SAFE_URL_SCHEMES.contains(&scheme.to_ascii_lowercase().as_str()),
    }
}

/// Post content is author-supplied, and pulldown-cmark passes raw HTML through
/// verbatim, so drop HTML events and unsafe URLs before the result is rendered
/// with `| safe`.
pub(crate) fn render_markdown(content: &str) -> String {
    use pulldown_cmark::{CowStr, Event, Tag, TagEnd};

    let content = content.replace("](Video:", "](video:");

    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_FOOTNOTES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);

    let mut dropped_link_depth = 0usize;
    let parser = Parser::new_ext(&content, options).filter_map(|event| match event {
        Event::Html(_) | Event::InlineHtml(_) => None,
        Event::Start(Tag::Link {
            link_type,
            dest_url,
            title,
            id,
        }) => {
            if is_safe_url(&dest_url) {
                Some(Event::Start(Tag::Link {
                    link_type,
                    dest_url,
                    title,
                    id,
                }))
            } else {
                // Keep the link text, lose the destination.
                dropped_link_depth += 1;
                None
            }
        }
        Event::End(TagEnd::Link) if dropped_link_depth > 0 => {
            dropped_link_depth -= 1;
            None
        }
        Event::Start(Tag::Image {
            link_type,
            dest_url,
            title,
            id,
        }) => {
            let dest_url = if is_safe_url(&dest_url) {
                dest_url
            } else {
                CowStr::Borrowed("")
            };
            Some(Event::Start(Tag::Image {
                link_type,
                dest_url,
                title,
                id,
            }))
        }
        event => Some(event),
    });

    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);
    html_output
}

pub async fn to_404(State(state): State<AppState>, uri: Uri) -> impl IntoResponse {
    let template = templates::NotFoundTemplate {
        title: "[404]".to_string(),
        uri: uri.to_string(),
        site: state.config.site.clone(),
    };
    (axum::http::StatusCode::NOT_FOUND, HtmlTemplate(template))
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
        pub site: SiteParams,
    }

    #[derive(Template)]
    #[template(path = "projects.html")]
    pub struct Projects {
        pub title: String,
        pub projects: Vec<Project>,
        pub site: SiteParams,
    }

    #[derive(Template)]
    #[template(path = "project-detail.html")]
    pub struct ProjectDetail {
        pub title: String,
        pub project: Project,
        pub description_html: String,
        pub site: SiteParams,
    }

    #[derive(Template)]
    #[template(path = "blog.html")]
    pub struct Blog {
        pub title: String,
        pub posts: Vec<Post>,
        pub has_more: bool,
        pub next_page: usize,
        pub active_tag: Option<String>,
        pub all_tags: Vec<String>,
        pub site: SiteParams,
    }

    #[derive(Template)]
    #[template(path = "blog/_content.html")]
    pub struct BlogContent {
        pub title: String,
        pub posts: Vec<Post>,
        pub has_more: bool,
        pub next_page: usize,
        pub active_tag: Option<String>,
        pub all_tags: Vec<String>,
    }

    #[derive(Template)]
    #[template(path = "blog/_more.html")]
    pub struct BlogMore {
        pub posts: Vec<Post>,
        pub has_more: bool,
        pub next_page: usize,
    }

    #[derive(Template)]
    #[template(path = "post-detail.html")]
    pub struct PostDetail {
        pub title: String,
        pub post: Post,
        pub content_html: String,
        pub site: SiteParams,
    }

    #[derive(Template)]
    #[template(path = "about.html")]
    pub struct About {
        pub title: String,
        pub site_name: String,
        pub tagline: String,
        pub team_members: Vec<TeamMember>,
        pub site: SiteParams,
    }

    #[derive(Template)]
    #[template(path = "contact.html")]
    pub struct Contact {
        pub title: String,
        pub site: SiteParams,
    }

    #[derive(Template)]
    #[template(path = "404.html")]
    pub struct NotFoundTemplate {
        pub title: String,
        pub uri: String,
        pub site: SiteParams,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_html_is_stripped_from_markdown() {
        let rendered = render_markdown("<script>alert(1)</script>\n\nhello");
        assert!(!rendered.contains("<script"), "{rendered}");
        assert!(rendered.contains("hello"));

        let rendered = render_markdown("text <img src=x onerror=alert(1)> more");
        assert!(!rendered.contains("onerror"), "{rendered}");
    }

    #[test]
    fn script_urls_are_dropped_from_links_and_images() {
        let rendered = render_markdown("[click](javascript:alert(1))");
        assert!(!rendered.contains("javascript:"), "{rendered}");
        assert!(rendered.contains("click"), "link text is kept");

        let rendered = render_markdown("![x](data:text/html;base64,PHN2Zz4=)");
        assert!(!rendered.contains("data:text/html"), "{rendered}");
    }

    #[test]
    fn ordinary_links_and_formatting_survive() {
        let rendered = render_markdown("[site](https://example.com) and *emphasis*");
        assert!(
            rendered.contains("href=\"https://example.com\""),
            "{rendered}"
        );
        assert!(rendered.contains("<em>emphasis</em>"), "{rendered}");

        let rendered = render_markdown("[rel](/blog/post) [mail](mailto:a@b.c)");
        assert!(rendered.contains("href=\"/blog/post\""), "{rendered}");
        assert!(rendered.contains("href=\"mailto:a@b.c\""), "{rendered}");
    }
}
