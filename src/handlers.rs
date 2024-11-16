use crate::{db, form_zip, form_zip::ZIP};
use askama::Template;
use axum::{
    extract::{Path, Query},
    http::{StatusCode, Uri},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use hyper::{header, HeaderMap};
use serde::Deserialize;
use tracing::{error, trace, warn};

pub async fn home() -> impl IntoResponse {
    let template = templates::Home {
        title: "Home".to_owned(),
    };
    HtmlTemplate(template)
}

#[derive(Deserialize)]
pub struct Hello {
    name: Option<String>,
}

pub async fn hello(Query(hello): Query<Hello>) -> impl IntoResponse {
    let name = hello.name.clone().map_or("stranger".to_string(), |l| l);

    let html = templates::Hello {
        name,
        title: "Hello".into(),
    };

    HtmlTemplate(html)
}

pub async fn posts() -> impl IntoResponse {
    let posts = db::get_all_posts().await.expect("getting all posts failed");
    trace!("fetched posts: {}", posts.len());

    let html = templates::Posts {
        title: "Posts".into(),
        posts,
    };

    HtmlTemplate(html)
}

pub async fn add_post(Form(post): Form<db::NewPost>) -> impl IntoResponse {
    trace!(?post, "Adding new post");
    db::add_post(post).await.expect("failed to add post");

    Redirect::permanent("/posts").into_response()
}

pub async fn update_post(Form(post): Form<db::NewPost>, Path(id): Path<u32>) -> impl IntoResponse {
    trace!(%id, ?post, "Update");
    db::update_post(id, post).await.expect("failed to add post");

    Redirect::permanent("/posts").into_response()
}

pub async fn delete_post(Path(id): Path<u32>) -> impl IntoResponse {
    trace!(%id, "Delete");
    db::delete_post(id).await.expect("failed to add post");

    Redirect::permanent("/posts").into_response()
}
/// Just a test handle that will fail in docker container
/// to illustrate how axum fails and how to deal with it
pub async fn fetch_zip() -> impl IntoResponse {
    let zip_res = form_zip::create_zip();
    let Ok(body) = zip_res else {
        warn!("Erorr forming zip file:{zip_res:?}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/zip".parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{ZIP}\"").parse().unwrap(),
    );

    (headers, body).into_response()
}

pub async fn handle_404(uri: Uri) -> impl IntoResponse {
    error!("404 `{uri}`");
    let template = templates::NotFoundTemplate {
        title: "404".to_owned(),
        uri: uri.to_string(),
    };
    HtmlTemplate(template)
}

/// Basically all templates handling
pub mod templates {
    use super::*;

    #[derive(Template)]
    #[template(path = "home.html")]
    pub struct Home {
        pub title: String,
    }

    #[derive(Template)]
    #[template(path = "hello.html")]
    pub struct Hello {
        pub title: String,
        pub name: String,
    }

    #[derive(Template)]
    #[template(path = "posts.html")]
    pub struct Posts {
        pub title: String,
        pub posts: Vec<db::Post>,
    }

    #[derive(Template)]
    #[template(path = "404.html")]
    pub struct NotFoundTemplate {
        pub title: String,
        pub uri: String,
    }
}

struct HtmlTemplate<T>(T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render the template. Error: {}", err),
            )
                .into_response(),
        }
    }
}
