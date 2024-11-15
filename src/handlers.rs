use crate::form_zip::ZIP;
use askama::Template;
use axum::{
    http::{StatusCode, Uri},
    response::{Html, IntoResponse, Response},
};
use hyper::{header, HeaderMap};
use tracing::{error, warn};

use crate::form_zip;

pub async fn index() -> impl IntoResponse {
    let template = templates::MainTemplate {
        title: "Home".to_string(),
    };
    HtmlTemplate(template)
}

/// some default pages
pub async fn main() -> impl IntoResponse {
    let template = templates::PageTemplate {
        title: "Main".to_owned(),
    };
    HtmlTemplate(template)
}
pub async fn fetch() -> impl IntoResponse {
    let template = templates::PageTemplate {
        title: "Fetch".to_owned(),
    };
    HtmlTemplate(template)
}

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
    #[template(path = "main.html")]
    pub struct MainTemplate {
        pub title: String,
    }

    #[derive(Template)]
    #[template(path = "page.html")]
    pub struct PageTemplate {
        pub title: String,
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
