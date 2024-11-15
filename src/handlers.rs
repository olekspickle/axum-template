use askama::Template;
use axum::{
    http::{StatusCode, Uri},
    response::{Html, IntoResponse, Response},
};
use tracing::{error, info};

pub async fn index() -> impl IntoResponse {
    info!("GET `/`");
    let template = templates::MainTemplate {
        title: "Axum server".to_string(),
    };
    HtmlTemplate(template)
}

pub async fn first() -> impl IntoResponse {
    info!("GET `/first`");
    let template = templates::FirstTemplate {
        title: "First".to_owned(),
    };
    HtmlTemplate(template)
}
pub async fn second() -> impl IntoResponse {
    info!("GET `/second`");
    let template = templates::FirstTemplate {
        title: "Second".to_owned(),
    };
    HtmlTemplate(template)
}
pub async fn third() -> impl IntoResponse {
    info!("GET `/third`");
    let template = templates::FirstTemplate {
        title: "Third".to_owned(),
    };
    HtmlTemplate(template)
}

pub async fn handle_404(uri: Uri) -> impl IntoResponse {
    error!("404 `/{uri}`");
    let template = templates::NotFoundTemplate {
        title: "Oops!".to_owned(),
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
    #[template(path = "first.html")]
    pub struct FirstTemplate {
        pub title: String,
    }

    #[derive(Template)]
    #[template(path = "second.html")]
    pub struct SecondTemplate {
        pub title: String,
    }

    #[derive(Template)]
    #[template(path = "third.html")]
    pub struct ThirdTemplate {
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
