//! # Middleware
//!
//! You can do whatever you want with incoming requests before they reach handles
//!
use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
    middleware::Next,
};
use hyper::HeaderMap;
use tracing::{info, trace, warn};

/// Logging middleware
pub(crate) async fn log(req: Request<Body>, next: Next) -> Result<Response<Body>, StatusCode> {
    let (parts, body) = req.into_parts();

    if !parts.uri.to_string().contains("static") {
        //trace!("{}", parts.uri);
    }

    let req = Request::from_parts(parts, body);
    Ok(next.run(req).await)
}

/// Auth middleware
pub(crate) async fn auth(req: Request<Body>, next: Next) -> Result<Response<Body>, StatusCode> {
    let (parts, body) = req.into_parts();

    if parts.uri == "/secret" && check_bearer(&parts.headers).is_err() {
        warn!("[secret] auth header is not present");
        return Err(StatusCode::BAD_REQUEST);
    }

    let req = Request::from_parts(parts, body);
    Ok(next.run(req).await)
}

fn check_bearer(header_map: &HeaderMap) -> Result<(), StatusCode> {
    const TOKEN: &str = "super-secret";

    if let Some(token) = header_map.get("Authorization") {
        if !token.is_empty() && token == TOKEN {
            trace!("Authorized!");
            return Ok(());
        }
    }

    Err(StatusCode::FORBIDDEN)
}
