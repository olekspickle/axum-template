//! # Middleware
//!
//! You can do whatever you want with incoming requests before they reach handles
//!
use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{Response, StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::IntoResponse,
};
use hyper::{HeaderMap, header::HeaderValue};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::AppState;

/// Custom logging middleware
pub(crate) async fn custom_log(req: Request, next: Next) -> Result<Response<Body>, StatusCode> {
    let (parts, body) = req.into_parts();

    if !parts.uri.to_string().contains("static") {
        //trace!("{}", parts.uri);
    }

    let req = Request::from_parts(parts, body);
    Ok(next.run(req).await)
}

pub async fn auth(State(state): State<AppState>, req: Request, next: Next) -> impl IntoResponse {
    let static_token = std::env::var("MANAGER_AUTH_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());

    let auth = state.token_manager.clone();
    let tokens = auth.tokens.read().await;
    if static_token.is_none() && tokens.is_empty() {
        return next.run(req).await.into_response();
    }

    let (parts, body) = req.into_parts();

    let auth_header = parts.headers.get(AUTHORIZATION);
    if auth.check_header(auth_header).await {
        let req = axum::extract::Request::from_parts(parts, body);
        return next.run(req).await.into_response();
    }

    let bearer_token = parts.headers.get("X-Bearer-Token");
    if auth.check_header(bearer_token).await {
        let req = axum::extract::Request::from_parts(parts, body);
        return next.run(req).await.into_response();
    }

    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}

/// Simple token manager
pub struct TokenManager {
    tokens: RwLock<HashMap<String, Instant>>,
    ttl: Duration,
}

impl TokenManager {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub async fn generate(&self) -> String {
        let token = Uuid::new_v4().to_string();
        let expiry = Instant::now() + self.ttl;
        self.tokens.write().await.insert(token.clone(), expiry);
        token
    }

    pub async fn validate(&self, token: &str) -> bool {
        let mut tokens = self.tokens.write().await;
        if let Some(expiry) = tokens.get(token)
            && Instant::now() < *expiry
        {
            return true;
        }
        tokens.remove(token);
        false
    }

    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut tokens = self.tokens.write().await;
        tokens.retain(|_, expiry| now < *expiry);
    }

    pub async fn check_header(&self, token: Option<&HeaderValue>) -> bool {
        if let Some(token_value) = token
            && let Ok(token) = token_value.to_str()
        {
            return self.validate(token).await;
        }
        false
    }
}

// Another primitive auth middleware
pub async fn auth_basic(req: Request<Body>, next: Next) -> Result<Response<Body>, StatusCode> {
    let (parts, body) = req.into_parts();

    if parts.uri == "/secret" && check_bearer(&parts.headers).is_err() {
        tracing::warn!("[secret] auth header is not present");
        return Err(StatusCode::BAD_REQUEST);
    }

    let req = Request::from_parts(parts, body);
    Ok(next.run(req).await)
}

fn check_bearer(header_map: &HeaderMap) -> Result<(), StatusCode> {
    const TOKEN: &str = "super-secret";

    if let Some(token) = header_map.get(AUTHORIZATION)
        && !token.is_empty()
        && token == TOKEN
    {
        tracing::debug!("Authorized!");
        return Ok(());
    }

    Err(StatusCode::FORBIDDEN)
}
