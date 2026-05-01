//! Test utilities for integration tests
//! This module provides helpers to create test servers and make assertions

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    middleware::{from_fn, from_fn_with_state},
};
use http_body_util::BodyExt;
use tower::ServiceExt;
use tokio::sync::RwLock;

use crate::{
    config::Config,
    db::{self, Db},
    middleware::{self, TokenManager},
    state::AppState,
};

use std::collections::HashMap;

/// Create a test app instance for integration testing
pub async fn create_test_app() -> (Router<AppState>, AppState) {
    // Load test config
    let config = Arc::new(Config::load("config.toml").expect("Failed to load config"));

    // Use in-memory SQLite for testing
    let db = db::create_db(&config).await.expect("Failed to create db");
    db.init().await.expect("Failed to init db");

    let token_manager = Arc::new(TokenManager::new(
        config.auth.token_ttl,
        config.admin_credentials(),
    ));

    let rate_limiter: Arc<RwLock<HashMap<String, (usize, Instant)>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let db = Arc::<dyn Db>::from(db);
    let state = AppState {
        db: db.clone(),
        config: config.clone(),
        token_manager: token_manager.clone(),
        required_role: middleware::Role::User,
        rate_limiter: rate_limiter.clone(),
    };

    let app = crate::create_router(state.clone());

    (app, state)
}

/// Helper to make a request to the test app
pub async fn make_request(
    app: &mut Router<AppState>,
    method: &str,
    uri: &str,
    headers: Vec<(&str, &str)>,
    body: Option<String>,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let mut request_builder = Request::builder().method(method).uri(uri);

    for (key, value) in headers {
        request_builder = request_builder.header(key, value);
    }

    let body = body.unwrap_or_default();
    let request = request_builder.body(Body::from(body)).unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body).to_string();

    (status, body_str, headers)
}

/// Login and return the token
pub async fn login(
    app: &mut Router<AppState>,
    username: &str,
    password: &str,
) -> Option<String> {
    let (status, body, _headers) = make_request(
        app,
        "POST",
        "/login",
        vec![("Content-Type", "application/x-www-form-urlencoded")],
        Some(format!("username={}&password={}", username, password)),
    )
    .await;

    if status == StatusCode::OK {
        // Extract token from JSON response
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
            return json.get("token").and_then(|t| t.as_str()).map(|s| s.to_string());
        }
    }
    None
}
