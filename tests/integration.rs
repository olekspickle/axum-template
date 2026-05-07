//! Integration tests for auth flow

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use axum_template::app_router;
use axum_template::config::Config;
use axum_template::db::{self, Db};
use axum_template::middleware::TokenManager;
use axum_template::state::AppState;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Helper to create a test app with in-memory DB
async fn setup_test_app() -> (Router<()>, AppState) {
    let config = Arc::new(Config::load("config.toml").expect("Failed to load config"));

    let db = db::create_db(&config).await.expect("Failed to create db");
    db.init().await.expect("Failed to init db");
    let db = Arc::<dyn Db>::from(db);

    let token_manager = Arc::new(TokenManager::new(
        config.auth.token_ttl,
        config.admin_credentials(),
        Some(db.clone()),
    ));

    let rate_limiter: Arc<RwLock<HashMap<String, (usize, Instant)>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let state = AppState {
        db: db.clone(),
        config: config.clone(),
        token_manager: token_manager.clone(),
        required_role: axum_template::middleware::Role::User,
        rate_limiter: rate_limiter.clone(),
        https: false,
    };

    let app = app_router(state.clone());
    (app, state)
}

/// Helper to make HTTP requests
async fn make_request(
    app: &mut Router<()>,
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

    // Use the router directly as a service
    use tower::Service;
    let response = app.call(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body();
    let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    (status, body_str, headers)
}

/// Login helper - returns token if successful
async fn login(app: &mut Router<()>, username: &str, password: &str) -> Option<String> {
    let (status, body, _headers) = make_request(
        app,
        "POST",
        "/login",
        vec![("Content-Type", "application/x-www-form-urlencoded")],
        Some(format!("username={}&password={}", username, password)),
    )
    .await;

    if status == StatusCode::OK
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
    {
        return json
            .get("token")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string());
    }
    None
}

#[tokio::test]
async fn test_login_with_valid_admin_credentials() {
    let (mut app, _state) = setup_test_app().await;

    let (status, body, _headers) = make_request(
        &mut app,
        "POST",
        "/login",
        vec![("Content-Type", "application/x-www-form-urlencoded")],
        Some("username=admin&password=admin".to_string()),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Login should succeed with valid credentials"
    );

    let json: serde_json::Value =
        serde_json::from_str(&body).expect("Response should be valid JSON");
    assert!(
        json.get("token").is_some(),
        "Response should contain a token"
    );
}

#[tokio::test]
async fn test_login_with_invalid_credentials() {
    let (mut app, _state) = setup_test_app().await;

    let (status, _body, _headers) = make_request(
        &mut app,
        "POST",
        "/login",
        vec![("Content-Type", "application/x-www-form-urlencoded")],
        Some("username=admin&password=wrong".to_string()),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Login should fail with invalid credentials"
    );
}

#[tokio::test]
async fn test_admin_route_without_token_returns_401() {
    let (mut app, _state) = setup_test_app().await;

    let (status, _body, _headers) = make_request(&mut app, "GET", "/admin", vec![], None).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Admin route should require authentication"
    );
}

#[tokio::test]
async fn test_admin_route_with_valid_token_returns_200() {
    let (mut app, _state) = setup_test_app().await;

    // First login to get token
    let token = login(&mut app, "admin", "admin")
        .await
        .expect("Login should succeed");

    // Access admin route with token
    let (status, _body, _headers) = make_request(
        &mut app,
        "GET",
        "/admin",
        vec![("Authorization", &token)],
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Admin route should be accessible with valid token"
    );
}

#[tokio::test]
async fn test_admin_route_with_x_bearer_token() {
    let (mut app, _state) = setup_test_app().await;

    // First login to get token
    let token = login(&mut app, "admin", "admin")
        .await
        .expect("Login should succeed");

    // Access admin route with X-Bearer-Token header
    let (status, _body, _headers) = make_request(
        &mut app,
        "GET",
        "/admin",
        vec![("X-Bearer-Token", &token)],
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Admin route should be accessible with X-Bearer-Token header"
    );
}

#[tokio::test]
async fn test_admin_route_with_invalid_token_returns_401() {
    let (mut app, _state) = setup_test_app().await;

    let (status, _body, _headers) = make_request(
        &mut app,
        "GET",
        "/admin",
        vec![("Authorization", "invalid-token")],
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Admin route should reject invalid token"
    );
}

#[tokio::test]
async fn test_logout_invalidates_token() {
    let (mut app, _state) = setup_test_app().await;

    // First login to get token
    let token = login(&mut app, "admin", "admin")
        .await
        .expect("Login should succeed");

    // Verify token works
    let (status_before, _body, _headers) = make_request(
        &mut app,
        "GET",
        "/admin",
        vec![("Authorization", &token)],
        None,
    )
    .await;
    assert_eq!(
        status_before,
        StatusCode::OK,
        "Token should work before logout"
    );

    // Logout (pass token in Authorization header)
    let _ = make_request(
        &mut app,
        "POST",
        "/admin/logout",
        vec![
            ("Authorization", &token),
            ("Content-Type", "application/json"),
        ],
        Some(format!("{{\"token\": \"{}\"}}", token)),
    )
    .await;

    // Verify token no longer works
    let (status_after, _body, _headers) = make_request(
        &mut app,
        "GET",
        "/admin",
        vec![("Authorization", &token)],
        None,
    )
    .await;
    assert_eq!(
        status_after,
        StatusCode::UNAUTHORIZED,
        "Token should be invalid after logout"
    );
}

#[tokio::test]
async fn test_cookie_based_auth() {
    let (mut app, _state) = setup_test_app().await;

    // Login and capture cookie
    let (status, _body, headers) = make_request(
        &mut app,
        "POST",
        "/login",
        vec![("Content-Type", "application/x-www-form-urlencoded")],
        Some("username=admin&password=admin".to_string()),
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    // Extract cookie from Set-Cookie header
    let cookie = headers
        .get("set-cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(';').next())
        .expect("Should have Set-Cookie header")
        .to_string();

    // Access admin route with cookie
    let (status, _body, _headers) =
        make_request(&mut app, "GET", "/admin", vec![("Cookie", &cookie)], None).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Admin route should be accessible with cookie"
    );
}

#[tokio::test]
async fn test_rate_limiting() {
    let (mut app, _state) = setup_test_app().await;

    // Make 5 failed attempts (should all be 401)
    for i in 1..=5 {
        let (status, _body, _headers) = make_request(
            &mut app,
            "POST",
            "/login",
            vec![("Content-Type", "application/x-www-form-urlencoded")],
            Some("username=admin&password=wrong".to_string()),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "Attempt {} should return 401",
            i
        );
    }

    // 6th attempt should be rate limited
    let (status, _body, _headers) = make_request(
        &mut app,
        "POST",
        "/login",
        vec![("Content-Type", "application/x-www-form-urlencoded")],
        Some("username=admin&password=wrong".to_string()),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "6th attempt should be rate limited"
    );
}

#[tokio::test]
async fn test_public_routes_accessible_without_auth() {
    let (mut app, _state) = setup_test_app().await;

    // Test public routes
    let public_routes = vec!["/", "/blog", "/projects", "/about", "/contact"];

    for route in public_routes {
        let (status, _body, _headers) = make_request(&mut app, "GET", route, vec![], None).await;
        // Should NOT be 401 (might be 200 or 404 depending on content, but not 401)
        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "Route {} should be publicly accessible",
            route
        );
    }
}

#[tokio::test]
async fn test_api_routes_require_auth() {
    let (mut app, _state) = setup_test_app().await;

    // Test API routes without token
    let (status, _body, _headers) =
        make_request(&mut app, "GET", "/api/v1/posts", vec![], None).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "API routes should require authentication"
    );
}
