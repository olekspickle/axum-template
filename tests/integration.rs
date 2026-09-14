//! Integration tests for auth, authorization and the public site.
//!
//! These run against the sqlite backend; see `surreal_db.rs` for the other one.
#![cfg(feature = "sqlite")]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use axum_template::app_router;
use axum_template::config::Config;
use axum_template::db::{self, Db, NewPost, NewTeamMember};
use axum_template::middleware::TokenManager;
use axum_template::state::AppState;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Each test gets its own sqlite file so they can run in parallel.
async fn setup_test_app() -> (Router<()>, AppState) {
    let mut config = Config::load("config.toml").expect("Failed to load config");
    config.db.path = std::env::temp_dir()
        .join(format!("axum-template-test-{}.db", uuid::Uuid::new_v4()))
        .to_string_lossy()
        .into_owned();
    let config = Arc::new(config);

    let db = db::create_db(&config).await.expect("Failed to create db");
    db.init().await.expect("Failed to init db");
    let db = Arc::<dyn Db>::from(db);

    let token_manager = Arc::new(TokenManager::new(
        config.auth.token_ttl,
        config.admin_credentials(),
        Some(db.clone()),
    ));

    let state = AppState {
        db: db.clone(),
        config: config.clone(),
        token_manager: token_manager.clone(),
        required_role: axum_template::middleware::Role::User,
        rate_limiter: Arc::new(RwLock::new(HashMap::new())),
        media_index: Arc::new(RwLock::new(None)),
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

/// Login helper - the token is delivered as an HttpOnly cookie, not in the body.
async fn login(app: &mut Router<()>, username: &str, password: &str) -> Option<String> {
    let (status, _body, headers) = make_request(
        app,
        "POST",
        "/login",
        vec![("Content-Type", "application/x-www-form-urlencoded")],
        Some(format!("username={username}&password={password}")),
    )
    .await;

    if status != StatusCode::OK {
        return None;
    }

    headers
        .get("set-cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|cookie| cookie.split(';').next())
        .and_then(|pair| pair.split_once('='))
        .map(|(_, token)| token.to_string())
}

async fn add_team_member(state: &AppState, name: &str, role: &str, password: &str) {
    state
        .db
        .create_team_member(NewTeamMember {
            name: name.into(),
            role: role.into(),
            bio: "bio".into(),
            password: Some(password.into()),
            ..Default::default()
        })
        .await
        .expect("create team member");
}

#[tokio::test]
async fn test_login_with_valid_admin_credentials() {
    let (mut app, _state) = setup_test_app().await;

    let (status, _body, headers) = make_request(
        &mut app,
        "POST",
        "/login",
        vec![("Content-Type", "application/x-www-form-urlencoded")],
        Some("username=admin&password=admin".to_string()),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "Login should succeed");

    let cookie = headers
        .get("set-cookie")
        .and_then(|h| h.to_str().ok())
        .expect("Response should set the auth cookie");
    assert!(cookie.starts_with("token="));
    assert!(cookie.contains("HttpOnly"), "cookie must be HttpOnly");
    assert!(
        cookie.contains("SameSite=Strict"),
        "cookie must be SameSite"
    );
    assert!(
        !headers
            .get("hx-redirect")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default()
            .is_empty(),
        "htmx should be told where to go next"
    );
}

#[tokio::test]
async fn test_login_with_invalid_credentials() {
    let (mut app, _state) = setup_test_app().await;

    let (status, _body, headers) = make_request(
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
    assert!(
        headers.get("set-cookie").is_none(),
        "failed login must not set an auth cookie"
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

    let token = login(&mut app, "admin", "admin")
        .await
        .expect("Login should succeed");

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
async fn test_bearer_prefix_is_accepted() {
    let (mut app, _state) = setup_test_app().await;

    let token = login(&mut app, "admin", "admin")
        .await
        .expect("Login should succeed");

    let (status, _body, _headers) = make_request(
        &mut app,
        "GET",
        "/admin",
        vec![("Authorization", &format!("Bearer {token}"))],
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "`Authorization: Bearer <token>` should authenticate"
    );
}

#[tokio::test]
async fn test_admin_route_with_x_bearer_token() {
    let (mut app, _state) = setup_test_app().await;

    let token = login(&mut app, "admin", "admin")
        .await
        .expect("Login should succeed");

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

    let token = login(&mut app, "admin", "admin")
        .await
        .expect("Login should succeed");

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

    let _ = make_request(
        &mut app,
        "POST",
        "/admin/logout",
        vec![("Authorization", &token)],
        None,
    )
    .await;

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

    let (status, _body, headers) = make_request(
        &mut app,
        "POST",
        "/login",
        vec![("Content-Type", "application/x-www-form-urlencoded")],
        Some("username=admin&password=admin".to_string()),
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    let cookie = headers
        .get("set-cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(';').next())
        .expect("Should have Set-Cookie header")
        .to_string();

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
            "Attempt {i} should return 401"
        );
    }

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
async fn test_rate_limit_ignores_spoofed_client_headers() {
    let (mut app, _state) = setup_test_app().await;

    // A fresh X-Real-IP per request must not buy a fresh rate-limit bucket.
    for i in 1..=5 {
        let ip = format!("10.0.0.{i}");
        let (status, _body, _headers) = make_request(
            &mut app,
            "POST",
            "/login",
            vec![
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("X-Real-IP", &ip),
            ],
            Some("username=admin&password=wrong".to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {i}");
    }

    let (status, _body, _headers) = make_request(
        &mut app,
        "POST",
        "/login",
        vec![
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("X-Real-IP", "10.0.0.99"),
        ],
        Some("username=admin&password=wrong".to_string()),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "spoofing X-Real-IP must not reset the counter when trusted_proxy is off"
    );
}

#[tokio::test]
async fn test_public_routes_accessible_without_auth() {
    let (mut app, _state) = setup_test_app().await;

    let public_routes = vec!["/", "/blog", "/projects", "/about", "/contact"];

    for route in public_routes {
        let (status, _body, _headers) = make_request(&mut app, "GET", route, vec![], None).await;
        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "Route {route} should be publicly accessible"
        );
    }
}

#[tokio::test]
async fn test_security_headers_are_set() {
    let (mut app, _state) = setup_test_app().await;

    let (_status, _body, headers) = make_request(&mut app, "GET", "/", vec![], None).await;

    assert_eq!(
        headers
            .get("x-content-type-options")
            .map(|h| h.to_str().unwrap()),
        Some("nosniff")
    );
    assert_eq!(
        headers.get("x-frame-options").map(|h| h.to_str().unwrap()),
        Some("DENY")
    );
    assert!(
        headers
            .get("content-security-policy")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default()
            .contains("script-src 'self'"),
        "a CSP should be present on rendered pages"
    );
}

#[tokio::test]
async fn test_api_routes_require_auth() {
    let (mut app, _state) = setup_test_app().await;

    let (status, _body, _headers) =
        make_request(&mut app, "GET", "/api/v1/posts", vec![], None).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "API routes should require authentication"
    );
}

#[tokio::test]
async fn test_api_writes_require_more_than_a_plain_user() {
    let (mut app, state) = setup_test_app().await;
    add_team_member(&state, "plain", "Contributor", "correct horse battery").await;

    let token = login(&mut app, "plain", "correct horse battery")
        .await
        .expect("team member login should succeed");

    // Reads are fine for any authenticated caller.
    let (status, _body, _headers) = make_request(
        &mut app,
        "GET",
        "/api/v1/posts",
        vec![("Authorization", &token)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reads are open to any user");

    // Writes are not.
    let (status, _body, _headers) = make_request(
        &mut app,
        "DELETE",
        "/api/v1/posts/whatever",
        vec![("Authorization", &token)],
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a User-role token must not be able to delete posts"
    );
}

#[tokio::test]
async fn test_api_writes_allowed_for_editor() {
    let (mut app, state) = setup_test_app().await;
    add_team_member(&state, "edith", "Editor", "correct horse battery").await;

    let token = login(&mut app, "edith", "correct horse battery")
        .await
        .expect("editor login should succeed");

    let (status, _body, _headers) = make_request(
        &mut app,
        "POST",
        "/api/v1/posts",
        vec![
            ("Authorization", &token),
            ("Content-Type", "application/json"),
        ],
        Some(
            serde_json::json!({
                "title": "t", "slug": "api-post", "content": "c", "excerpt": "e",
                "cover_image": "", "tags": [], "author": "edith", "published": true
            })
            .to_string(),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "an Editor may create posts");
}

#[tokio::test]
async fn test_drafts_are_not_served_publicly() {
    let (mut app, state) = setup_test_app().await;

    state
        .db
        .create_post(NewPost {
            title: "Secret".into(),
            slug: "secret-draft".into(),
            content: "unreleased".into(),
            excerpt: "e".into(),
            cover_image: String::new(),
            tags: vec![],
            author: "admin".into(),
            published: false,
        })
        .await
        .expect("create draft");

    let (status, body, _headers) =
        make_request(&mut app, "GET", "/blog/secret-draft", vec![], None).await;

    assert_ne!(status, StatusCode::OK, "a draft must not render publicly");
    assert!(
        !body.contains("unreleased"),
        "draft content leaked in the response"
    );
}

#[tokio::test]
async fn test_forgot_password_does_not_leak_a_token() {
    let (mut app, state) = setup_test_app().await;
    add_team_member(&state, "dave", "Editor", "correct horse battery").await;

    let (status, known, _headers) = make_request(
        &mut app,
        "POST",
        "/admin/forgot-password",
        vec![("Content-Type", "application/x-www-form-urlencoded")],
        Some("username=dave".to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_status, unknown, _headers) = make_request(
        &mut app,
        "POST",
        "/admin/forgot-password",
        vec![("Content-Type", "application/x-www-form-urlencoded")],
        Some("username=nobody".to_string()),
    )
    .await;

    assert_eq!(
        known, unknown,
        "the response must not reveal whether the account exists"
    );
    assert!(
        !known.to_lowercase().contains("dev:"),
        "a reset token must never be returned to the caller"
    );
}

#[tokio::test]
async fn test_reset_password_rejects_unknown_token() {
    let (mut app, _state) = setup_test_app().await;

    let (status, body, _headers) = make_request(
        &mut app,
        "POST",
        "/admin/reset-password",
        vec![("Content-Type", "application/x-www-form-urlencoded")],
        Some(
            "token=made-up&new_password=correct+horse+battery&confirm_password=correct+horse+battery"
                .to_string(),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Invalid or expired"),
        "unknown reset tokens must be rejected"
    );
}

#[tokio::test]
async fn test_swagger_ui_is_not_public() {
    let (mut app, _state) = setup_test_app().await;

    let (status, _body, _headers) =
        make_request(&mut app, "GET", "/api-docs/openapi.json", vec![], None).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the API schema should not be readable anonymously"
    );
}
