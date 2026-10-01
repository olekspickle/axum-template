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
    // Config::load requires ADMIN_PASSWORD; set a throwaway one for the test run.
    // SAFETY: written once via `Once` before any test reads the env, never mutated after.
    static ENV_INIT: std::sync::Once = std::sync::Once::new();
    ENV_INIT.call_once(|| unsafe { std::env::set_var("ADMIN_PASSWORD", "admin") });

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

    assert_eq!(status, StatusCode::CREATED, "an Editor may create posts");
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

/// Minimal form-urlencoding so the tests can post JSON and paths as field values.
fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn form_body(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

#[tokio::test]
async fn test_team_member_links_framing_and_edit_round_trip() {
    let (mut app, state) = setup_test_app().await;
    let token = login(&mut app, "admin", "admin").await.expect("admin login");
    let cookie = format!("token={token}");
    let form = ("Content-Type", "application/x-www-form-urlencoded");

    let (status, _, _) = make_request(
        &mut app,
        "POST",
        "/admin/team",
        vec![form, ("Cookie", &cookie)],
        Some(form_body(&[
            ("name", "Jane"),
            ("role", "Dev"),
            ("bio", "hi"),
            ("photo_url", "/static/media/img/jane.png"),
            ("photo_w", "240"),
            ("photo_l", "-60"),
            ("photo_t", "-15"),
            (
                "links",
                r#"[{"platform":"github","url":"https://github.com/jane"},
                    {"platform":"x","url":"javascript:alert(1)"}]"#,
            ),
        ])),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "create redirects to the list");

    let jane = state.db.get_team_member("Jane").await.unwrap().expect("created");
    assert_eq!(jane.links.len(), 1, "the javascript: link must be dropped");
    assert_eq!(jane.links[0].platform, "github");
    assert_eq!(
        jane.photo,
        db::PhotoPos {
            w: Some(240.0),
            l: -60.0,
            t: -15.0
        }
    );

    let (status, body, _) = make_request(&mut app, "GET", "/about", vec![], None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("fa-brands fa-github"), "icon rendered from links");
    assert!(body.contains("width:240.00%"), "framing rendered inline");
    assert!(!body.contains("javascript:"));

    let (status, body, _) = make_request(
        &mut app,
        "GET",
        &format!("/admin/team/{}", jane.id),
        vec![("Cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"value="Jane""#), "edit form is prefilled");
    assert!(body.contains(r#"name="photo_w" value="240""#));

    // Editing replaces links/framing but never the password hash.
    add_team_member(&state, "pw", "Editor", "correct horse battery").await;
    let pw = state.db.get_team_member("pw").await.unwrap().expect("pw");
    let hash = pw.password_hash.clone().expect("hash stored");
    let (status, _, _) = make_request(
        &mut app,
        "POST",
        &format!("/admin/team/{}", pw.id),
        vec![form, ("Cookie", &cookie)],
        Some(form_body(&[
            ("name", "pw"),
            ("role", "Lead"),
            ("bio", "new bio"),
            ("photo_url", ""),
            ("photo_w", "not-a-number"),
            ("links", r#"[{"platform":"email","url":"pw@example.com"}]"#),
        ])),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let pw = state.db.get_team_member_by_id(&pw.id).await.unwrap().expect("pw");
    assert_eq!(pw.role, "Lead");
    assert_eq!(pw.links[0].url, "mailto:pw@example.com");
    assert_eq!(pw.photo, db::PhotoPos::default(), "junk framing falls back to default");
    assert_eq!(pw.password_hash, Some(hash), "edit must not touch the password");

    let (status, _, headers) = make_request(
        &mut app,
        "GET",
        "/admin/team/does-not-exist",
        vec![("Cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers.get("location").unwrap(), "/admin/team");

    let (status, _, _) = make_request(
        &mut app,
        "POST",
        &format!("/admin/team/{}", jane.id),
        vec![form],
        Some(form_body(&[("name", "x"), ("role", "x"), ("bio", "x")])),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "editing needs a login");
}

#[tokio::test]
async fn test_legacy_team_columns_are_migrated() {
    // Databases created before `links`/avatar framing existed must be upgraded in place.
    static ENV_INIT: std::sync::Once = std::sync::Once::new();
    ENV_INIT.call_once(|| unsafe { std::env::set_var("ADMIN_PASSWORD", "admin") });

    let path = std::env::temp_dir().join(format!("legacy-team-{}.db", uuid::Uuid::new_v4()));
    {
        use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
        let pool = SqlitePool::connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true),
        )
        .await
        .expect("legacy db");
        sqlx::query(
            "CREATE TABLE team_members (id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, bio TEXT NOT NULL, photo_url TEXT NOT NULL, github_url TEXT, twitter_url TEXT, linkedin_url TEXT, password_hash TEXT, created_at TEXT NOT NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO team_members VALUES ('1','legacy','dev','bio','','https://github.com/old','','https://linkedin.com/in/old',NULL,'2026-01-01T00:00:00Z'), ('2','bare','dev','bio','',NULL,NULL,NULL,NULL,'2026-01-02T00:00:00Z')",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
    }

    let mut config = Config::load("config.toml").expect("config");
    config.db.path = path.to_string_lossy().into_owned();
    let db = db::create_db(&config).await.expect("create db");
    db.init().await.expect("first init migrates");
    db.init().await.expect("init is idempotent");

    let legacy = db.get_team_member("legacy").await.unwrap().expect("legacy");
    let links: Vec<_> = legacy.links.iter().map(|l| (l.platform.as_str(), l.url.as_str())).collect();
    assert_eq!(
        links,
        vec![
            ("github", "https://github.com/old"),
            ("linkedin", "https://linkedin.com/in/old")
        ],
        "legacy socials carried over, empty ones skipped"
    );
    assert_eq!(legacy.photo, db::PhotoPos::default());
    let bare = db.get_team_member("bare").await.unwrap().expect("bare");
    assert!(bare.links.is_empty());

    // The legacy schema still has `photo_url NOT NULL`: an empty photo must keep working.
    let created = db
        .create_team_member(db::NewTeamMember {
            name: "fresh".into(),
            role: "dev".into(),
            bio: "bio".into(),
            photo_url: Some(String::new()),
            ..Default::default()
        })
        .await
        .expect("create on legacy schema");
    db.update_team_member(
        &created.id,
        db::NewTeamMember {
            name: "fresh".into(),
            role: "lead".into(),
            bio: "bio".into(),
            photo_url: Some(String::new()),
            ..Default::default()
        },
    )
    .await
    .expect("update on legacy schema");
    let _ = std::fs::remove_file(&path);
}
