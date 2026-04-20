//! # Middleware
//!
//! You can do whatever you want with incoming requests before they reach handles
//!

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{Response, StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::IntoResponse,
};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Clone, PartialEq)]
pub enum Role {
    Admin,
    User,
}

#[derive(Debug, Clone)]
pub struct TokenData {
    pub username: String,
    pub role: Role,
    pub created_at: Instant,
    pub expiry: Instant,
}

pub struct TokenManager {
    tokens: Arc<RwLock<HashMap<String, TokenData>>>,
    ttl: Duration,
    credentials: HashMap<String, String>,
}

impl TokenManager {
    pub fn new(ttl_secs: u64, credentials: HashMap<String, String>) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
            credentials,
        }
    }

    pub async fn login(&self, username: &str, password: &str) -> Option<String> {
        if let Some(expected_hash) = self.credentials.get(username) {
            let parsed_hash = PasswordHash::new(expected_hash).ok()?;
            if Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok()
            {
                return Some(
                    self.generate_with_metadata(username.to_string(), Role::Admin)
                        .await,
                );
            }
        }
        None
    }

    pub async fn generate(&self) -> String {
        self.generate_with_metadata("anonymous".to_string(), Role::User)
            .await
    }

    pub async fn generate_user_token(&self, username: String) -> String {
        self.generate_with_metadata(username, Role::User).await
    }

    pub async fn generate_with_metadata(&self, username: String, role: Role) -> String {
        let token = Uuid::new_v4().to_string();
        let token_for_return = token.clone();
        let now = Instant::now();
        let data = TokenData {
            username,
            role,
            created_at: now,
            expiry: now + self.ttl,
        };
        self.tokens.write().await.insert(token, data);
        token_for_return
    }

    pub async fn validate(&self, token: &str) -> bool {
        let mut tokens = self.tokens.write().await;
        if let Some(data) = tokens.get(token)
            && Instant::now() < data.expiry
        {
            return true;
        }
        tokens.remove(token);
        false
    }

    pub async fn is_admin(&self, token: &str) -> bool {
        let tokens = self.tokens.read().await;
        matches!(tokens.get(token).map(|d| &d.role), Some(Role::Admin))
    }

    pub async fn get_username(&self, token: &str) -> Option<String> {
        let tokens = self.tokens.read().await;
        tokens.get(token).map(|d| d.username.clone())
    }

    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut tokens = self.tokens.write().await;
        tokens.retain(|_, data| now < data.expiry);
    }

    pub async fn check_header(&self, token: Option<&hyper::header::HeaderValue>) -> bool {
        if let Some(token_value) = token
            && let Ok(token) = token_value.to_str()
        {
            return self.validate(token).await;
        }
        false
    }

    pub async fn invalidate(&self, token: &str) {
        self.tokens.write().await.remove(token);
    }
}

pub async fn custom_log(req: Request, next: Next) -> Result<Response<Body>, StatusCode> {
    let (parts, body) = req.into_parts();
    let req = Request::from_parts(parts, body);
    Ok(next.run(req).await)
}

pub async fn auth(State(state): State<AppState>, req: Request, next: Next) -> impl IntoResponse {
    let auth = state.token_manager.clone();
    let tokens = auth.tokens.read().await;
    if tokens.is_empty() {
        return next.run(req).await.into_response();
    }
    drop(tokens);

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

pub async fn require_admin(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let auth = state.token_manager.clone();

    let (parts, body) = req.into_parts();
    let token = parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            parts
                .headers
                .get("X-Bearer-Token")
                .and_then(|v| v.to_str().ok())
        });

    if let Some(token) = token
        && auth.validate(token).await
        && auth.is_admin(token).await
    {
        let req = axum::extract::Request::from_parts(parts, body);
        return next.run(req).await.into_response();
    }

    (StatusCode::UNAUTHORIZED, "Admin access required").into_response()
}

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}
