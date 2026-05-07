//! # Middleware
//!
//! You can do whatever you want with incoming requests before they reach handles
//!

use std::sync::Arc;
use std::time::Duration;
use std::{collections::HashMap, str::FromStr};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{Extensions, Response, StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Redirect},
};
use chrono::{DateTime, Utc};
use strum::{AsRefStr, EnumString};

use tokio::sync::RwLock;
use uuid::Uuid;

use crate::db::Db;
use crate::state::AppState;

#[derive(Debug, Clone, Default, PartialEq, PartialOrd, EnumString, AsRefStr)]
pub enum Role {
    #[default]
    User,
    Editor,
    Admin,
}

#[derive(Debug, Clone)]
pub struct TokenData {
    pub username: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
    pub expiry: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ResetTokenData {
    pub username: String,
    pub expiry: DateTime<Utc>,
}

pub struct TokenManager {
    tokens: Arc<RwLock<HashMap<String, TokenData>>>,
    reset_tokens: Arc<RwLock<HashMap<String, ResetTokenData>>>,
    ttl: Duration,
    credentials: HashMap<String, String>,
    db: Option<Arc<dyn Db>>,
}

impl TokenManager {
    pub fn new(
        ttl_secs: u64,
        credentials: HashMap<String, String>,
        db: Option<Arc<dyn Db>>,
    ) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            reset_tokens: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
            credentials,
            db,
        }
    }

    fn long_ttl(&self) -> Duration {
        self.ttl * 30 * 24 // 30 days
    }

    pub async fn login(&self, username: &str, password: &str, long: bool) -> Option<String> {
        if let Some(expected_hash) = self.credentials.get(username) {
            let parsed_hash = PasswordHash::new(expected_hash).ok()?;
            if Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok()
            {
                return Some(
                    self.generate_with_metadata(username.to_string(), Role::Admin, long)
                        .await,
                );
            }
        }
        None
    }

    pub async fn generate(&self) -> String {
        self.generate_with_metadata("anonymous".to_string(), Role::User, false)
            .await
    }

    pub async fn generate_user_token(&self, username: String, role: Role, long: bool) -> String {
        self.generate_with_metadata(username, role, long).await
    }

    async fn generate_with_metadata(&self, username: String, role: Role, long: bool) -> String {
        let token = Uuid::new_v4().to_string();
        let token_for_return = token.clone();
        let now = Utc::now();
        let ttl = if long { self.long_ttl() } else { self.ttl };
        let expiry = now + chrono::Duration::from_std(ttl).unwrap_or_default();
        let data = TokenData {
            username: username.clone(),
            role: role.clone(),
            created_at: now,
            expiry,
        };
        self.tokens.write().await.insert(token.clone(), data);

        if let Some(db) = &self.db {
            let _ = db
                .save_token(
                    &token,
                    &username,
                    role.as_ref(),
                    &now.to_rfc3339(),
                    &expiry.to_rfc3339(),
                )
                .await;
        }

        token_for_return
    }

    pub async fn validate(&self, token: &str) -> bool {
        // scope to drop guard faster
        {
            let tokens = self.tokens.read().await;
            if let Some(data) = tokens.get(token) {
                return Utc::now() < data.expiry;
            }
        }

        if let Some(db) = &self.db
            && let Ok(Some((username, role_str, created_at, expiry))) = db.get_token(token).await
            && let (Ok(expiry_dt), Ok(created_dt)) = (
                expiry.parse::<DateTime<Utc>>(),
                created_at.parse::<DateTime<Utc>>(),
            )
        {
            if Utc::now() < expiry_dt {
                self.tokens.write().await.insert(
                    token.to_string(),
                    TokenData {
                        username,
                        expiry: expiry_dt,
                        created_at: created_dt,
                        role: Role::from_str(&role_str).unwrap_or_default(),
                    },
                );
                return true;
            } else {
                let _ = db.delete_token(token).await;
            }
        }

        false
    }

    pub async fn is_admin(&self, token: &str) -> bool {
        let tokens = self.tokens.read().await;
        matches!(tokens.get(token).map(|d| &d.role), Some(Role::Admin))
    }

    pub async fn get_role(&self, token: &str) -> Option<Role> {
        let tokens = self.tokens.read().await;
        tokens.get(token).map(|d| d.role.clone())
    }

    pub async fn get_username(&self, token: &str) -> Option<String> {
        let tokens = self.tokens.read().await;
        tokens.get(token).map(|d| d.username.clone())
    }

    pub async fn cleanup(&self) {
        let now = Utc::now();
        self.tokens
            .write()
            .await
            .retain(|_, data| now < data.expiry);

        if let Some(db) = &self.db {
            let _ = db.cleanup_expired_tokens(&now.to_rfc3339()).await;
        }
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
        if let Some(db) = &self.db {
            let _ = db.delete_token(token).await;
        }
    }

    /// Generate a password reset token (valid 1 hour)
    pub async fn generate_reset_token(&self, username: &str) -> String {
        let token = Uuid::new_v4().to_string();
        let data = ResetTokenData {
            username: username.to_string(),
            expiry: Utc::now() + chrono::Duration::hours(1),
        };
        self.reset_tokens.write().await.insert(token.clone(), data);
        token
    }

    /// Validate reset token, return username if valid
    pub async fn validate_reset_token(&self, token: &str) -> Option<String> {
        let mut tokens = self.reset_tokens.write().await;
        if let Some(data) = tokens.get(token)
            && Utc::now() < data.expiry
        {
            return Some(data.username.clone());
        }
        tokens.remove(token);
        None
    }

    /// Consume reset token after use
    pub async fn consume_reset_token(&self, token: &str) -> Option<String> {
        let mut tokens = self.reset_tokens.write().await;
        if let Some(data) = tokens.remove(token)
            && Utc::now() < data.expiry
        {
            return Some(data.username);
        }
        None
    }
}

pub async fn custom_log(req: Request, next: Next) -> Result<Response<Body>, StatusCode> {
    let (parts, body) = req.into_parts();
    let req = Request::from_parts(parts, body);
    Ok(next.run(req).await)
}

pub async fn require_role(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let auth = state.token_manager.clone();
    let (parts, body) = req.into_parts();

    let token = extract_token(&parts.headers, &parts.extensions);

    if let Some(token) = token.as_deref()
        && auth.validate(token).await
    {
        let user_role = auth.get_role(token).await.unwrap_or(Role::User);
        if user_role >= state.required_role {
            let req = axum::extract::Request::from_parts(parts, body);
            return next.run(req).await.into_response();
        }
    }

    let accepts_html = parts
        .headers
        .get("accept")
        .and_then(|h| h.to_str().ok())
        .map(|accept| accept.contains("text/html"))
        .unwrap_or(false);

    if accepts_html {
        return Redirect::to("/login").into_response();
    }

    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}

fn extract_token(headers: &axum::http::HeaderMap, _extensions: &Extensions) -> Option<String> {
    if let Some(token) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        return Some(token.to_string());
    }

    if let Some(token) = headers.get("X-Bearer-Token").and_then(|v| v.to_str().ok()) {
        return Some(token.to_string());
    }

    if let Some(cookie_header) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some((name, value)) = cookie.split_once('=')
                && name.trim() == "token"
            {
                return Some(value.trim().to_string());
            }
        }
    }

    None
}

pub fn hash_password(password: &str) -> String {
    Argon2::default()
        .hash_password(password.as_bytes())
        .unwrap()
        .to_string()
}

pub async fn rate_limit(
    State(state): State<AppState>,
    req: Request,
    next: axum::middleware::Next,
) -> impl IntoResponse {
    if req.uri().path() == "/login" {
        let ip = req
            .headers()
            .get("X-Real-IP")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        let mut map = state.rate_limiter.write().await;
        let now = std::time::Instant::now();

        map.retain(|_, (_, time)| now.duration_since(*time) < std::time::Duration::from_secs(900));

        let (count, _) = map.entry(ip).or_insert((0, now));
        *count += 1;

        if *count > 5 {
            return (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "Too many login attempts",
            )
                .into_response();
        }
    }

    let response = next.run(req).await;
    response.into_response()
}
