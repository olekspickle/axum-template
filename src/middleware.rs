//! # Middleware
//!
//! You can do whatever you want with incoming requests before they reach handles
//!

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::{collections::HashMap, str::FromStr};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{Extensions, HeaderValue, Response, StatusCode, header, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Redirect},
};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use strum::{AsRefStr, EnumString};

use tokio::sync::RwLock;
use uuid::Uuid;

use crate::db::Db;
use crate::state::AppState;

/// Paths where credentials are submitted, and which therefore get rate limited.
const RATE_LIMITED_PATHS: [&str; 3] = ["/login", "/admin/forgot-password", "/admin/reset-password"];
const RATE_LIMIT_ATTEMPTS: usize = 5;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(900);

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, EnumString, AsRefStr)]
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

/// Tokens are bearer credentials, so only their digest is persisted - a leaked
/// database dump then can't be replayed as a session.
fn token_digest(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
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
        let expected_hash = self.credentials.get(username);
        // Verify even for unknown users so response time doesn't reveal which names exist.
        let verified = match expected_hash.and_then(|h| PasswordHash::new(h).ok()) {
            Some(parsed) => Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok(),
            None => {
                let _ = Argon2::default().hash_password(password.as_bytes());
                false
            }
        };

        if verified {
            return Some(
                self.generate_with_metadata(username.to_string(), Role::Admin, long)
                    .await,
            );
        }
        None
    }

    pub async fn generate_user_token(&self, username: String, role: Role, long: bool) -> String {
        self.generate_with_metadata(username, role, long).await
    }

    async fn generate_with_metadata(&self, username: String, role: Role, long: bool) -> String {
        let token = Uuid::new_v4().to_string();
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

        if let Some(db) = &self.db
            && let Err(e) = db
                .save_token(
                    &token_digest(&token),
                    &username,
                    role.as_ref(),
                    &now.to_rfc3339(),
                    &expiry.to_rfc3339(),
                )
                .await
        {
            tracing::error!(error = %e, "failed to persist token");
        }

        token
    }

    pub async fn validate(&self, token: &str) -> bool {
        // scope to drop guard faster
        {
            let tokens = self.tokens.read().await;
            if let Some(data) = tokens.get(token) {
                return Utc::now() < data.expiry;
            }
        }

        let digest = token_digest(token);
        if let Some(db) = &self.db
            && let Ok(Some((username, role_str, created_at, expiry))) = db.get_token(&digest).await
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
                let _ = db.delete_token(&digest).await;
            }
        }

        false
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
        self.reset_tokens
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
            return self.validate(strip_bearer(token)).await;
        }
        false
    }

    pub async fn invalidate(&self, token: &str) {
        self.tokens.write().await.remove(token);
        if let Some(db) = &self.db {
            let _ = db.delete_token(&token_digest(token)).await;
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
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
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

/// `Authorization: Bearer <token>` and a bare token are both accepted.
fn strip_bearer(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .unwrap_or(value)
        .trim()
}

pub(crate) fn extract_token(
    headers: &axum::http::HeaderMap,
    _extensions: &Extensions,
) -> Option<String> {
    if let Some(token) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        return Some(strip_bearer(token).to_string());
    }

    if let Some(token) = headers.get("X-Bearer-Token").and_then(|v| v.to_str().ok()) {
        return Some(strip_bearer(token).to_string());
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
        .expect("argon2 hashing with a generated salt cannot fail")
        .to_string()
}

/// Rate limit key: the peer address, or a proxy-provided address when the deployment
/// declares `server.trusted_proxy`. Client headers are never trusted otherwise, since
/// anyone can vary them to get a fresh bucket per request.
fn client_key(state: &AppState, req: &Request) -> String {
    if state.config.server.trusted_proxy {
        let forwarded = req
            .headers()
            .get("X-Real-IP")
            .or_else(|| req.headers().get("X-Forwarded-For"))
            .and_then(|h| h.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|v| v.trim().to_string());
        if let Some(ip) = forwarded.filter(|ip| !ip.is_empty()) {
            return ip;
        }
    }

    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub async fn rate_limit(
    State(state): State<AppState>,
    req: Request,
    next: axum::middleware::Next,
) -> impl IntoResponse {
    if RATE_LIMITED_PATHS.contains(&req.uri().path()) {
        let key = client_key(&state, &req);

        let mut map = state.rate_limiter.write().await;
        let now = std::time::Instant::now();

        map.retain(|_, (_, start)| now.duration_since(*start) < RATE_LIMIT_WINDOW);

        let (count, start) = map.entry(key).or_insert((0, now));
        if now.duration_since(*start) >= RATE_LIMIT_WINDOW {
            *count = 0;
            *start = now;
        }
        *count += 1;

        if *count > RATE_LIMIT_ATTEMPTS {
            return (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "Too many attempts",
            )
                .into_response();
        }
    }

    next.run(req).await.into_response()
}

/// Baseline hardening headers. Swagger UI ships inline scripts/styles, so it keeps
/// the transport headers but not the script policy.
pub async fn security_headers(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response<Body> {
    let path = req.uri().path().to_string();
    let https = state.https;
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );

    if !path.starts_with("/swagger-ui") && !path.starts_with("/api-docs") {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; img-src 'self' data:; media-src 'self'; \
                 style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; \
                 base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
            ),
        );
    }

    if https {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }

    response
}
