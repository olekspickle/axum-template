use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_default_utils::{default_bool, default_u16, default_u64, serde_inline_default};

use crate::middleware::hash_password;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerParams,
    pub auth: AuthParams,
    pub db: DbParams,
    pub site: SiteParams,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerParams {
    pub host: String,
    #[serde(default = "default_u16::<7777>")]
    pub port: u16,
    /// Only set when the server sits behind a proxy you control (nginx, cloudflared).
    /// Enables trusting X-Real-IP/X-Forwarded-For for rate limiting.
    #[serde(default = "default_bool::<false>")]
    pub trusted_proxy: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthParams {
    #[serde(default = "default_u64::<3600>")]
    pub token_ttl: u64,
    pub admin_username: String,
    /// Never read from config.toml (`skip`) — the ADMIN_PASSWORD env var is the
    /// only source, so a password can never be committed or shipped in the file.
    #[serde(skip)]
    pub admin_password: Option<String>,
}

#[serde_inline_default]
#[derive(Debug, Clone, Deserialize)]
pub struct DbParams {
    #[cfg(feature = "sqlite")]
    pub path: String,
    #[cfg(feature = "surreal")]
    #[serde(default)]
    pub surreal: SurrealParams,
}

#[cfg(feature = "surreal")]
#[serde_inline_default]
#[derive(Debug, Clone, Deserialize)]
pub struct SurrealParams {
    #[serde_inline_default("ws://localhost:8000".into())]
    pub url: String,
    #[serde_inline_default("root".into())]
    pub username: String,
    #[serde_inline_default("root".into())]
    pub password: String,
    #[serde_inline_default("studio".into())]
    pub namespace: String,
    /// Database name
    #[serde_inline_default("portfolio".into())]
    pub name: String,
}

#[cfg(feature = "surreal")]
impl Default for SurrealParams {
    fn default() -> Self {
        Self {
            url: "ws://localhost:8000".into(),
            username: "root".into(),
            password: "root".into(),
            namespace: "studio".into(),
            name: "portfolio".into(),
        }
    }
}

#[serde_inline_default]
#[derive(Debug, Clone, Deserialize)]
pub struct SiteParams {
    pub name: String,
    pub tagline: String,
    #[serde_inline_default("en".into())]
    pub default_language: String,
    pub socials: Socials,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Socials {
    pub twitter: Option<String>,
    pub bluesky: Option<String>,
    pub instagram: Option<String>,
    pub github: Option<String>,
    pub linkedin: Option<String>,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let config_str = fs::read_to_string(path.as_ref())?;
        let mut config: Config = toml::from_str(&config_str)?;

        // Admin password comes from the ADMIN_PASSWORD env var only; the server
        // refuses to start without it (deployments get it from /etc/<app>.env).
        match env::var("ADMIN_PASSWORD") {
            Ok(password) => config.auth.admin_password = Some(password),
            Err(_) => anyhow::bail!("ADMIN_PASSWORD env var must be set"),
        }

        #[cfg(feature = "surreal")]
        if let Ok(password) = env::var("SURREAL_PASSWORD") {
            config.db.surreal.password = password;
        }

        Ok(config)
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }

    pub fn admin_credentials(&self) -> HashMap<String, String> {
        [(
            self.auth.admin_username.clone(),
            hash_password(self.auth.admin_password.as_deref().unwrap_or("")),
        )]
        .into_iter()
        .collect()
    }
}
