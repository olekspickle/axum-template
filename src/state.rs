use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::config::Config;
use crate::db::Db;
use crate::middleware::Role;
use crate::middleware::TokenManager;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<dyn Db>,
    pub config: Arc<Config>,
    pub token_manager: Arc<TokenManager>,
    pub required_role: Role,
    pub rate_limiter: Arc<RwLock<HashMap<String, (usize, Instant)>>>,
    pub https: bool,
}

impl AppState {
    pub fn with_role(mut self, role: Role) -> Self {
        self.required_role = role;
        self
    }
}
