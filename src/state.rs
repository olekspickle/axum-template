use std::sync::Arc;

use crate::config::Config;
use crate::db::Db;
use crate::middleware::TokenManager;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<dyn Db>,
    pub config: Arc<Config>,
    pub token_manager: Arc<TokenManager>,
}
