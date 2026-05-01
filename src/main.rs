use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use axum_template::{
    app_router,
    config::Config,
    db,
    middleware::{Role, TokenManager},
    state::AppState,
    tls,
};

async fn auth_cleanup(auth: Arc<TokenManager>) {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    loop {
        interval.tick().await;
        auth.cleanup().await;
    }
}

fn tracing_init() {
    use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

    const NAME: &str = env!("CARGO_PKG_NAME");
    let name = NAME.replace('_', "-");

    let fallback_log_level: EnvFilter = match cfg!(debug_assertions) {
        true => format!(
            "debug,\
            {name}=debug,\
            tower_http=debug,\
            sqlx=info,\
            rusqlite=debug,\
            axum::rejection=trace,\
            tower_http::trace::on_response=trace,\
            tower_http::trace::on_request=trace"
        )
        .into(),
        _ => "info".into(),
    };
    let log_level = EnvFilter::try_from_default_env().unwrap_or(fallback_log_level);

    let fmt = fmt::format().with_line_number(true);
    let sub_fmt = tracing_subscriber::fmt::layer().event_format(fmt);
    tracing_subscriber::registry()
        .with(sub_fmt)
        .with(log_level.clone())
        .init();

    let pretty = log_level
        .to_string()
        .split(',')
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    tracing::info!(level=%pretty, "set up logging.");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install ring CryptoProvider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("rustls CryptoProvider::install_default");

    tracing_init();

    let config = Arc::new(Config::load("config.toml")?);
    let config_addr = config.address();

    let db = db::create_db(&config).await?;
    db.init().await?;
    let db = Arc::<dyn db::Db>::from(db);

    let token_manager = Arc::new(TokenManager::new(
        config.auth.token_ttl,
        config.admin_credentials(),
    ));
    let auth = token_manager.clone();

    tokio::spawn(auth_cleanup(auth.clone()));

    let https = Path::new("cert.pem").exists() && Path::new("key.pem").exists();

    let state = AppState {
        db: db.clone(),
        config: config.clone(),
        token_manager: token_manager.clone(),
        required_role: Role::User,
        rate_limiter: Arc::new(RwLock::new(HashMap::new())),
        https,
    };

    let router = app_router(state);
    let addr: SocketAddr = config_addr.parse().expect("invalid address");

    if https {
        tls::run_with_tls(addr, router).await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(address = %addr, "listening (HTTP)");
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }
    Ok(())
}
