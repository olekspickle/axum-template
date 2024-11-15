use axum::{
    body::Bytes,
    error_handling::HandleErrorLayer,
    extract::{DefaultBodyLimit, Path, State},
    handler::Handler,
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get},
    Router,
};
use axum::{
    response::Json,
    routing::{get, Router},
};
use std::sync::{Arc, RwLock};
use std::{
    borrow::Cow,
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::sync::mpsc::{channel, Receiver};
use tokio::time::{sleep, Duration};
use tower::{BoxError, ServiceBuilder};
use tower_http::{
    compression::CompressionLayer, limit::RequestBodyLimitLayer, trace::TraceLayer,
    validate_request::ValidateRequestHeaderLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod data;

use data::{data_updater, handlers::get_data, SharedState, STATE};

#[tokio::main]
async fn main() {
    let (tx, rx) = channel(10);

    // Spawn a separate task to update data and send it over the channel
    tokio::spawn(data_updater(tx));

    let app = Router::new()
        .route("/:key", get(get_data(rx)).layer(CompressionLayer::new()))
        .layer((
            DefaultBodyLimit::disable(),
            RequestBodyLimitLayer::new(1024 * 1_000 /* ~1mb */),
        ))
        .with_state(Arc::clone(&STATE));

    // Start the server
    let addr = "127.0.0.1:3000".parse().unwrap();
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    println!("Hello, world!");
}
