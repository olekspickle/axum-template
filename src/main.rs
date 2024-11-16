use axum::{
    response::Json,
    routing::{get, Router},
};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc::{channel, Receiver};
use tokio::time::{sleep, Duration};

mod data;

use data::{data_handler, data_updater, SharedState, STATE, handlers::get_data};

#[tokio::main]
async fn main() {
    let (tx, rx) = channel(10);

    // Spawn a separate task to update data and send it over the channel
    tokio::spawn(data_updater(tx));

    let app = Router::new()
        .route(
            "/:key",
            // Add compression to `kv_get`
            get(kv_get.layer(CompressionLayer::new()))
                // But don't compress `kv_set`
                .post_service(
                    kv_set
                        .layer((
                            DefaultBodyLimit::disable(),
                            RequestBodyLimitLayer::new(1024 * 5_000 /* ~5mb */),
                        ))
                        .with_state(Arc::clone(&shared_state)),
                ),
        )
        .route("/", get(data_handler(STATE.clone(), rx)))
        .with_state(STATE);

    // Start the server
    let addr = "127.0.0.1:3000".parse().unwrap();
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    println!("Hello, world!");
}
