use anyhow::Result;
use axum::{extract::State, http::StatusCode, response::Json};
use lazy_static::lazy_static;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    str::Bytes,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc::Receiver;
use tokio::time::{sleep, Duration};

lazy_static! {
    #[derive(Clone)]
    pub static ref STATE: SharedState = Arc::new(Mutex::new(AppState::default()));
}

const TMP_DIR: &str = "/tmp/updated-file.json";

pub type SharedState = Arc<Mutex<AppState>>;

pub async fn data_updater(tx: tokio::sync::mpsc::Sender<AppState>) -> Result<()> {
    loop {
        if let Ok(mut state) = STATE.try_lock() {
            // TODO: some data requesting routine: persisted file reading, request update etc.
            let json: Value = fs::read_to_string(TMP_DIR)?.into();
            for (k, v) in json.as_object().expect("Not a valid json") {
                // Note: this is viable only if your json payload is small. If you figure out you
                // are approaching more than 100 Kb, my dude...switch to some streaming or event based solution.
                state.db.insert(k.to_string(), v.to_string());
            }
            tx.send(state.clone()).await.unwrap();
        }
        sleep(Duration::from_secs(10)).await;
    }
}

#[derive(Default, Debug, Clone)]
pub struct AppState {
    db: BTreeMap<String, String>,
}

impl AppState {
    pub fn data(&self) -> BTreeMap<String, String> {
        self.db.clone()
    }
}

pub mod handlers {
    use super::*;

    /// Main get state handler
    pub async fn get_data(
        State(state): State<SharedState>,
        mut rx: Receiver<SharedState>,
    ) -> Result<String, StatusCode> {
        let map = &state
            .try_lock()
            .map_err(|e| {
                eprintln!("Error accessing state:{:?}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR).into()
            })?
            .db;

        map.keys().map(|i| i.to_string()).collect()
    }

    pub async fn list_keys(State(state): State<SharedState>) -> Result<String> {
        let db = &state
            .try_lock()
            .map_err(|e| {
                eprintln!("Error accessing state:{:?}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR).into()
            })?
            .db;

        db.keys()
            .map(|key| key.to_string())
            .collect::<Vec<String>>()
            .join("\n")
    }
}
