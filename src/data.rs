use anyhow::Result;
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::Json,
};
use lazy_static::lazy_static;
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    str::Bytes,
    sync::{Arc, Mutex},
};
use tinytemplate::TinyTemplate;
use tokio::sync::mpsc::Receiver;
use tokio::time::{sleep, Duration};

/// Json file being persisted on disk
const TMP_DIR: &str = "/tmp/updated-file.json";
/// Template for visualisation
const TEMPLATE: &'static str = include_str!("../assets/template.html");

pub type SharedState = Arc<Mutex<AppState>>;

lazy_static! {
    #[derive(Clone)]
    pub static ref STATE: SharedState = Arc::new(Mutex::new(AppState::default()));
}

/// Updates lazy shared state instance using persistent data or by querying some API
pub async fn data_updater(tx: tokio::sync::mpsc::Sender<SharedState>) -> Result<()> {
    loop {
        if let Ok(mut state) = STATE.try_lock() {
            // TODO: some data requesting routine: persisted file reading, request update etc.
            let json: Value = fs::read_to_string(TMP_DIR)?.into();
            for (k, v) in json.as_object().expect("Not a valid json") {
                // Note: this is viable only if your json payload is small. If you figure out you
                // are approaching more than 100 Kb, my dude...switch to some streaming or event based solution.
                state.db.insert(k.to_string(), v.to_string());
            }
            drop(state);
            tx.send(Arc::clone(&STATE)).await.unwrap();
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

#[derive(Serialize)]
struct Context {
    fields: Vec<(String, String)>,
}

pub mod handlers {
    use super::*;

    /// Main get state handler
    pub async fn get_data(mut rx: Receiver<SharedState>) -> Result<String, StatusCode> {
        let map = &STATE
            .try_lock()
            .or_else(|e| {
                eprintln!("Error accessing state:{:?}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            })?
            .db;

        if let Some(state) = rx.recv().await {
            if &state.db != map {
                let keys: Vec<String> = state.db.keys().map(ToString::to_string).collect();
                let fields: Vec<(String, String)> = state.db.into_iter().collect();
                let mut tt = TinyTemplate::new();
                tt.add_template("main", TEMPLATE)
                    .map_err(|e| StatusCode::INTERNAL_SERVER_ERROR)?;

                let rendered = tt
                    .render("main", &Context { fields })
                    .map_err(|e| StatusCode::INTERNAL_SERVER_ERROR)?;
            }
        }

        let s = map.keys().map(|i| Ok(i.to_string())).collect();
        s
    }

    pub async fn list_keys(State(state): State<SharedState>) -> Result<String> {
        let db = &state
            .try_lock()
            .map_err(|e| {
                eprintln!("Error accessing state:{:?}", e);
                anyhow::format_err!("{}:{e}", StatusCode::INTERNAL_SERVER_ERROR)
            })?
            .db;

        Ok(db
            .keys()
            .map(|key| key.to_string())
            .collect::<Vec<String>>()
            .join("\n"))
    }
}
