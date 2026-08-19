//! GET /api/functions

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use serde_json::json;

use tracemiku_core::prelude::{make_bn_id, FunctionEntry};

use crate::state::{AppState, AppStateInner};

const MAX_FUNCTIONS: usize = 10_000;

#[derive(Debug, Serialize)]
pub struct FunctionsResponse {
    pub counts: HashMap<String, u64>,
    pub functions: Vec<FunctionEntry>,
    pub total_functions: usize,
    pub returned_functions: usize,
    pub max_functions_used: usize,
    pub truncated: bool,
}

pub async fn functions_handler(
    State(state): State<AppState>,
) -> Result<Json<FunctionsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let inner = state.inner.clone();
    let response = tokio::task::spawn_blocking(move || functions_response(inner))
        .await
        .map_err(|err| crate::routes::worker_panic_response("functions", &err))?;
    Ok(Json(response))
}

fn functions_response(inner: Arc<AppStateInner>) -> FunctionsResponse {
    let mut fns = inner.function_index.entries.clone();
    if let Ok(mut sidecar) = inner.bn_sidecar.lock() {
        let bn = sidecar.request("functions", json!({}));
        if bn.get("ready").and_then(|v| v.as_bool()).unwrap_or(false) {
            if let Some(items) = bn.get("functions").and_then(|v| v.as_array()) {
                for item in items {
                    let Some(start) = item.get("start").and_then(|v| v.as_u64()) else {
                        continue;
                    };
                    let name = item
                        .get("name")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("sub_{start:x}"));
                    fns.push(FunctionEntry {
                        id: make_bn_id(start),
                        name,
                        source: "bn".to_string(),
                        entry_pc: Some(start),
                        blocks: 0,
                        records: 0,
                        module: None,
                        entry_rel: None,
                        bn_start: Some(start),
                        can_bn_hlil: true,
                    });
                }
            }
        }
    }
    functions_response_from_entries(fns)
}

fn functions_response_from_entries(fns: Vec<FunctionEntry>) -> FunctionsResponse {
    let mut counts: HashMap<String, u64> = HashMap::new();
    counts.insert("symbol".to_string(), 0);
    counts.insert("bn".to_string(), 0);
    for f in &fns {
        *counts.entry(f.source.clone()).or_insert(0) += 1;
    }
    let total_functions = fns.len();
    let mut functions = fns;
    if functions.len() > MAX_FUNCTIONS {
        functions.truncate(MAX_FUNCTIONS);
    }
    let returned_functions = functions.len();
    FunctionsResponse {
        counts,
        functions,
        total_functions,
        returned_functions,
        max_functions_used: MAX_FUNCTIONS,
        truncated: total_functions > returned_functions,
    }
}
