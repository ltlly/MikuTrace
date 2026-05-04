//! GET /api/functions

use std::collections::HashMap;

use axum::extract::State;
use axum::Json;
use serde::Serialize;
use serde_json::json;

use tracemiku_core::prelude::{make_bn_id, FunctionEntry};

use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct FunctionsResponse {
    pub counts: HashMap<String, u64>,
    pub functions: Vec<FunctionEntry>,
}

pub async fn functions_handler(State(state): State<AppState>) -> Json<FunctionsResponse> {
    let inner = &state.inner;
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
                        trace_ir_id: None,
                        bn_start: Some(start),
                        can_llil: false,
                        can_bn_hlil: true,
                    });
                }
            }
        }
    }
    let mut counts: HashMap<String, u64> = HashMap::new();
    counts.insert("trace-ir".to_string(), 0);
    counts.insert("symbol".to_string(), 0);
    counts.insert("bn".to_string(), 0);
    for f in &fns {
        *counts.entry(f.source.clone()).or_insert(0) += 1;
    }
    Json(FunctionsResponse {
        counts,
        functions: fns,
    })
}
