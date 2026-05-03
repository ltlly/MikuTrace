//! GET /api/functions

use std::collections::HashMap;

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use tracemiku_core::prelude::FunctionEntry;

use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct FunctionsResponse {
    pub counts: HashMap<String, u64>,
    pub functions: Vec<FunctionEntry>,
}

pub async fn functions_handler(State(state): State<AppState>) -> Json<FunctionsResponse> {
    let inner = &state.inner;
    let fns = inner.function_index.entries.clone();
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
