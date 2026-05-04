//! GET /api/hash-finalize-detect.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use tracemiku_core::hashfin::{hash_finalize_detect, HashFinalizeCandidate};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct HashFinalizeQuery {
    #[serde(default = "default_window")]
    pub window: usize,
    #[serde(default = "default_min_size")]
    pub min_size: u64,
}

fn default_window() -> usize {
    500
}

fn default_min_size() -> u64 {
    16
}

#[derive(Debug, Serialize)]
pub struct HashFinalizeResponse {
    pub window: usize,
    pub min_size: u64,
    pub count: usize,
    pub candidates: Vec<HashFinalizeCandidate>,
}

pub async fn hash_finalize_detect_handler(
    State(state): State<AppState>,
    Query(q): Query<HashFinalizeQuery>,
) -> Json<HashFinalizeResponse> {
    let candidates = hash_finalize_detect(&state.inner.memshadow, q.window, q.min_size);

    Json(HashFinalizeResponse {
        window: q.window,
        min_size: q.min_size,
        count: candidates.len(),
        candidates,
    })
}
