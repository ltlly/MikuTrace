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
    pub status: &'static str,
    pub window: usize,
    pub min_size: u64,
    pub count: usize,
    pub candidates: Vec<HashFinalizeCandidate>,
}

pub async fn hash_finalize_detect_handler(
    State(state): State<AppState>,
    Query(q): Query<HashFinalizeQuery>,
) -> Json<HashFinalizeResponse> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || hash_finalize_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "hash finalize worker failed: {err}");
                HashFinalizeResponse {
                    status: "error",
                    window: 0,
                    min_size: 0,
                    count: 0,
                    candidates: Vec::new(),
                }
            }),
    )
}

fn hash_finalize_response(
    inner: &crate::state::AppStateInner,
    q: HashFinalizeQuery,
) -> HashFinalizeResponse {
    let mem = match inner.memshadow_ready_or_block_if_idle() {
        Ok(mem) => mem,
        Err(status) => {
            return HashFinalizeResponse {
                status,
                window: q.window,
                min_size: q.min_size,
                count: 0,
                candidates: Vec::new(),
            };
        }
    };
    let candidates = hash_finalize_detect(mem, q.window, q.min_size);

    HashFinalizeResponse {
        status: "ready",
        window: q.window,
        min_size: q.min_size,
        count: candidates.len(),
        candidates,
    }
}
