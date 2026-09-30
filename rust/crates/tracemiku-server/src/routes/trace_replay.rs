//! GET /api/trace-replay — bounded, trace-anchored ARM64 verification.
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use tracemiku_core::replay::{replay_trace, ReplayReport};

#[derive(Debug, Deserialize)]
pub struct ReplayQuery {
    #[serde(default)]
    pub start: usize,
    #[serde(default = "default_count")]
    pub count: usize,
}
fn default_count() -> usize {
    100
}

pub async fn trace_replay_handler(
    State(state): State<AppState>,
    Query(query): Query<ReplayQuery>,
) -> Result<Json<ReplayReport>, (StatusCode, String)> {
    let result = tokio::task::spawn_blocking(move || {
        let trace = &state.inner.trace;
        if query.count == 0 || query.start >= trace.len() {
            return Err((
                StatusCode::BAD_REQUEST,
                "positive count and start inside trace required".into(),
            ));
        }
        let mem = state
            .inner
            .memshadow_ready_or_block_if_idle()
            .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
        replay_trace(trace, mem, query.start, query.count).map_err(|e| (StatusCode::BAD_REQUEST, e))
    })
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "replay worker failed".into(),
        )
    })??;
    Ok(Json(result))
}
