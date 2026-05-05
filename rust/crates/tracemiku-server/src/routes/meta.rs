use axum::extract::State;
use axum::Json;

use crate::state::AppState;

pub async fn meta_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    // Use serde_json::Value rather than a typed response so the wire shape
    // is dictated by serde::Serialize on TraceMeta itself (single source).
    Json(serde_json::to_value(&state.inner.meta).unwrap())
}
