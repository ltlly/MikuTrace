//! GET /api/jni-events.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct JniEventsQuery {
    pub id: Option<String>,
    pub idx_lo: Option<usize>,
    pub idx_hi: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct JniEventsResponse {
    pub count: usize,
    pub events: Vec<Value>,
}

pub async fn jni_events_handler(
    State(state): State<AppState>,
    Query(q): Query<JniEventsQuery>,
) -> Json<JniEventsResponse> {
    let trace_dir = state.inner.trace_dir.clone();
    let response = tokio::task::spawn_blocking(move || jni_events_response(trace_dir, q))
        .await
        .unwrap_or_else(|err| {
            tracing::warn!(target: "tracemiku-server", "jni events worker failed: {err}");
            JniEventsResponse {
                count: 0,
                events: Vec::new(),
            }
        });
    Json(response)
}

fn jni_events_response(trace_dir: std::path::PathBuf, q: JniEventsQuery) -> JniEventsResponse {
    let path = trace_dir.join("jni_hooks.jsonl");
    let mut events = Vec::new();
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines() {
            let Ok(value) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            if q.id
                .as_deref()
                .is_some_and(|want| value.get("id").and_then(Value::as_str) != Some(want))
            {
                continue;
            }
            let trace_idx = value
                .get("trace_idx")
                .and_then(Value::as_u64)
                .map(|v| v as usize);
            if q.idx_lo
                .is_some_and(|lo| trace_idx.is_none_or(|idx| idx < lo))
            {
                continue;
            }
            if q.idx_hi
                .is_some_and(|hi| trace_idx.is_none_or(|idx| idx >= hi))
            {
                continue;
            }
            events.push(value);
        }
    }
    JniEventsResponse {
        count: events.len(),
        events,
    }
}
