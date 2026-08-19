//! GET /api/jni-events.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::BufRead;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct JniEventsQuery {
    pub id: Option<String>,
    pub idx_lo: Option<usize>,
    pub idx_hi: Option<usize>,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    1_000
}

const MAX_LIMIT: usize = 5_000;

#[derive(Debug, Serialize)]
pub struct JniEventsResponse {
    pub count: usize,
    pub returned: usize,
    pub truncated: bool,
    pub events: Vec<Value>,
}

pub async fn jni_events_handler(
    State(state): State<AppState>,
    Query(q): Query<JniEventsQuery>,
) -> Result<Json<JniEventsResponse>, crate::routes::WorkerFailure> {
    let trace_dir = state.inner.trace_dir.clone();
    let response = tokio::task::spawn_blocking(move || jni_events_response(trace_dir, q))
        .await
        .map_err(|err| crate::routes::worker_panic_response("jni events", &err))?;
    Ok(Json(response))
}

fn jni_events_response(trace_dir: std::path::PathBuf, q: JniEventsQuery) -> JniEventsResponse {
    let path = trace_dir.join("jni_hooks.jsonl");
    let limit = q.limit.min(MAX_LIMIT);
    let mut count = 0usize;
    let mut events = Vec::new();
    if let Ok(file) = std::fs::File::open(path) {
        let reader = std::io::BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let Ok(value) = serde_json::from_str::<Value>(&line) else {
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
            count += 1;
            if events.len() < limit {
                events.push(value);
            }
        }
    }
    let returned = events.len();
    JniEventsResponse {
        count,
        returned,
        truncated: returned < count,
        events,
    }
}
