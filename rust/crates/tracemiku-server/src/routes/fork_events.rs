//! GET /api/fork-events?status=

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ForkEventsQuery {
    pub status: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ForkEventsResponse {
    pub count: usize,
    pub events: Vec<serde_json::Value>,
}

pub async fn fork_events_handler(
    State(state): State<AppState>,
    Query(q): Query<ForkEventsQuery>,
) -> Json<ForkEventsResponse> {
    let events: Vec<serde_json::Value> = state
        .inner
        .meta
        .fork_events
        .iter()
        .filter(|ev| match q.status.as_deref() {
            Some(status) => ev
                .get("attach_status")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s == status),
            None => true,
        })
        .cloned()
        .collect();
    Json(ForkEventsResponse {
        count: events.len(),
        events,
    })
}
