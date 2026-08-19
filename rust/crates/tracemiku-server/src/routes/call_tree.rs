//! GET /api/call-tree — nested call tree (bl/ret pair-walked).

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::CallNode;

use crate::routes::worker_panic_response;
use crate::state::AppState;

const DEFAULT_MAX_DEPTH: usize = 50;
const MAX_CALL_TREE_DEPTH: usize = 256;

#[derive(Debug, Deserialize)]
pub struct CallTreeQuery {
    pub max_depth: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct CallTreeResponse {
    pub tree: CallNode,
}

fn effective_max_depth(raw: Option<usize>) -> usize {
    raw.unwrap_or(DEFAULT_MAX_DEPTH).min(MAX_CALL_TREE_DEPTH)
}

pub async fn call_tree_handler(
    State(state): State<AppState>,
    Query(q): Query<CallTreeQuery>,
) -> Result<Json<CallTreeResponse>, (StatusCode, Json<serde_json::Value>)> {
    let inner = state.inner.clone();
    let depth = effective_max_depth(q.max_depth);
    let tree = tokio::task::spawn_blocking(move || inner.call_tree_for_depth(depth))
        .await
        .map_err(|err| worker_panic_response("call tree", &err))?;
    Ok(Json(CallTreeResponse { tree }))
}

#[cfg(test)]
mod tests {
    use super::{effective_max_depth, DEFAULT_MAX_DEPTH, MAX_CALL_TREE_DEPTH};

    #[test]
    fn effective_max_depth_caps_extreme_requests() {
        assert_eq!(effective_max_depth(None), DEFAULT_MAX_DEPTH);
        assert_eq!(effective_max_depth(Some(0)), 0);
        assert_eq!(effective_max_depth(Some(5)), 5);
        assert_eq!(effective_max_depth(Some(usize::MAX)), MAX_CALL_TREE_DEPTH);
    }
}
