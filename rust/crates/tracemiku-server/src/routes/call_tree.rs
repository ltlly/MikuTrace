//! GET /api/call-tree — nested call tree (bl/ret pair-walked).

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::{build_call_tree_indexed, CallNode};

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
) -> Json<CallTreeResponse> {
    let inner = state.inner.clone();
    let depth = effective_max_depth(q.max_depth);
    let tree = tokio::task::spawn_blocking(move || inner.call_tree_for_depth(depth))
        .await
        .unwrap_or_else(|err| {
            tracing::warn!(target: "tracemiku-server", "call tree worker failed: {err}");
            build_call_tree_indexed(
                &state.inner.trace,
                &state.inner.symbols,
                &state.inner.index,
                0,
            )
        });
    Json(CallTreeResponse { tree })
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
