//! GET /api/call-tree — nested call tree (bl/ret pair-walked).

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::{build_call_tree_indexed, CallNode};

use crate::state::AppState;

const DEFAULT_MAX_DEPTH: usize = 50;

#[derive(Debug, Deserialize)]
pub struct CallTreeQuery {
    pub max_depth: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct CallTreeResponse {
    pub tree: CallNode,
}

pub async fn call_tree_handler(
    State(state): State<AppState>,
    Query(q): Query<CallTreeQuery>,
) -> Json<CallTreeResponse> {
    let inner = state.inner.clone();
    let depth = q.max_depth.unwrap_or(DEFAULT_MAX_DEPTH);
    let tree = tokio::task::spawn_blocking(move || {
        if depth == DEFAULT_MAX_DEPTH {
            inner.call_tree().clone()
        } else {
            build_call_tree_indexed(&inner.trace, &inner.symbols, &inner.index, depth)
        }
    })
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
