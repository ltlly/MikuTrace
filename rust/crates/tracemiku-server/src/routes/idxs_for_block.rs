//! GET /api/idxs-for-block?pc=&max_count=&near=
//!
//! Returns record indices whose PC falls within the block whose start_pc
//! equals the input. Uses the global pc→idxs index and walks only instruction
//! PCs inside the block, avoiding an O(trace records) scan on large traces.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use tracemiku_core::prelude::parse_address;

use crate::state::AppState;

const MAX_IDXS_FOR_BLOCK_RETURNED: usize = 5_000;

#[derive(Debug, Deserialize)]
pub struct IdxsForBlockQuery {
    pub pc: String,
    #[serde(default = "default_max")]
    pub max_count: usize,
    #[serde(default = "default_near")]
    pub near: isize,
}

fn default_max() -> usize {
    200
}
fn default_near() -> isize {
    -1
}

fn effective_max_count(raw: usize) -> usize {
    raw.min(MAX_IDXS_FOR_BLOCK_RETURNED)
}

#[derive(Debug, Serialize)]
pub struct IdxsForBlockResponse {
    pub status: &'static str,
    pub block: String,
    pub idxs: Vec<usize>,
    pub truncated: bool,
    pub total: usize,
}

pub async fn idxs_for_block_handler(
    State(state): State<AppState>,
    Query(q): Query<IdxsForBlockQuery>,
) -> Result<Json<IdxsForBlockResponse>, StatusCode> {
    let inner = state.inner.clone();
    let response = tokio::task::spawn_blocking(move || idxs_for_block_response(&inner, q))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "idxs-for-block worker failed: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })??;
    Ok(Json(response))
}

fn idxs_for_block_response(
    inner: &crate::state::AppStateInner,
    q: IdxsForBlockQuery,
) -> Result<IdxsForBlockResponse, StatusCode> {
    // Parse via the shared core parser: an invalid `pc` surfaces as a distinct
    // 400 Bad Request instead of silently resolving to 0 and 404-ing on a
    // block that never existed (audit P0-1).
    let target = parse_address(&q.pc).map_err(|_| StatusCode::BAD_REQUEST)?;
    let cfg = &inner.cfg;

    let block = cfg.block(target).ok_or(StatusCode::NOT_FOUND)?;
    let start = block.start_pc;
    let end = block.end_pc;

    let mut idxs = Vec::new();
    let mut pc = start;
    loop {
        if let Some(hit_idxs) = inner.index.pc_to_idxs.get(&pc) {
            idxs.extend(hit_idxs.iter().copied());
        }
        if end.saturating_sub(pc) < 4 {
            break;
        }
        pc = pc.saturating_add(4);
    }
    idxs.sort_unstable();

    let total = idxs.len();
    let max_count = effective_max_count(q.max_count);
    let truncated = total > max_count;
    if truncated {
        if q.near >= 0 {
            let near = q.near as usize;
            idxs.sort_unstable_by_key(|idx| idx.abs_diff(near));
            idxs.truncate(max_count);
            idxs.sort_unstable();
        } else {
            idxs.truncate(max_count);
        }
    }

    Ok(IdxsForBlockResponse {
        status: "ready",
        block: format!("{start:#x}"),
        idxs,
        truncated,
        total,
    })
}

#[cfg(test)]
mod tests {
    use super::{effective_max_count, MAX_IDXS_FOR_BLOCK_RETURNED};

    #[test]
    fn effective_max_count_caps_extreme_requests() {
        assert_eq!(effective_max_count(0), 0);
        assert_eq!(effective_max_count(200), 200);
        assert_eq!(effective_max_count(usize::MAX), MAX_IDXS_FOR_BLOCK_RETURNED);
    }
}
