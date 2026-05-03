//! GET /api/idxs-for-block?pc=&max_count=
//!
//! Returns record indices whose PC falls within the block whose start_pc
//! equals the input. Linear pc-scan; precomputed pc→block map deferred to
//! M2-ε.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct IdxsForBlockQuery {
    pub pc: String,
    #[serde(default = "default_max")]
    pub max_count: usize,
}

fn default_max() -> usize {
    200
}

#[derive(Debug, Serialize)]
pub struct IdxsForBlockResponse {
    pub status: &'static str,
    pub idxs: Vec<usize>,
}

pub async fn idxs_for_block_handler(
    State(state): State<AppState>,
    Query(q): Query<IdxsForBlockQuery>,
) -> Result<Json<IdxsForBlockResponse>, StatusCode> {
    let target = u64::from_str_radix(q.pc.trim_start_matches("0x"), 16).unwrap_or(0);
    let inner = &state.inner;
    let cfg = &inner.cfg;
    let trace = &inner.trace;

    let block = cfg.block(target).ok_or(StatusCode::NOT_FOUND)?;
    let start = block.start_pc;
    let end = block.end_pc;

    let n = trace.len();
    let mut idxs = Vec::new();
    for i in 0..n {
        if idxs.len() >= q.max_count {
            break;
        }
        let pc = trace.pc(i);
        if pc >= start && pc <= end {
            idxs.push(i);
        }
    }

    Ok(Json(IdxsForBlockResponse {
        status: "ready",
        idxs,
    }))
}
