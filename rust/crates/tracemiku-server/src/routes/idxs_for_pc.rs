//! GET /api/idxs-for-pc?pc=&cursor=&limit=
//!
//! Returns the set of record indices whose PC equals the target, partitioned
//! around `cursor` into `before` (descending, closest-to-cursor first) and
//! `after` (ascending). Each partition is capped at `limit`; the unbounded
//! totals are returned alongside as `total_before` / `total_after` plus
//! `*_capped` booleans.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct IdxsForPcQuery {
    pub pc: String,
    #[serde(default = "default_cursor")]
    pub cursor: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_cursor() -> usize {
    0
}
fn default_limit() -> usize {
    30
}

#[derive(Debug, Serialize)]
pub struct IdxsForPcResponse {
    pub status: &'static str,
    pub pc: String,
    pub cursor: usize,
    pub before: Vec<usize>,
    pub after: Vec<usize>,
    pub total_before: usize,
    pub total_after: usize,
    pub before_capped: bool,
    pub after_capped: bool,
}

pub async fn idxs_for_pc_handler(
    State(state): State<AppState>,
    Query(q): Query<IdxsForPcQuery>,
) -> Json<IdxsForPcResponse> {
    let target = u64::from_str_radix(q.pc.trim_start_matches("0x"), 16).unwrap_or(0);

    let trace = &state.inner.trace;
    let n = trace.len();
    let cursor = q.cursor.min(n);

    let mut before_all: Vec<usize> = Vec::new();
    let mut after_all: Vec<usize> = Vec::new();
    for i in 0..n {
        if trace.pc(i) != target {
            continue;
        }
        if i < cursor {
            before_all.push(i);
        } else {
            after_all.push(i);
        }
    }

    let total_before = before_all.len();
    let total_after = after_all.len();
    let before_capped = total_before > q.limit;
    let after_capped = total_after > q.limit;

    // before: closest-to-cursor first (descending), capped at limit.
    before_all.reverse();
    before_all.truncate(q.limit);
    after_all.truncate(q.limit);

    Json(IdxsForPcResponse {
        status: "ready",
        pc: q.pc,
        cursor: q.cursor,
        before: before_all,
        after: after_all,
        total_before,
        total_after,
        before_capped,
        after_capped,
    })
}
