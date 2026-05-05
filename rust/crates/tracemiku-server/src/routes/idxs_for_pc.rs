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

const MAX_IDXS_FOR_PC_RETURNED: usize = 5_000;

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

fn effective_limit(raw: usize) -> usize {
    raw.min(MAX_IDXS_FOR_PC_RETURNED)
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

    let n = state.inner.trace.len();
    let cursor = q.cursor.min(n);
    let all = state
        .inner
        .index
        .pc_to_idxs
        .get(&target)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let cut = all.partition_point(|&idx| idx < cursor);
    let total_before = cut;
    let total_after = all.len().saturating_sub(cut);
    let limit = effective_limit(q.limit);
    let before_capped = total_before > limit;
    let after_capped = total_after > limit;

    // before: closest-to-cursor first (descending), capped at limit.
    let before = all[..cut].iter().rev().take(limit).copied().collect();
    let after = all[cut..].iter().take(limit).copied().collect();

    Json(IdxsForPcResponse {
        status: "ready",
        pc: q.pc,
        cursor: q.cursor,
        before,
        after,
        total_before,
        total_after,
        before_capped,
        after_capped,
    })
}

#[cfg(test)]
mod tests {
    use super::{effective_limit, MAX_IDXS_FOR_PC_RETURNED};

    #[test]
    fn effective_limit_caps_extreme_requests() {
        assert_eq!(effective_limit(0), 0);
        assert_eq!(effective_limit(60), 60);
        assert_eq!(effective_limit(usize::MAX), MAX_IDXS_FOR_PC_RETURNED);
    }
}
