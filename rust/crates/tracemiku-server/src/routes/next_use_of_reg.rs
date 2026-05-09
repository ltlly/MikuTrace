//! GET /api/next-use-of-reg?reg=&after=
//!
//! Returns the smallest record index > `after` that uses `reg`,
//! or null if no such index exists.
//! `value` is the pre-execution snapshot at the use index, i.e. the value read.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use tracemiku_core::disasm::normalize_disasm_reg;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NextUseQuery {
    pub reg: String,
    pub after: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct NextUseResponse {
    pub status: &'static str,
    pub idx: Option<usize>,
    pub value: Option<String>,
}

pub async fn next_use_of_reg_handler(
    State(state): State<AppState>,
    Query(q): Query<NextUseQuery>,
) -> Json<NextUseResponse> {
    let after = q.after.unwrap_or(0);
    let canon = normalize_disasm_reg(&q.reg);
    let reg = if canon.is_empty() { q.reg } else { canon };
    let idx = state.inner.index.next_use_after(&reg, after);
    let value = idx.and_then(|use_idx| {
        (use_idx < state.inner.trace.len())
            .then(|| state.inner.trace.record(use_idx).reg_by_name(&reg))
            .flatten()
            .map(|v| format!("{v:#x}"))
    });
    Json(NextUseResponse {
        status: "ready",
        idx,
        value,
    })
}
