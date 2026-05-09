//! GET /api/last-write-of-reg?reg=&before=
//!
//! Returns the largest record index < `before` that defines `reg`,
//! or null if no such index exists.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use tracemiku_core::disasm::normalize_disasm_reg;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LastWriteQuery {
    pub reg: String,
    pub before: Option<usize>,
    pub cursor: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct LastWriteResponse {
    pub status: &'static str,
    pub idx: Option<usize>,
    pub value: Option<String>,
}

pub async fn last_write_of_reg_handler(
    State(state): State<AppState>,
    Query(q): Query<LastWriteQuery>,
) -> Json<LastWriteResponse> {
    let before = q
        .before
        .or(q.cursor)
        .unwrap_or_else(|| state.inner.trace.len());
    let canon = normalize_disasm_reg(&q.reg);
    let reg = if canon.is_empty() { q.reg } else { canon };
    let idx = state.inner.index.last_def_before(&reg, before);
    let value = if before < state.inner.trace.len() {
        state
            .inner
            .trace
            .record(before)
            .reg_by_name(&reg)
            .map(|v| format!("{v:#x}"))
    } else {
        None
    };
    Json(LastWriteResponse {
        status: "ready",
        idx,
        value,
    })
}
