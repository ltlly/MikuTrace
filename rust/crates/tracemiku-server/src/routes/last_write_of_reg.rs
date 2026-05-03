//! GET /api/last-write-of-reg?reg=&before=
//!
//! Returns the largest record index < `before` that defines `reg`,
//! or null if no such index exists.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LastWriteQuery {
    pub reg: String,
    pub before: usize,
}

#[derive(Debug, Serialize)]
pub struct LastWriteResponse {
    pub idx: Option<usize>,
}

pub async fn last_write_of_reg_handler(
    State(state): State<AppState>,
    Query(q): Query<LastWriteQuery>,
) -> Json<LastWriteResponse> {
    let idx = state.inner.index.last_def_before(&q.reg, q.before);
    Json(LastWriteResponse { idx })
}
