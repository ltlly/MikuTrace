//! GET /api/reg-value-at?idx=&reg=
//! GET /api/reg-at-idx?idx=&reg=

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RegValueAtQuery {
    pub idx: usize,
    pub reg: String,
}

#[derive(Debug, Serialize)]
pub struct RegValueAtResponse {
    pub status: String,
    pub idx: usize,
    pub reg: String,
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn reg_value_at_handler(
    State(state): State<AppState>,
    Query(q): Query<RegValueAtQuery>,
) -> Json<RegValueAtResponse> {
    let inner = &state.inner;
    if q.idx >= inner.trace.len() {
        return Json(RegValueAtResponse {
            status: "error".to_string(),
            idx: q.idx,
            reg: q.reg,
            value: None,
            error: Some("idx out of range".to_string()),
        });
    }
    let record = inner.trace.record(q.idx);
    let value = record.reg_by_name(&q.reg).map(|v| format!("{v:#x}"));
    if let Some(value) = value {
        Json(RegValueAtResponse {
            status: "ready".to_string(),
            idx: q.idx,
            reg: q.reg,
            value: Some(value),
            error: None,
        })
    } else {
        Json(RegValueAtResponse {
            status: "error".to_string(),
            idx: q.idx,
            reg: q.reg,
            value: None,
            error: Some("unknown register".to_string()),
        })
    }
}
