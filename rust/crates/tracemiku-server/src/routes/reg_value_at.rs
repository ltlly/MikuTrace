//! GET /api/reg-value-at?idx=&reg=
//! GET /api/reg-at-idx?idx=&reg=

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;
use tracemiku_core::disasm::normalize_disasm_reg;

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
    pub annotation: Option<String>,
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
            annotation: None,
            error: Some("idx out of range".to_string()),
        });
    }
    let record = inner.trace.record(q.idx);
    let canon = normalize_disasm_reg(&q.reg);
    let reg = if canon.is_empty() { q.reg } else { canon };
    let raw_value = record.reg_by_name(&reg);
    if let Some(v) = raw_value {
        let annotation = if reg == "xzr" {
            None
        } else {
            let annotation = crate::routes::record::classify_reg_value(
                inner,
                inner.memshadow_if_ready(),
                v,
                q.idx,
                record.reg_by_name("sp").unwrap_or(0),
            );
            (!annotation.is_empty()).then_some(annotation)
        };
        Json(RegValueAtResponse {
            status: "ready".to_string(),
            idx: q.idx,
            reg,
            value: Some(format!("{v:#x}")),
            annotation,
            error: None,
        })
    } else {
        Json(RegValueAtResponse {
            status: "error".to_string(),
            idx: q.idx,
            reg,
            value: None,
            annotation: None,
            error: Some("unknown register".to_string()),
        })
    }
}
