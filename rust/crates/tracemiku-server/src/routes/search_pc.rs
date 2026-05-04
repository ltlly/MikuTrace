//! GET /api/search-pc?pc=&limit=.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct SearchPcQuery {
    pub pc: String,
    #[serde(default)]
    pub limit: usize,
}

#[derive(Debug, Serialize)]
pub struct SearchPcResponse {
    pub pc: String,
    pub count: usize,
    pub idxs: Vec<usize>,
    pub truncated: bool,
}

pub async fn search_pc_handler(
    State(state): State<AppState>,
    Query(q): Query<SearchPcQuery>,
) -> Result<Json<SearchPcResponse>, StatusCode> {
    let target = parse_int(&q.pc).ok_or(StatusCode::BAD_REQUEST)?;
    let all = state
        .inner
        .index
        .pc_to_idxs
        .get(&target)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let count = all.len();
    let idxs = if q.limit == 0 {
        all.to_vec()
    } else {
        all.iter().copied().take(q.limit).collect()
    };
    Ok(Json(SearchPcResponse {
        pc: format!("{target:#x}"),
        count,
        idxs,
        truncated: q.limit > 0 && count > q.limit,
    }))
}

fn parse_int(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}
