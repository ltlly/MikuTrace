//! GET /api/search-pc?pc=&limit=.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

const MAX_SEARCH_PC_IDXS: usize = 50_000;

#[derive(Debug, Deserialize)]
pub struct SearchPcQuery {
    pub pc: String,
    #[serde(default)]
    pub limit: usize,
}

fn effective_limit(raw: usize) -> usize {
    if raw == 0 {
        MAX_SEARCH_PC_IDXS
    } else {
        raw.min(MAX_SEARCH_PC_IDXS)
    }
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
    let effective_limit = effective_limit(q.limit);
    let idxs = all
        .iter()
        .copied()
        .take(effective_limit)
        .collect::<Vec<_>>();
    Ok(Json(SearchPcResponse {
        pc: format!("{target:#x}"),
        count,
        idxs,
        truncated: count > effective_limit,
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

#[cfg(test)]
mod tests {
    use super::{effective_limit, MAX_SEARCH_PC_IDXS};

    #[test]
    fn effective_limit_caps_default_and_extreme_requests() {
        assert_eq!(effective_limit(0), MAX_SEARCH_PC_IDXS);
        assert_eq!(effective_limit(60), 60);
        assert_eq!(effective_limit(usize::MAX), MAX_SEARCH_PC_IDXS);
    }
}
