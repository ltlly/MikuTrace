//! GET /api/asm-tokens-for-pcs.

use std::collections::BTreeMap;

use axum::extract::Query;
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct AsmTokensQuery {
    pub pcs: String,
}

#[derive(Debug, Serialize)]
pub struct AsmTokenWire {
    pub t: String,
    pub c: String,
    pub a: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AsmTokensResponse {
    pub ready: bool,
    pub status: &'static str,
    pub tokens: BTreeMap<String, Vec<AsmTokenWire>>,
}

pub async fn asm_tokens_handler(Query(q): Query<AsmTokensQuery>) -> Json<AsmTokensResponse> {
    let _ = q.pcs;
    Json(AsmTokensResponse {
        ready: false,
        status: "not-ready",
        tokens: BTreeMap::new(),
    })
}
