//! GET /api/asm-tokens-for-pcs.

use crate::routes::seed_resolver::parse_u64;
use std::collections::BTreeMap;

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AsmTokensQuery {
    pub pcs: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AsmTokenWire {
    pub t: String,
    pub c: String,
    pub a: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AsmTokensResponse {
    pub ready: bool,
    pub status: String,
    pub tokens: BTreeMap<String, Vec<AsmTokenWire>>,
    pub error: Option<String>,
}

pub async fn asm_tokens_handler(
    State(state): State<AppState>,
    Query(q): Query<AsmTokensQuery>,
) -> Json<AsmTokensResponse> {
    let pcs: Vec<u64> = q.pcs.split(',').filter_map(parse_u64).take(512).collect();
    if pcs.is_empty() {
        return Json(AsmTokensResponse {
            ready: true,
            status: "ok".to_string(),
            tokens: BTreeMap::new(),
            error: None,
        });
    }
    let value = tokio::task::spawn_blocking(move || request_sidecar_tokens(state, &pcs))
        .await
        .unwrap_or_else(|err| json!({"ok": false, "ready": false, "error": err.to_string()}));

    let ready = value
        .get("ready")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ok = value.get("ok").and_then(|v| v.as_bool()).unwrap_or(ready);
    if !ready || !ok {
        return Json(AsmTokensResponse {
            ready: false,
            status: value
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("not-ready")
                .to_string(),
            tokens: BTreeMap::new(),
            error: value
                .get("error")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        });
    }

    let mut tokens = BTreeMap::new();
    if let Some(obj) = value.get("tokens").and_then(|v| v.as_object()) {
        for (pc, raw_tokens) in obj {
            if let Ok(items) = serde_json::from_value::<Vec<AsmTokenWire>>(raw_tokens.clone()) {
                tokens.insert(pc.to_lowercase(), items);
            }
        }
    }
    Json(AsmTokensResponse {
        ready: true,
        status: "ok".to_string(),
        tokens,
        error: None,
    })
}

fn request_sidecar_tokens(state: AppState, pcs: &[u64]) -> Value {
    match state.inner.bn_sidecar.lock() {
        Ok(mut sidecar) => sidecar.request("asm_tokens", json!({"pcs": pcs})),
        Err(e) => json!({"ok": false, "ready": false, "error": e.to_string()}),
    }
}
