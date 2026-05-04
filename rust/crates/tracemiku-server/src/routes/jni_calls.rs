//! GET /api/jni-calls.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::jni_scan::JniCallRecord;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct JniCallsQuery {
    pub in_fn: Option<String>,
    #[serde(default = "default_max")]
    pub max: usize,
}

fn default_max() -> usize {
    200
}

#[derive(Debug, Clone, Serialize)]
pub struct JniCallHit {
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub func: Option<String>,
    pub jni_fn: String,
    pub vtable_offset: String,
    pub args: HashMap<&'static str, String>,
}

#[derive(Debug, Serialize)]
pub struct JniCallsResponse {
    pub in_fn: Option<String>,
    pub count: usize,
    pub hits: Vec<JniCallHit>,
    pub vtable_size: usize,
}

pub async fn jni_calls_handler(
    State(state): State<AppState>,
    Query(q): Query<JniCallsQuery>,
) -> Json<JniCallsResponse> {
    Json(
        tokio::task::spawn_blocking(move || {
            let scan = state.inner.jni_calls();
            let mut hits = Vec::new();
            for call in &scan.calls {
                if q.in_fn
                    .as_deref()
                    .is_some_and(|want| call.func_name.as_str() != want)
                {
                    continue;
                }
                hits.push(jni_call_hit(call));
                if q.max > 0 && hits.len() >= q.max {
                    break;
                }
            }
            JniCallsResponse {
                in_fn: q.in_fn,
                count: hits.len(),
                hits,
                vtable_size: scan.vtable_size,
            }
        })
        .await
        .unwrap_or_else(|err| {
            tracing::warn!(target: "tracemiku-server", "jni calls worker failed: {err}");
            JniCallsResponse {
                in_fn: None,
                count: 0,
                hits: Vec::new(),
                vtable_size: 0,
            }
        }),
    )
}

fn jni_call_hit(call: &JniCallRecord) -> JniCallHit {
    JniCallHit {
        idx: call.idx,
        pc: format!("{:#x}", call.pc),
        rel: call.rel.map(|rel| format!("{rel:#x}")),
        func: call.func_display(),
        jni_fn: call.jni_fn.clone(),
        vtable_offset: format!("{:#x}", call.vtable_offset),
        args: call.args_map(),
    }
}
