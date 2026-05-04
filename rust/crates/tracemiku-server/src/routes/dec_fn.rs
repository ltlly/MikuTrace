//! GET /api/dec/fn/{fn_id} — per-fn TraceIR markdown.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::function_index::parse_id;
use tracemiku_core::prelude::render_func_md;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct DecFnQuery {
    #[serde(default = "default_tier")]
    pub tier: String,
}

fn default_tier() -> String {
    "hot".to_string()
}

#[derive(Debug, Serialize)]
pub struct DecFnResponse {
    pub fn_id: String,
    pub name: String,
    pub tier: String,
    pub markdown: String,
}

pub async fn dec_fn_handler(
    State(state): State<AppState>,
    Path(fn_id): Path<String>,
    Query(q): Query<DecFnQuery>,
) -> Result<Json<DecFnResponse>, (StatusCode, String)> {
    let inner = &state.inner;

    // Resolve fn_id to a FuncIR. Accept trace:F0, bare F0, sym:<name>,
    // bn:<addr>, cfg:<name> via parse_id legacy-alias path. M3-θ
    // supports trace:* only — sym/bn fall back to 404 (M3-ι could
    // wire those by looking up in FunctionIndex / building on demand).
    let (src, payload) = parse_id(&fn_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid fn_id: {e}")))?;
    if src != "trace" {
        return Err((
            StatusCode::NOT_FOUND,
            format!(
                "fn_id {fn_id} (source={src}) not yet supported by /api/dec/fn — only trace:* in M3-θ"
            ),
        ));
    }
    let fn_ = inner
        .top_ir
        .fn_by_id(&payload)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such fn {fn_id}")))?;

    let markdown = render_func_md(fn_, &q.tier);

    Ok(Json(DecFnResponse {
        fn_id: fn_id.clone(),
        name: fn_.name.clone(),
        tier: q.tier,
        markdown,
    }))
}
