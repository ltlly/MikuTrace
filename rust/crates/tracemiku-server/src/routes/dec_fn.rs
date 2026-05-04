//! GET /api/dec/fn/{fn_id} — per-fn TraceIR markdown.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use tracemiku_core::function_index::parse_id;
use tracemiku_core::prelude::{build_symbol_func_ir, render_func_md};

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

    let (src, payload) =
        parse_id(&fn_id).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid fn_id: {e}")))?;
    match src.as_str() {
        "trace" => {
            let fn_ = inner
                .top_ir
                .fn_by_id(&payload)
                .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such fn {fn_id}")))?;
            let markdown = render_func_md(fn_, &q.tier);
            Ok(Json(DecFnResponse {
                fn_id,
                name: fn_.name.clone(),
                tier: q.tier,
                markdown,
            }))
        }
        "sym" => {
            let fn_ = build_symbol_func_ir(&inner.trace, &inner.symbols, &inner.cfg, &payload)
                .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such sym fn {payload}")))?;
            let markdown = render_func_md(&fn_, &q.tier);
            Ok(Json(DecFnResponse {
                fn_id,
                name: fn_.name,
                tier: q.tier,
                markdown,
            }))
        }
        "bn" => Err((
            StatusCode::NOT_FOUND,
            "bn:* dec_fn support is deferred until the Rust BN backend lands".to_string(),
        )),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported fn_id source {src}"),
        )),
    }
}
