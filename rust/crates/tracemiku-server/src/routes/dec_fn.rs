//! GET /api/dec/fn/{fn_id} — per-fn TraceIR markdown.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use serde_json::json;

use tracemiku_core::function_index::parse_id;
use tracemiku_core::prelude::{
    build_symbol_func_ir_at_indexed, build_symbol_func_ir_indexed, render_func_md,
};

use crate::routes::dec_options::DecFnQuery;
use crate::state::AppState;

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
    let response = tokio::task::spawn_blocking(move || dec_fn_response(&state, fn_id, q))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "dec fn worker failed: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "dec fn worker failed".to_string(),
            )
        })??;
    Ok(Json(response))
}

fn dec_fn_response(
    state: &AppState,
    fn_id: String,
    q: DecFnQuery,
) -> Result<DecFnResponse, (StatusCode, String)> {
    let inner = &state.inner;

    let (src, payload) =
        parse_id(&fn_id).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid fn_id: {e}")))?;
    match src.as_str() {
        "trace" => {
            let opts = q.to_options();
            if opts.uses_cached_default() {
                let fn_ = inner
                    .top_ir()
                    .fn_by_id(&payload)
                    .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such fn {fn_id}")))?;
                let markdown = render_func_md(fn_, &q.tier);
                Ok(DecFnResponse {
                    fn_id,
                    name: fn_.name.clone(),
                    tier: q.tier,
                    markdown,
                })
            } else {
                let top = inner.build_top_ir_with_options(&opts);
                let fn_ = top
                    .fn_by_id(&payload)
                    .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such fn {fn_id}")))?;
                let markdown = render_func_md(fn_, &q.tier);
                Ok(DecFnResponse {
                    fn_id,
                    name: fn_.name.clone(),
                    tier: q.tier,
                    markdown,
                })
            }
        }
        "sym" => {
            let fn_ = build_symbol_func_ir_indexed(
                &inner.trace,
                &inner.symbols,
                &inner.cfg,
                &inner.index,
                &payload,
            )
            .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such sym fn {payload}")))?;
            let markdown = render_func_md(&fn_, &q.tier);
            Ok(DecFnResponse {
                fn_id,
                name: fn_.name,
                tier: q.tier,
                markdown,
            })
        }
        "symaddr" => {
            let pc = parse_u64(&payload)
                .ok_or_else(|| (StatusCode::BAD_REQUEST, format!("invalid symaddr {fn_id}")))?;
            let fn_ = build_symbol_func_ir_at_indexed(
                &inner.trace,
                &inner.symbols,
                &inner.cfg,
                &inner.index,
                pc,
            )
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("no such symaddr fn {payload}"),
                )
            })?;
            let markdown = render_func_md(&fn_, &q.tier);
            Ok(DecFnResponse {
                fn_id,
                name: fn_.name,
                tier: q.tier,
                markdown,
            })
        }
        "bn" => render_bn_hlil_fn(state, &fn_id, &payload, q.tier),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported fn_id source {src}"),
        )),
    }
}

fn render_bn_hlil_fn(
    state: &AppState,
    fn_id: &str,
    payload: &str,
    tier: String,
) -> Result<DecFnResponse, (StatusCode, String)> {
    let pc = parse_u64(payload)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, format!("invalid bn fn id {fn_id}")))?;
    let result = state
        .inner
        .bn_sidecar
        .lock()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .request("hlil_for", json!({"pc": pc}));
    if !result
        .get("ready")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        let err = result
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("BN sidecar is not ready");
        return Err((StatusCode::SERVICE_UNAVAILABLE, err.to_string()));
    }
    if !result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        let err = result
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("BN HLIL request failed");
        return Err((StatusCode::NOT_FOUND, err.to_string()));
    }
    let name = result
        .get("fn")
        .and_then(|f| f.get("name"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("sub_{pc:x}"));
    let mut markdown = format!("# {name}\n\n- id: `{fn_id}`\n- source: `bn-hlil`\n\n```c\n");
    if let Some(lines) = result.get("lines").and_then(|v| v.as_array()) {
        for line in lines {
            if let Some(text) = line.get("text").and_then(|v| v.as_str()) {
                markdown.push_str(text);
                markdown.push('\n');
            }
        }
    }
    markdown.push_str("```\n");
    Ok(DecFnResponse {
        fn_id: fn_id.to_string(),
        name,
        tier,
        markdown,
    })
}

fn parse_u64(s: &str) -> Option<u64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}
