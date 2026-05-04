//! Binary Ninja sidecar-backed HLIL and static CFG endpoints.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use tracemiku_core::function_index::parse_id;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct PcQuery {
    pub pc: String,
}

#[derive(Debug, Deserialize)]
pub struct FnQuery {
    pub fn_id: String,
}

pub async fn bn_sidecar_status_handler(State(state): State<AppState>) -> Json<Value> {
    let status = state
        .inner
        .bn_sidecar
        .lock()
        .map(|sidecar| sidecar.status())
        .unwrap_or_else(|e| json!({"ready": false, "configured": false, "error": e.to_string()}));
    Json(status)
}

pub async fn hlil_for_pc_handler(
    State(state): State<AppState>,
    Query(q): Query<PcQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let pc = parse_u64(&q.pc).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid pc, expected decimal or hex: {}", q.pc),
        )
    })?;
    Ok(Json(request_sidecar(&state, "hlil_for", json!({"pc": pc}))))
}

pub async fn hlil_for_fn_handler(
    State(state): State<AppState>,
    Query(q): Query<FnQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let pc = resolve_fn_pc(&state, &q.fn_id)?;
    Ok(Json(request_sidecar(&state, "hlil_for", json!({"pc": pc}))))
}

pub async fn bn_cfg_for_pc_handler(
    State(state): State<AppState>,
    Query(q): Query<PcQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let pc = parse_u64(&q.pc).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid pc, expected decimal or hex: {}", q.pc),
        )
    })?;
    Ok(Json(request_sidecar(&state, "cfg_for", json!({"pc": pc}))))
}

pub async fn bn_cfg_svg_for_pc_handler(
    State(state): State<AppState>,
    Query(q): Query<PcQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let pc = parse_u64(&q.pc).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid pc, expected decimal or hex: {}", q.pc),
        )
    })?;
    let cfg = request_sidecar(&state, "cfg_for", json!({"pc": pc}));
    Ok(Json(json!({
        "ok": cfg.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
        "ready": cfg.get("ready").and_then(|v| v.as_bool()).unwrap_or(false),
        "svg": cfg.get("svg").and_then(|v| v.as_str()).unwrap_or(""),
        "error": cfg.get("error").cloned().unwrap_or(Value::Null),
    })))
}

fn request_sidecar(state: &AppState, method: &str, params: Value) -> Value {
    match state.inner.bn_sidecar.lock() {
        Ok(mut sidecar) => sidecar.request(method, params),
        Err(e) => json!({"ok": false, "ready": false, "error": e.to_string()}),
    }
}

fn resolve_fn_pc(state: &AppState, fn_id: &str) -> Result<u64, (StatusCode, String)> {
    let (src, payload) =
        parse_id(fn_id).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid fn_id: {e}")))?;
    match src.as_str() {
        "trace" => state
            .inner
            .top_ir()
            .fn_by_id(&payload)
            .map(|f| f.pc_start)
            .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such trace fn {fn_id}"))),
        "sym" => state
            .inner
            .function_index
            .by_id(fn_id)
            .and_then(|f| f.entry_pc)
            .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such sym fn {payload}"))),
        "bn" => parse_u64(&payload)
            .ok_or_else(|| (StatusCode::BAD_REQUEST, format!("invalid bn fn id {fn_id}"))),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported fn_id source {src}"),
        )),
    }
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
