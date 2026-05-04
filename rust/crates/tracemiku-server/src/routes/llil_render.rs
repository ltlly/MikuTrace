//! POST /api/llil/render — Rust LLIL pipeline preview.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::function_index::parse_id;
use tracemiku_core::prelude::{
    build_symbol_func_ir, constfold_block, dce_block, decode, lift_arm64, render_llil_block,
    ssa_block, FuncIR, LiftStats,
};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LlilRenderPayload {
    #[serde(default = "default_fn_id")]
    pub fn_id: String,
    #[serde(default = "default_max_records")]
    pub max_records: usize,
    #[serde(default = "default_true")]
    pub ssa: bool,
    #[serde(default = "default_true")]
    pub constfold: bool,
    #[serde(default)]
    pub dce: bool,
}

fn default_fn_id() -> String {
    "trace:F0".to_string()
}

fn default_max_records() -> usize {
    300
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct LlilRenderResponse {
    pub fn_id: String,
    pub name: String,
    pub records: usize,
    pub truncated: bool,
    pub lift_total: usize,
    pub lift_intrinsic: usize,
    pub lift_coverage: f64,
    pub removed_pcs: Vec<String>,
    pub pseudocode: String,
}

pub async fn llil_render_handler(
    State(state): State<AppState>,
    Json(payload): Json<LlilRenderPayload>,
) -> Result<Json<LlilRenderResponse>, (StatusCode, String)> {
    let fn_ = resolve_fn(&state, &payload.fn_id)?;
    let inner = &state.inner;
    let max_records = payload.max_records.clamp(1, 10_000);
    let start = fn_.entry_idx.min(inner.trace.len());
    let end = fn_.exit_idx.min(inner.trace.len().saturating_sub(1));

    let mut stats = LiftStats::default();
    let mut exprs = Vec::new();
    let mut record_count = 0usize;
    if start <= end {
        for idx in start..=end {
            if record_count >= max_records {
                break;
            }
            let rec = inner.trace.record(idx);
            let lifted = lift_arm64(rec.pc, rec.inst);
            let decoded = decode(rec.pc, rec.inst);
            stats.record(&decoded, &lifted);
            exprs.extend(lifted);
            record_count += 1;
        }
    }
    let truncated = start <= end && (end - start + 1) > max_records;
    if payload.constfold {
        exprs = constfold_block(&exprs);
    }
    if payload.ssa {
        exprs = ssa_block(&exprs).exprs;
    }
    let removed_pcs = if payload.dce {
        let dce = dce_block(&exprs);
        exprs = dce.exprs;
        dce.removed_pcs
            .into_iter()
            .map(|pc| format!("{pc:#x}"))
            .collect()
    } else {
        Vec::new()
    };
    let pseudocode = render_llil_block(&exprs);

    Ok(Json(LlilRenderResponse {
        fn_id: payload.fn_id,
        name: fn_.name,
        records: record_count,
        truncated,
        lift_total: stats.total,
        lift_intrinsic: stats.intrinsic,
        lift_coverage: stats.coverage(),
        removed_pcs,
        pseudocode,
    }))
}

fn resolve_fn(state: &AppState, fn_id: &str) -> Result<FuncIR, (StatusCode, String)> {
    let inner = &state.inner;
    let (src, payload) =
        parse_id(fn_id).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid fn_id: {e}")))?;
    match src.as_str() {
        "trace" => inner
            .top_ir
            .fn_by_id(&payload)
            .cloned()
            .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such fn {fn_id}"))),
        "sym" => build_symbol_func_ir(&inner.trace, &inner.symbols, &inner.cfg, &payload)
            .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such sym fn {payload}"))),
        "bn" => Err((
            StatusCode::NOT_FOUND,
            "bn:* LLIL render is deferred until the Rust BN backend lands".to_string(),
        )),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported fn_id source {src}"),
        )),
    }
}
