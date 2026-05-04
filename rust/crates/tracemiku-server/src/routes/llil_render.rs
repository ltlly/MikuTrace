//! POST /api/llil/render — Rust LLIL pipeline preview.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::function_index::parse_id;
use tracemiku_core::prelude::{
    build_symbol_func_ir_indexed, collect_uidf_indexed, constfold_block, dce_block, decode,
    flag_elim_block, lift_arm64, render_llil_block, restructure_block, ssa_block,
    struct_recover_block, typelat_block, unify_vars, FuncIR, LiftStats,
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
    #[serde(default = "default_true")]
    pub flag_elim: bool,
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
    pub flag_elim_pairs: Vec<(String, String)>,
    pub types: std::collections::BTreeMap<String, String>,
    pub struct_shapes: serde_json::Value,
    pub var_names: std::collections::BTreeMap<String, String>,
    pub uidf: serde_json::Value,
    pub structured: serde_json::Value,
    pub removed_pcs: Vec<String>,
    pub pseudocode: String,
}

pub async fn llil_render_handler(
    State(state): State<AppState>,
    Json(payload): Json<LlilRenderPayload>,
) -> Result<Json<LlilRenderResponse>, (StatusCode, String)> {
    let response = tokio::task::spawn_blocking(move || render_llil_response(&state, payload))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "llil render worker failed: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "llil render worker failed".to_string(),
            )
        })??;
    Ok(Json(response))
}

pub fn render_llil_response(
    state: &AppState,
    payload: LlilRenderPayload,
) -> Result<LlilRenderResponse, (StatusCode, String)> {
    let fn_ = resolve_fn(state, &payload.fn_id)?;
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
    let flag_elim_pairs = if payload.flag_elim {
        let folded = flag_elim_block(&exprs);
        exprs = folded.exprs;
        folded
            .folded_pairs
            .into_iter()
            .map(|(cmp, br)| (format!("{cmp:#x}"), format!("{br:#x}")))
            .collect()
    } else {
        Vec::new()
    };
    if payload.ssa {
        exprs = ssa_block(&exprs).exprs;
    }
    let types_raw = typelat_block(&exprs);
    let types = types_raw
        .iter()
        .map(|(k, v)| (k.clone(), format!("{v:?}").to_lowercase()))
        .collect();
    let struct_shapes = serde_json::to_value(struct_recover_block(&exprs, &types_raw))
        .unwrap_or_else(|_| serde_json::json!({}));
    let var_names = unify_vars(&exprs);
    let uidf = serde_json::to_value(collect_uidf_indexed(&inner.trace, &inner.index, &exprs, 64))
        .unwrap_or_else(|_| serde_json::json!({}));
    let structured =
        serde_json::to_value(restructure_block(&exprs)).unwrap_or_else(|_| serde_json::json!([]));
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

    Ok(LlilRenderResponse {
        fn_id: payload.fn_id,
        name: fn_.name,
        records: record_count,
        truncated,
        lift_total: stats.total,
        lift_intrinsic: stats.intrinsic,
        lift_coverage: stats.coverage(),
        flag_elim_pairs,
        types,
        struct_shapes,
        var_names,
        uidf,
        structured,
        removed_pcs,
        pseudocode,
    })
}

fn resolve_fn(state: &AppState, fn_id: &str) -> Result<FuncIR, (StatusCode, String)> {
    let inner = &state.inner;
    let (src, payload) =
        parse_id(fn_id).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid fn_id: {e}")))?;
    match src.as_str() {
        "trace" => inner
            .top_ir()
            .fn_by_id(&payload)
            .cloned()
            .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such fn {fn_id}"))),
        "sym" => build_symbol_func_ir_indexed(
            &inner.trace,
            &inner.symbols,
            &inner.cfg,
            &inner.index,
            &payload,
        )
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
