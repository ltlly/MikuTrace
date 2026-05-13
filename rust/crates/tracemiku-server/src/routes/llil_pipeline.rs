//! POST /api/llil/pipeline — full LLIL→MLIL→HLIL decompiler pipeline.
//!
//! Returns all three layers plus pipeline stats.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::decompiler::il_pipeline::decompile_trace;
use tracemiku_core::function_index::parse_id;
use tracemiku_core::prelude::FuncIR;

use crate::state::AppState;

const MAX_PIPELINE_RECORDS: usize = 5_000;

#[derive(Debug, Deserialize)]
pub struct LlilPipelinePayload {
    #[serde(default = "default_fn_id")]
    pub fn_id: String,
    #[serde(default = "default_max_records")]
    pub max_records: usize,
    #[serde(default)]
    pub include_text: bool,
}

fn default_fn_id() -> String {
    "trace:F0".to_string()
}

fn default_max_records() -> usize {
    500
}

fn effective_max_records(raw: usize) -> usize {
    raw.clamp(1, MAX_PIPELINE_RECORDS)
}

#[derive(Debug, Serialize)]
pub struct PipelineResponse {
    pub fn_id: String,
    pub name: String,
    pub records: usize,
    pub truncated: bool,
    pub unique_pcs: usize,
    // LLIL stats
    pub llil_count: usize,
    pub llil_coverage: f64,
    // MLIL stats
    pub mlil_count: usize,
    pub struct_loads: u64,
    pub struct_stores: u64,
    // HLIL stats
    pub hlil_count: usize,
    // Text output (only when include_text=true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llil_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mlil_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hlil_text: Option<String>,
}

pub async fn llil_pipeline_handler(
    State(state): State<AppState>,
    Json(payload): Json<LlilPipelinePayload>,
) -> Result<Json<PipelineResponse>, (StatusCode, String)> {
    let response = tokio::task::spawn_blocking(move || pipeline_response(&state, payload))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "pipeline worker failed: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "pipeline worker failed".to_string(),
            )
        })??;
    Ok(Json(response))
}

fn pipeline_response(
    state: &AppState,
    payload: LlilPipelinePayload,
) -> Result<PipelineResponse, (StatusCode, String)> {
    let fn_ = resolve_fn(state, &payload.fn_id)?;
    let inner = &state.inner;
    let max_records = effective_max_records(payload.max_records);

    let trace_len = inner.trace.len();
    let start = fn_.entry_idx.min(trace_len);
    let end = fn_.exit_idx.min(trace_len.saturating_sub(1));

    // Collect unique (pc, inst) pairs from the function's trace range
    let mut seen = std::collections::BTreeSet::new();
    let mut insns: Vec<(u64, u32)> = Vec::new();

    if start <= end {
        for idx in start..=end {
            if insns.len() >= max_records {
                break;
            }
            let rec = inner.trace.record(idx);
            if seen.insert((rec.pc, rec.inst)) {
                insns.push((rec.pc, rec.inst));
            }
        }
    }
    let unique_pcs = seen.len();
    let records_consumed = if start <= end {
        (end - start + 1).min(max_records)
    } else {
        0
    };
    let truncated = start <= end && (end - start + 1) > max_records;

    // Run the full three-layer pipeline
    let output = decompile_trace(&insns, &[], &fn_.name);

    let mlil_stats = output.mlil_lower_stats;

    Ok(PipelineResponse {
        fn_id: payload.fn_id,
        name: fn_.name,
        records: records_consumed,
        truncated,
        unique_pcs,
        llil_count: output.llil_count,
        llil_coverage: output.llil_coverage,
        mlil_count: output.mlil_count,
        struct_loads: mlil_stats.struct_loads as u64,
        struct_stores: mlil_stats.struct_stores as u64,
        hlil_count: output.hlil_count,
        llil_text: if payload.include_text {
            Some(output.llil_ssa_text)
        } else {
            None
        },
        mlil_text: if payload.include_text {
            Some(output.mlil_text)
        } else {
            None
        },
        hlil_text: if payload.include_text {
            Some(output.hlil_text)
        } else {
            None
        },
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
        "sym" => tracemiku_core::prelude::build_symbol_func_ir_indexed(
            &inner.trace,
            &inner.symbols,
            &inner.cfg,
            &inner.index,
            &payload,
        )
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such sym fn {payload}"))),
        "symaddr" => {
            let pc = parse_u64(&payload)
                .ok_or_else(|| (StatusCode::BAD_REQUEST, format!("invalid symaddr {fn_id}")))?;
            tracemiku_core::prelude::build_symbol_func_ir_at_indexed(
                &inner.trace,
                &inner.symbols,
                &inner.cfg,
                &inner.index,
                pc,
            )
            .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such symaddr fn {payload}")))
        }
        "bn" => Err((
            StatusCode::NOT_FOUND,
            "bn:* pipeline is deferred until the Rust BN backend lands".into(),
        )),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported fn_id source {src}"),
        )),
    }
}

fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}
