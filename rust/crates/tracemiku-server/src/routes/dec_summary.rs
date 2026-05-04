//! GET /api/dec/summary — TraceIR top-level summary.
//!
//! Wire shape mirrors webui/server.py:2756-2773. M3-δ skeleton: only
//! "trace-ir" source entries (no symbol/bn fallback yet); minimal
//! summary_md (Python's render_summary_md fidelity defers to M3-ε).

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use tracemiku_core::prelude::make_trace_id;

use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct DecFnEntry {
    pub id: String,
    pub name: String,
    pub blocks: usize,
    pub loops: usize,
    pub calls: usize,
    pub type_anchors: usize,
    pub entry_idx: Option<usize>,
    pub exit_idx: Option<usize>,
    pub source: &'static str,
    pub trace_ir_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DecSummaryResponse {
    pub records: u64,
    pub module_name: String,
    pub module_base: u64,
    pub module_size: u64,
    pub truncated: bool,
    pub fns: Vec<DecFnEntry>,
    pub vm_candidates: Vec<serde_json::Value>,
    pub summary_md: String,
}

pub async fn dec_summary_handler(State(state): State<AppState>) -> Json<DecSummaryResponse> {
    let inner = &state.inner;
    let top = &inner.top_ir;

    let fns: Vec<DecFnEntry> = top
        .fns
        .iter()
        .map(|f| DecFnEntry {
            id: make_trace_id(&f.id),
            name: f.name.clone(),
            blocks: f.blocks.len(),
            loops: f.loops.len(),
            calls: f.calls.len(),
            type_anchors: f.type_anchors.len(),
            entry_idx: Some(f.entry_idx),
            exit_idx: Some(f.exit_idx),
            source: "trace-ir",
            trace_ir_id: Some(f.id.clone()),
        })
        .collect();

    let mut summary_md = format!(
        "trace: {} records, module={}\n",
        top.records, top.module_name
    );
    for f in &top.fns {
        summary_md.push_str(&format!(
            "  {} {:24} blocks={:<4} loops={:<3} calls={:<3} idx=[{},{}]\n",
            f.id,
            f.name,
            f.blocks.len(),
            f.loops.len(),
            f.calls.len(),
            f.entry_idx,
            f.exit_idx
        ));
    }

    Json(DecSummaryResponse {
        records: top.records,
        module_name: top.module_name.clone(),
        module_base: top.module_base,
        module_size: top.module_size,
        truncated: top.truncated,
        fns,
        vm_candidates: Vec::new(),
        summary_md,
    })
}
