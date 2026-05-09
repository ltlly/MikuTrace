//! GET /api/dec/summary — TraceIR top-level summary.
//!
//! Wire shape mirrors webui/server.py:2734-2773. M3-ε: trace-ir entries
//! (root + top-K split callees from build_trace_ir) plus the
//! symbol-source fallback (FunctionIndex entries with source=="symbol"
//! whose entry PCs are not already represented by trace-ir functions).

use std::collections::HashSet;

use axum::extract::{Query, State};
use axum::Json;
use serde::Serialize;

use tracemiku_core::prelude::{make_trace_id, render_summary_md};

use crate::routes::dec_options::DecIrQuery;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct DecFnEntry {
    pub id: String,
    pub name: String,
    pub module: Option<String>,
    pub entry_rel: Option<u64>,
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

pub async fn dec_summary_handler(
    State(state): State<AppState>,
    Query(q): Query<DecIrQuery>,
) -> Json<DecSummaryResponse> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || dec_summary_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "dec summary worker failed: {err}");
                DecSummaryResponse {
                    records: 0,
                    module_name: String::new(),
                    module_base: 0,
                    module_size: 0,
                    truncated: false,
                    fns: Vec::new(),
                    vm_candidates: Vec::new(),
                    summary_md: String::new(),
                }
            }),
    )
}

fn dec_summary_response(inner: &crate::state::AppStateInner, q: DecIrQuery) -> DecSummaryResponse {
    let opts = q.to_options();
    if opts.uses_cached_default() {
        dec_summary_response_for_top(inner, inner.top_ir())
    } else {
        let top = inner.build_top_ir_with_options(&opts);
        dec_summary_response_for_top(inner, &top)
    }
}

fn dec_summary_response_for_top(
    inner: &crate::state::AppStateInner,
    top: &tracemiku_core::prelude::TopIR,
) -> DecSummaryResponse {
    let fns: Vec<DecFnEntry> = top
        .fns
        .iter()
        .map(|f| {
            let (module, entry_rel) = inner
                .modules
                .resolve_relative(f.pc_start)
                .map(|(module, rel)| (Some(module), Some(rel)))
                .unwrap_or((None, None));
            DecFnEntry {
                id: make_trace_id(&f.id),
                name: f.name.clone(),
                module,
                entry_rel,
                blocks: f.blocks.len(),
                loops: f.loops.len(),
                calls: f.calls.len(),
                type_anchors: f.type_anchors.len(),
                entry_idx: Some(f.entry_idx),
                exit_idx: Some(f.exit_idx),
                source: "trace-ir",
                trace_ir_id: Some(f.id.clone()),
            }
        })
        .collect();

    let trace_starts: HashSet<u64> = top.fns.iter().map(|f| f.pc_start).collect();
    let mut fns = fns;
    for entry in &inner.function_index.entries {
        if entry.source != "symbol" {
            continue;
        }
        if entry.entry_pc.is_some_and(|pc| trace_starts.contains(&pc)) {
            continue;
        }
        fns.push(DecFnEntry {
            id: entry.id.clone(),
            name: entry.name.clone(),
            module: entry.module.clone(),
            entry_rel: entry.entry_rel,
            blocks: entry.blocks as usize,
            loops: 0,
            calls: 0,
            type_anchors: 0,
            entry_idx: None,
            exit_idx: None,
            source: "symbol",
            trace_ir_id: None,
        });
    }

    let summary_md = render_summary_md(top);
    let vm_candidates = top
        .vm_candidates
        .iter()
        .filter_map(|c| serde_json::to_value(c).ok())
        .collect();

    DecSummaryResponse {
        records: top.records,
        module_name: top.module_name.clone(),
        module_base: top.module_base,
        module_size: top.module_size,
        truncated: top.truncated,
        fns,
        vm_candidates,
        summary_md,
    }
}
