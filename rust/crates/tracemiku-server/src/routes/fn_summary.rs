//! GET /api/fn-summary.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct FnSummaryQuery {
    #[serde(rename = "fn")]
    pub fn_name: String,
    #[serde(default = "default_top_blocks")]
    pub top_blocks: usize,
}

fn default_top_blocks() -> usize {
    5
}

#[derive(Debug, Serialize)]
pub struct FnSummaryHotBlock {
    pub pc: String,
    pub rel: Option<String>,
    pub insns: usize,
    pub executions: u64,
}

#[derive(Debug, Serialize)]
pub struct FnSummaryCallee {
    pub pc: String,
    pub func: Option<String>,
    pub count: u64,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum FnSummaryResponse {
    Ready {
        status: &'static str,
        #[serde(rename = "fn")]
        fn_name: String,
        pc: String,
        rel: Option<String>,
        block_count: usize,
        total_executions: u64,
        entry_idxs: Vec<usize>,
        entry_idxs_total: usize,
        hot_blocks: Vec<FnSummaryHotBlock>,
        callees: Vec<FnSummaryCallee>,
    },
    NotFound {
        status: &'static str,
        #[serde(rename = "fn")]
        fn_name: String,
    },
}

pub async fn fn_summary_handler(
    State(state): State<AppState>,
    Query(q): Query<FnSummaryQuery>,
) -> Result<Json<FnSummaryResponse>, (StatusCode, Json<serde_json::Value>)> {
    let inner = state.inner.clone();
    let response = tokio::task::spawn_blocking(move || fn_summary_response(&inner, q))
        .await
        .map_err(|err| crate::routes::worker_panic_response("fn summary", &err))?;
    Ok(Json(response))
}

fn fn_summary_response(
    inner: &crate::state::AppStateInner,
    q: FnSummaryQuery,
) -> FnSummaryResponse {
    let mut blocks = inner
        .cfg
        .blocks()
        .into_iter()
        .filter(|block| {
            inner
                .symbols
                .lookup(block.start_pc)
                .0
                .eq(q.fn_name.as_str())
        })
        .collect::<Vec<_>>();
    if blocks.is_empty() {
        return FnSummaryResponse::NotFound {
            status: "not-found",
            fn_name: q.fn_name,
        };
    }

    blocks.sort_by_key(|block| block.start_pc);
    let entry_pc = blocks[0].start_pc;
    let total_executions = blocks.iter().map(|block| block.executions).sum();
    let entry_idx_src = inner.index.pc_to_idxs.get(&entry_pc).map(Vec::as_slice);
    let entry_idxs_total = entry_idx_src.map_or(0, <[usize]>::len);
    let entry_idxs = entry_idx_src
        .map(|idxs| idxs.iter().take(50).copied().collect())
        .unwrap_or_default();

    let mut hot = blocks.clone();
    hot.sort_by(|a, b| {
        b.executions
            .cmp(&a.executions)
            .then_with(|| a.start_pc.cmp(&b.start_pc))
    });
    hot.truncate(q.top_blocks);
    let hot_blocks = hot
        .into_iter()
        .map(|block| FnSummaryHotBlock {
            pc: format!("{:#x}", block.start_pc),
            rel: inner
                .modules
                .relative_offset(block.start_pc)
                .map(|off| format!("{off:#x}")),
            insns: block
                .end_pc
                .saturating_sub(block.start_pc)
                .checked_div(4)
                .unwrap_or(0) as usize
                + 1,
            executions: block.executions,
        })
        .collect();

    let fn_starts = blocks
        .iter()
        .map(|block| block.start_pc)
        .collect::<std::collections::HashSet<_>>();
    let mut callee_counts = std::collections::BTreeMap::<u64, u64>::new();
    for edge in inner.cfg.graph.edge_references() {
        let Some(src) = inner.cfg.graph.node_weight(edge.source()) else {
            continue;
        };
        if !fn_starts.contains(&src.start_pc) {
            continue;
        }
        let is_call = match &edge.weight().kind {
            tracemiku_core::cfg::EdgeKind::Direct(mnem) => mnem == "bl" || mnem == "blr",
            _ => false,
        };
        if !is_call {
            continue;
        }
        let Some(dst) = inner.cfg.graph.node_weight(edge.target()) else {
            continue;
        };
        *callee_counts.entry(dst.start_pc).or_default() += edge.weight().count;
    }
    let mut callees = callee_counts.into_iter().collect::<Vec<_>>();
    callees.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    callees.truncate(20);
    let callees = callees
        .into_iter()
        .map(|(pc, count)| {
            let (func_name, _) = inner.symbols.lookup(pc);
            FnSummaryCallee {
                pc: format!("{pc:#x}"),
                func: (!func_name.is_empty()).then_some(func_name),
                count,
            }
        })
        .collect();

    FnSummaryResponse::Ready {
        status: "ready",
        fn_name: q.fn_name,
        pc: format!("{entry_pc:#x}"),
        rel: inner
            .modules
            .relative_offset(entry_pc)
            .map(|off| format!("{off:#x}")),
        block_count: blocks.len(),
        total_executions,
        entry_idxs,
        entry_idxs_total,
        hot_blocks,
        callees,
    }
}
