//! GET /api/fn-summary.

use axum::extract::{Query, State};
use axum::Json;
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::TraceMeta;

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
) -> Json<FnSummaryResponse> {
    let inner = &state.inner;
    let base = primary_base(&inner.meta);
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
        return Json(FnSummaryResponse::NotFound {
            status: "not-found",
            fn_name: q.fn_name,
        });
    }

    blocks.sort_by_key(|block| block.start_pc);
    let entry_pc = blocks[0].start_pc;
    let total_executions = blocks.iter().map(|block| block.executions).sum();
    let mut entry_idxs = Vec::new();
    let mut entry_idxs_total = 0usize;
    for i in 0..inner.trace.len() {
        if inner.trace.pc(i) != entry_pc {
            continue;
        }
        entry_idxs_total += 1;
        if entry_idxs.len() < 50 {
            entry_idxs.push(i);
        }
    }

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
            rel: base.map(|b| format!("{:#x}", block.start_pc.wrapping_sub(b))),
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
        let kind = edge.weight().kind.as_str();
        if kind != "bl" && kind != "blr" {
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
                func: (func_name != "?").then_some(func_name),
                count,
            }
        })
        .collect();

    Json(FnSummaryResponse::Ready {
        status: "ready",
        fn_name: q.fn_name,
        pc: format!("{entry_pc:#x}"),
        rel: base.map(|b| format!("{:#x}", entry_pc.wrapping_sub(b))),
        block_count: blocks.len(),
        total_executions,
        entry_idxs,
        entry_idxs_total,
        hot_blocks,
        callees,
    })
}

fn primary_base(meta: &TraceMeta) -> Option<u64> {
    meta.module.as_ref().and_then(|m| parse_int(&m.base))
}

fn parse_int(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}
