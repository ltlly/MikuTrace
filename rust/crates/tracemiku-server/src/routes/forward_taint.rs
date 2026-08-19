//! GET /api/forward-taint — index-accelerated forward taint.

use std::collections::HashSet;

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::disasm::{decode, normalize_disasm_reg};
use tracemiku_core::prelude::{
    default_frame_reg_set, forward_taint_ext, TaintOptions, TaintStopReason,
};

use crate::state::AppState;
use crate::taint_graph::{build_taint_graph, empty_taint_graph, TaintGraph, TaintGraphRow};

const MAX_COUNT_CEILING: usize = 5_000;
const DEFAULT_MAX_COUNT: usize = 5_000;
const DEFAULT_SCAN_LIMIT: usize = 200_000;

#[derive(Debug, Deserialize)]
pub struct ForwardTaintQuery {
    #[serde(alias = "trace_idx", alias = "traceIdx")]
    pub start: usize,
    pub reg: String,
    pub max_count: Option<usize>,
    #[serde(default)]
    pub through_mem: bool,
    #[serde(default)]
    pub data_only: bool,
    #[serde(default)]
    pub cross_fn_call: bool,
    /// GumTrace `SCAN_LIMIT_REACHED` watchdog.
    /// `None` → use [`DEFAULT_SCAN_LIMIT`]; `Some(0)` → disable watchdog.
    pub scan_limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct TaintRow {
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub func: Option<String>,
    pub asm: String,
    pub why: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_kind: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parent_idxs: Vec<usize>,
    pub taint_depth: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_depth: Option<u32>,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_ret: bool,
}

#[derive(Debug, Serialize)]
pub struct ForwardTaintResponse {
    pub status: &'static str,
    pub count: usize,
    pub from: usize,
    pub reg: String,
    pub hits: Vec<TaintRow>,
    pub graph: TaintGraph,
    pub stopped_at_max: bool,
    pub max_count_used: usize,
    pub stop_reason: &'static str,
    pub scan_limit_used: Option<usize>,
}

impl TaintGraphRow for TaintRow {
    fn idx(&self) -> usize {
        self.idx
    }

    fn func(&self) -> Option<&str> {
        self.func.as_deref()
    }

    fn asm(&self) -> &str {
        &self.asm
    }

    fn via(&self) -> &str {
        &self.why
    }

    fn edge_kind(&self) -> Option<&str> {
        self.edge_kind.as_deref()
    }

    fn parent_idxs(&self) -> &[usize] {
        &self.parent_idxs
    }

    fn taint_depth(&self) -> u32 {
        self.taint_depth
    }
}

pub async fn forward_taint_handler(
    State(state): State<AppState>,
    Query(q): Query<ForwardTaintQuery>,
) -> Result<Json<ForwardTaintResponse>, crate::routes::WorkerFailure> {
    let inner = state.inner.clone();
    let response = tokio::task::spawn_blocking(move || forward_taint_response(&inner, q))
        .await
        .map_err(|err| crate::routes::worker_panic_response("forward taint", &err))?;
    Ok(Json(response))
}

fn forward_taint_response(
    inner: &crate::state::AppStateInner,
    q: ForwardTaintQuery,
) -> ForwardTaintResponse {
    let eff = effective_max_count(q.max_count);
    let reg = normalize_disasm_reg(&q.reg);
    let exclude: HashSet<String> = if q.data_only {
        default_frame_reg_set()
    } else {
        HashSet::new()
    };
    let mem_arg = if q.through_mem {
        match inner.memshadow_ready_or_block_if_idle() {
            Ok(mem) => Some(mem),
            Err(status) => {
                let status = status.status_str();
                return ForwardTaintResponse {
                    status,
                    count: 0,
                    from: q.start,
                    graph: empty_taint_graph(q.start, &reg),
                    reg,
                    hits: Vec::new(),
                    stopped_at_max: false,
                    max_count_used: eff,
                    stop_reason: "memshadow_unavailable",
                    scan_limit_used: None,
                };
            }
        }
    } else {
        None
    };
    let scan_limit = effective_scan_limit(q.scan_limit);
    let walk = forward_taint_ext(
        &inner.trace,
        &inner.index,
        q.start,
        &reg,
        eff,
        &exclude,
        mem_arg,
        TaintOptions {
            through_mem: q.through_mem,
            data_only: q.data_only,
            scan_limit,
        },
    );
    let stop_reason_str = stop_reason_str(walk.stop_reason);
    let stopped = matches!(
        walk.stop_reason,
        TaintStopReason::MaxCount | TaintStopReason::ScanLimit
    );
    let hits = walk.hits;

    let rows: Vec<TaintRow> = hits
        .into_iter()
        .map(|h| {
            let r = inner.trace.record(h.idx);
            let d = decode(r.pc, r.inst);
            let (fname, _) = inner.symbols.lookup(r.pc);
            TaintRow {
                idx: h.idx,
                pc: format!("{:#x}", r.pc),
                rel: inner
                    .modules
                    .relative_offset(r.pc)
                    .map(|off| format!("{off:#x}")),
                func: if fname.is_empty() { None } else { Some(fname) },
                asm: format!("{} {}", d.mnemonic, d.op_str),
                why: h.why,
                edge_kind: h.edge_kind,
                parent_idxs: h.parent_idxs,
                taint_depth: h.taint_depth,
                frame_depth: if q.cross_fn_call {
                    inner.frame_depths().get(h.idx).copied()
                } else {
                    None
                },
                is_branch: d.is_branch,
                is_call: d.is_call,
                is_ret: d.is_ret,
            }
        })
        .collect();
    let graph = build_taint_graph(q.start, &reg, &rows);

    ForwardTaintResponse {
        status: "ready",
        count: rows.len(),
        from: q.start,
        reg,
        hits: rows,
        graph,
        stopped_at_max: stopped,
        max_count_used: eff,
        stop_reason: stop_reason_str,
        scan_limit_used: scan_limit,
    }
}

fn effective_max_count(raw: Option<usize>) -> usize {
    match raw {
        None | Some(0) => DEFAULT_MAX_COUNT,
        Some(n) => n.min(MAX_COUNT_CEILING),
    }
}

fn effective_scan_limit(raw: Option<usize>) -> Option<usize> {
    match raw {
        None => Some(DEFAULT_SCAN_LIMIT),
        Some(0) => None,
        Some(n) => Some(n),
    }
}

fn stop_reason_str(reason: TaintStopReason) -> &'static str {
    match reason {
        TaintStopReason::Completed => "completed",
        TaintStopReason::MaxCount => "max_count",
        TaintStopReason::ScanLimit => "scan_limit",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        effective_max_count, effective_scan_limit, stop_reason_str, DEFAULT_MAX_COUNT,
        DEFAULT_SCAN_LIMIT, MAX_COUNT_CEILING,
    };
    use tracemiku_core::prelude::TaintStopReason;

    #[test]
    fn effective_max_count_caps_extreme_requests() {
        assert_eq!(effective_max_count(None), DEFAULT_MAX_COUNT);
        assert_eq!(effective_max_count(Some(0)), DEFAULT_MAX_COUNT);
        assert_eq!(effective_max_count(Some(10)), 10);
        assert_eq!(effective_max_count(Some(usize::MAX)), MAX_COUNT_CEILING);
    }

    #[test]
    fn effective_scan_limit_routes_zero_to_disabled() {
        assert_eq!(effective_scan_limit(None), Some(DEFAULT_SCAN_LIMIT));
        assert_eq!(effective_scan_limit(Some(0)), None);
        assert_eq!(effective_scan_limit(Some(7)), Some(7));
    }

    #[test]
    fn stop_reason_str_round_trip() {
        assert_eq!(stop_reason_str(TaintStopReason::Completed), "completed");
        assert_eq!(stop_reason_str(TaintStopReason::MaxCount), "max_count");
        assert_eq!(stop_reason_str(TaintStopReason::ScanLimit), "scan_limit");
    }
}
