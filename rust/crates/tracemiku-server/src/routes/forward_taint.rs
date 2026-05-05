//! GET /api/forward-taint — index-accelerated forward taint.

use std::collections::HashSet;

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::disasm::decode;
use tracemiku_core::prelude::{default_frame_reg_set, forward_taint};

use crate::state::AppState;

const MAX_COUNT_CEILING: usize = 5_000;
const DEFAULT_MAX_COUNT: usize = 5_000;

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
    pub frame_depth: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ForwardTaintResponse {
    pub status: &'static str,
    pub count: usize,
    pub from: usize,
    pub reg: String,
    pub hits: Vec<TaintRow>,
    pub stopped_at_max: bool,
    pub max_count_used: usize,
}

pub async fn forward_taint_handler(
    State(state): State<AppState>,
    Query(q): Query<ForwardTaintQuery>,
) -> Json<ForwardTaintResponse> {
    let start = q.start;
    let reg = q.reg.clone();
    let inner = state.inner.clone();
    let response = tokio::task::spawn_blocking(move || forward_taint_response(&inner, q))
        .await
        .unwrap_or_else(|err| {
            tracing::warn!(target: "tracemiku-server", "forward taint worker failed: {err}");
            ForwardTaintResponse {
                status: "error",
                count: 0,
                from: start,
                reg,
                hits: Vec::new(),
                stopped_at_max: true,
                max_count_used: 0,
            }
        });
    Json(response)
}

fn forward_taint_response(
    inner: &crate::state::AppStateInner,
    q: ForwardTaintQuery,
) -> ForwardTaintResponse {
    let eff = effective_max_count(q.max_count);
    let exclude: HashSet<String> = if q.data_only {
        default_frame_reg_set()
    } else {
        HashSet::new()
    };
    let mem_arg = if q.through_mem {
        match inner.memshadow_ready_or_block_if_idle() {
            Ok(mem) => Some(mem),
            Err(status) => {
                return ForwardTaintResponse {
                    status,
                    count: 0,
                    from: q.start,
                    reg: q.reg,
                    hits: Vec::new(),
                    stopped_at_max: false,
                    max_count_used: eff,
                };
            }
        }
    } else {
        None
    };
    let (hits, stopped) = forward_taint(
        &inner.trace,
        &inner.index,
        q.start,
        &q.reg,
        eff,
        &exclude,
        q.through_mem,
        mem_arg,
        q.data_only,
    );

    let base = inner
        .meta
        .module
        .as_ref()
        .map(|m| u64::from_str_radix(m.base.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0);

    let rows: Vec<TaintRow> = hits
        .into_iter()
        .map(|h| {
            let r = inner.trace.record(h.idx);
            let d = decode(r.pc, r.inst);
            let (fname, _) = inner.symbols.lookup(r.pc);
            TaintRow {
                idx: h.idx,
                pc: format!("{:#x}", r.pc),
                rel: if base != 0 {
                    Some(format!("{:#x}", r.pc - base))
                } else {
                    None
                },
                func: if fname == "?" { None } else { Some(fname) },
                asm: format!("{} {}", d.mnemonic, d.op_str),
                why: h.why,
                frame_depth: if q.cross_fn_call {
                    inner.frame_depths().get(h.idx).copied()
                } else {
                    None
                },
            }
        })
        .collect();

    ForwardTaintResponse {
        status: "ready",
        count: rows.len(),
        from: q.start,
        reg: q.reg,
        hits: rows,
        stopped_at_max: stopped,
        max_count_used: eff,
    }
}

fn effective_max_count(raw: Option<usize>) -> usize {
    raw.unwrap_or(DEFAULT_MAX_COUNT).min(MAX_COUNT_CEILING)
}

#[cfg(test)]
mod tests {
    use super::{effective_max_count, DEFAULT_MAX_COUNT, MAX_COUNT_CEILING};

    #[test]
    fn effective_max_count_caps_extreme_requests() {
        assert_eq!(effective_max_count(None), DEFAULT_MAX_COUNT);
        assert_eq!(effective_max_count(Some(10)), 10);
        assert_eq!(effective_max_count(Some(usize::MAX)), MAX_COUNT_CEILING);
    }
}
