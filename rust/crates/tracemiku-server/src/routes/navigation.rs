//! CFG/navigation endpoints: block lookup, loop SCCs, and dynamic backtrace.

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::*;

use crate::routes::parse;
use crate::state::AppState;

const MAX_CALL_CHAIN_DEPTH: usize = 256;
const MAX_BLOCK_INSNS: usize = 2_000;
const MAX_BLOCK_EXITS: usize = 1_000;

#[derive(Debug, Deserialize)]
pub struct PcQuery {
    pub pc: String,
}

#[derive(Debug, Serialize)]
pub struct BlockForPcResponse {
    pub pc: String,
    pub block: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_status: Option<String>,
}

pub async fn block_for_pc_handler(
    State(state): State<AppState>,
    Query(q): Query<PcQuery>,
) -> Json<BlockForPcResponse> {
    let pc = parse::parse_dec_u64(&q.pc).unwrap_or(0);
    let block = find_block_for_pc(&state, pc).map(|b| format!("{:#x}", b.start_pc));
    Json(BlockForPcResponse {
        pc: q.pc,
        block,
        cfg_status: None,
    })
}

#[derive(Debug, Serialize)]
pub struct BlockInsn {
    pub pc: String,
    pub rel: Option<String>,
    pub asm: String,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_ret: bool,
}

#[derive(Debug, Serialize)]
pub struct BlockExit {
    pub to: String,
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct BlockDetail {
    pub start: String,
    pub end: String,
    pub func: Option<String>,
    pub off: Option<String>,
    pub executions: u64,
    pub insns: Vec<BlockInsn>,
    pub exits: Vec<BlockExit>,
    pub total_insns: usize,
    pub total_exits: usize,
    pub max_insns_used: usize,
    pub max_exits_used: usize,
    pub truncated: bool,
}

pub async fn block_handler(
    State(state): State<AppState>,
    Query(q): Query<PcQuery>,
) -> Result<Json<BlockDetail>, StatusCode> {
    let pc = parse::parse_dec_u64(&q.pc).ok_or(StatusCode::BAD_REQUEST)?;
    let inner = state.inner.clone();
    let detail = tokio::task::spawn_blocking(move || block_detail_response(&inner, pc))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "block worker failed: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(detail))
}

fn block_detail_response(inner: &crate::state::AppStateInner, pc: u64) -> Option<BlockDetail> {
    let block = inner.cfg.block_containing(pc)?;
    let (func_name, off_u64) = inner.symbols.lookup(block.start_pc);
    let func = (!func_name.is_empty()).then_some(func_name);
    let off = func.as_ref().map(|_| format!("{off_u64:#x}"));

    let mut pcs = inner
        .index
        .pc_to_idxs
        .keys()
        .copied()
        .filter(|pc| *pc >= block.start_pc && *pc <= block.end_pc)
        .collect::<Vec<_>>();
    pcs.sort_unstable();
    let total_insns = pcs.len();
    let insns_truncated = total_insns > MAX_BLOCK_INSNS;
    let insns = pcs
        .into_iter()
        .take(MAX_BLOCK_INSNS)
        .map(|pc| {
            let inst = inner
                .index
                .pc_to_idxs
                .get(&pc)
                .and_then(|idxs| idxs.first())
                .map(|idx| inner.trace.inst(*idx))
                .unwrap_or(0);
            let d = decode(pc, inst);
            BlockInsn {
                pc: format!("{pc:#x}"),
                rel: inner
                    .modules
                    .relative_offset(pc)
                    .map(|off| format!("{off:#x}")),
                asm: format!("{} {}", d.mnemonic, d.op_str).trim().to_string(),
                is_branch: d.is_branch,
                is_call: d.is_call,
                is_ret: d.is_ret,
            }
        })
        .collect();
    let all_exits = inner.cfg.edges_from(block.start_pc);
    let total_exits = all_exits.len();
    let exits_truncated = total_exits > MAX_BLOCK_EXITS;
    let exits = all_exits
        .into_iter()
        .take(MAX_BLOCK_EXITS)
        .map(|(to, meta)| BlockExit {
            to: format!("{to:#x}"),
            kind: meta.kind.label(),
        })
        .collect();
    Some(BlockDetail {
        start: format!("{:#x}", block.start_pc),
        end: format!("{:#x}", block.end_pc),
        func,
        off,
        executions: block.executions,
        insns,
        exits,
        total_insns,
        total_exits,
        max_insns_used: MAX_BLOCK_INSNS,
        max_exits_used: MAX_BLOCK_EXITS,
        truncated: insns_truncated || exits_truncated,
    })
}

#[derive(Debug, Serialize)]
pub struct LoopInfo {
    pub members: Vec<String>,
    pub size: usize,
}

#[derive(Debug, Serialize)]
pub struct LoopsResponse {
    pub status: &'static str,
    pub loops: Vec<LoopInfo>,
    pub count: usize,
}

pub async fn loops_handler(
    State(state): State<AppState>,
) -> Result<Json<LoopsResponse>, crate::routes::WorkerFailure> {
    let inner = state.inner.clone();
    let response = tokio::task::spawn_blocking(move || loops_response(&inner))
        .await
        .map_err(|err| crate::routes::worker_panic_response("loops", &err))?;
    Ok(Json(response))
}

fn loops_response(inner: &crate::state::AppStateInner) -> LoopsResponse {
    let mut groups: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
    for block in inner.cfg.blocks() {
        groups.entry(block.scc_id).or_default().push(block.start_pc);
    }
    let self_edges: BTreeSet<u64> = inner
        .cfg
        .graph
        .edge_references()
        .filter_map(|edge| {
            (edge.source() == edge.target()).then(|| {
                inner
                    .cfg
                    .graph
                    .node_weight(edge.source())
                    .map(|b| b.start_pc)
            })?
        })
        .collect();
    let mut loops = Vec::new();
    for mut members in groups.into_values() {
        members.sort_unstable();
        if members.len() >= 2 || members.iter().any(|pc| self_edges.contains(pc)) {
            loops.push(LoopInfo {
                size: members.len(),
                members: members.into_iter().map(|pc| format!("{pc:#x}")).collect(),
            });
        }
    }
    LoopsResponse {
        status: "ready",
        count: loops.len(),
        loops,
    }
}

#[derive(Debug, Deserialize)]
pub struct BacktraceQuery {
    pub idx: usize,
    #[serde(default = "default_backtrace_limit")]
    pub limit: usize,
}

fn default_backtrace_limit() -> usize {
    256
}

#[derive(Debug, Serialize, Clone)]
pub struct BacktraceFrame {
    pub call_site_idx: usize,
    pub call_pc: String,
    pub call_pc_fmt: Option<String>,
    pub callee_pc: Option<String>,
    pub callee_pc_fmt: Option<String>,
    #[serde(rename = "fn")]
    pub fn_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BacktraceResponse {
    pub status: &'static str,
    pub idx: usize,
    pub stack: Vec<BacktraceFrame>,
    pub depth: usize,
    pub returned: usize,
    pub truncated: bool,
}

#[derive(Debug, Deserialize)]
pub struct CallChainQuery {
    pub idx: usize,
    #[serde(default = "default_call_chain_depth")]
    pub depth: usize,
}

fn default_call_chain_depth() -> usize {
    5
}

fn effective_call_chain_depth(raw: usize) -> usize {
    raw.min(MAX_CALL_CHAIN_DEPTH)
}

#[derive(Debug, Serialize)]
pub struct CallChainEntry {
    pub depth: usize,
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub func: Option<String>,
    pub off: Option<String>,
    pub lr: String,
    pub caller_pc: String,
    pub caller_func: Option<String>,
    pub caller_off: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CallChainResponse {
    pub start_idx: usize,
    pub depth: usize,
    pub chain: Vec<CallChainEntry>,
    pub requested_depth: usize,
    pub max_depth_used: usize,
    pub truncated: bool,
}

pub async fn call_chain_handler(
    State(state): State<AppState>,
    Query(q): Query<CallChainQuery>,
) -> Result<Json<CallChainResponse>, StatusCode> {
    let inner = state.inner.clone();
    if q.idx >= inner.trace.len() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let response = tokio::task::spawn_blocking(move || call_chain_response(&inner, q))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "call chain worker failed: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(Json(response))
}

fn call_chain_response(
    inner: &crate::state::AppStateInner,
    q: CallChainQuery,
) -> CallChainResponse {
    let mut chain = Vec::new();
    let mut cur_idx = q.idx;
    let max_depth = effective_call_chain_depth(q.depth);
    for depth in 0..max_depth {
        let record = inner.trace.record(cur_idx);
        let pc = record.pc;
        let (func_name, off_u64) = inner.symbols.lookup(pc);
        let func = (!func_name.is_empty()).then_some(func_name);
        let off = func.as_ref().map(|_| format!("{off_u64:#x}"));
        let lr = record.reg_by_name("lr").unwrap_or(0);
        let caller_pc = lr.saturating_sub(4);
        let (caller_name, caller_off_u64) = if caller_pc != 0 {
            inner.symbols.lookup(caller_pc)
        } else {
            ("".to_string(), 0)
        };
        let caller_func = (!caller_name.is_empty()).then_some(caller_name);
        let caller_off = caller_func.as_ref().map(|_| format!("{caller_off_u64:#x}"));
        chain.push(CallChainEntry {
            depth,
            idx: cur_idx,
            pc: format!("{pc:#x}"),
            rel: inner
                .modules
                .relative_offset(pc)
                .map(|off| format!("{off:#x}")),
            func,
            off,
            lr: format!("{lr:#x}"),
            caller_pc: format!("{caller_pc:#x}"),
            caller_func,
            caller_off,
        });
        if caller_pc == 0 {
            break;
        }
        let Some(next_idx) = last_pc_before(inner, caller_pc, cur_idx) else {
            break;
        };
        cur_idx = next_idx;
    }
    let truncated = q.depth > max_depth || chain.len() == max_depth;
    CallChainResponse {
        start_idx: q.idx,
        depth: chain.len(),
        chain,
        requested_depth: q.depth,
        max_depth_used: max_depth,
        truncated,
    }
}

pub async fn backtrace_handler(
    State(state): State<AppState>,
    Query(q): Query<BacktraceQuery>,
) -> Result<Json<BacktraceResponse>, StatusCode> {
    let inner = state.inner.clone();
    if q.idx >= inner.trace.len() {
        return Err(StatusCode::NOT_FOUND);
    }
    let response = tokio::task::spawn_blocking(move || backtrace_response(&inner, q.idx, q.limit))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "backtrace worker failed: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(Json(response))
}

fn backtrace_response(
    inner: &crate::state::AppStateInner,
    idx: usize,
    limit: usize,
) -> BacktraceResponse {
    let limit = limit.clamp(1, 2048);
    let events = inner.backtrace_events();
    let take = events.partition_point(|event| event.idx <= idx);
    let mut stack: Vec<usize> = Vec::new();

    for event in &events[..take] {
        if event.is_call {
            stack.push(event.idx);
        } else {
            stack.pop();
        }
    }

    let depth = stack.len();
    let truncated = depth > limit;
    if truncated {
        stack = stack.split_off(depth - limit);
    }
    let frames = stack
        .into_iter()
        .map(|call_idx| {
            let record = inner.trace.record(call_idx);
            backtrace_frame(inner, call_idx, record.pc)
        })
        .collect::<Vec<_>>();
    BacktraceResponse {
        status: "ready",
        idx,
        depth,
        returned: frames.len(),
        truncated,
        stack: frames,
    }
}

fn backtrace_frame(
    inner: &crate::state::AppStateInner,
    call_site_idx: usize,
    call_pc: u64,
) -> BacktraceFrame {
    let callee = (call_site_idx + 1 < inner.trace.len()).then(|| inner.trace.pc(call_site_idx + 1));
    let fn_name = callee
        .map(|pc| inner.symbols.lookup(pc).0)
        .filter(|name| !name.is_empty());
    BacktraceFrame {
        call_site_idx,
        call_pc: format!("{call_pc:#x}"),
        call_pc_fmt: Some(fmt_pc_inner(inner, call_pc)),
        callee_pc: callee.map(|pc| format!("{pc:#x}")),
        callee_pc_fmt: callee.map(|pc| fmt_pc_inner(inner, pc)),
        fn_name,
    }
}

fn find_block_for_pc(state: &AppState, pc: u64) -> Option<&tracemiku_core::cfg::Block> {
    state.inner.cfg.block_containing(pc)
}

fn last_pc_before(
    inner: &crate::state::AppStateInner,
    pc: u64,
    before_idx: usize,
) -> Option<usize> {
    let idxs = inner.index.pc_to_idxs.get(&pc)?;
    let pos = idxs.partition_point(|&i| i < before_idx);
    pos.checked_sub(1).map(|i| idxs[i])
}

fn fmt_pc_inner(inner: &crate::state::AppStateInner, pc: u64) -> String {
    let Some((_, rel)) = inner.modules.resolve_relative(pc) else {
        return format!("{pc:#x}");
    };
    let (fn_name, off) = inner.symbols.lookup(pc);
    if !fn_name.is_empty() {
        format!("{fn_name}+{off:#x}")
    } else {
        format!("+{rel:#x}")
    }
}

#[cfg(test)]
mod tests {
    use super::{effective_call_chain_depth, MAX_CALL_CHAIN_DEPTH};

    #[test]
    fn effective_call_chain_depth_caps_extreme_requests() {
        assert_eq!(effective_call_chain_depth(0), 0);
        assert_eq!(effective_call_chain_depth(5), 5);
        assert_eq!(effective_call_chain_depth(usize::MAX), MAX_CALL_CHAIN_DEPTH);
    }
}
