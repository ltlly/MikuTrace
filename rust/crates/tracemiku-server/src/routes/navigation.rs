//! CFG/navigation endpoints: block lookup, loop SCCs, and dynamic backtrace.

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::*;

use crate::state::AppState;

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
    let pc = parse_int(&q.pc).unwrap_or(0);
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
}

pub async fn block_handler(
    State(state): State<AppState>,
    Query(q): Query<PcQuery>,
) -> Result<Json<BlockDetail>, StatusCode> {
    let pc = parse_int(&q.pc).ok_or(StatusCode::BAD_REQUEST)?;
    let block = find_block_for_pc(&state, pc).ok_or(StatusCode::NOT_FOUND)?;
    let inner = &state.inner;
    let base = primary_base(&inner.meta);
    let (func_name, off_u64) = inner.symbols.lookup(block.start_pc);
    let func = (func_name != "?").then_some(func_name);
    let off = func.as_ref().map(|_| format!("{off_u64:#x}"));

    let mut pcs = inner
        .index
        .pc_to_idxs
        .keys()
        .copied()
        .filter(|pc| *pc >= block.start_pc && *pc <= block.end_pc)
        .collect::<Vec<_>>();
    pcs.sort_unstable();
    let insns = pcs
        .into_iter()
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
                rel: base.map(|b| format!("{:#x}", pc.wrapping_sub(b))),
                asm: format!("{} {}", d.mnemonic, d.op_str).trim().to_string(),
                is_branch: d.is_branch,
                is_call: d.is_call,
                is_ret: d.is_ret,
            }
        })
        .collect();
    let exits = inner
        .cfg
        .edges_from(block.start_pc)
        .into_iter()
        .map(|(to, meta)| BlockExit {
            to: format!("{to:#x}"),
            kind: meta.kind,
        })
        .collect();
    Ok(Json(BlockDetail {
        start: format!("{:#x}", block.start_pc),
        end: format!("{:#x}", block.end_pc),
        func,
        off,
        executions: block.executions,
        insns,
        exits,
    }))
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

pub async fn loops_handler(State(state): State<AppState>) -> Json<LoopsResponse> {
    let mut groups: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
    for block in state.inner.cfg.blocks() {
        groups.entry(block.scc_id).or_default().push(block.start_pc);
    }
    let self_edges: BTreeSet<u64> = state
        .inner
        .cfg
        .graph
        .edge_references()
        .filter_map(|edge| {
            (edge.source() == edge.target()).then(|| {
                state
                    .inner
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
    Json(LoopsResponse {
        status: "ready",
        count: loops.len(),
        loops,
    })
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
}

pub async fn call_chain_handler(
    State(state): State<AppState>,
    Query(q): Query<CallChainQuery>,
) -> Result<Json<CallChainResponse>, StatusCode> {
    let inner = &state.inner;
    if q.idx >= inner.trace.len() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let base = primary_base(&inner.meta);
    let mut chain = Vec::new();
    let mut cur_idx = q.idx;
    for depth in 0..q.depth {
        let record = inner.trace.record(cur_idx);
        let pc = record.pc;
        let (func_name, off_u64) = inner.symbols.lookup(pc);
        let func = (func_name != "?").then_some(func_name);
        let off = func.as_ref().map(|_| format!("{off_u64:#x}"));
        let lr = record.reg_by_name("lr").unwrap_or(0);
        let caller_pc = lr.saturating_sub(4);
        let (caller_name, caller_off_u64) = if caller_pc != 0 {
            inner.symbols.lookup(caller_pc)
        } else {
            ("?".to_string(), 0)
        };
        let caller_func = (caller_name != "?").then_some(caller_name);
        let caller_off = caller_func.as_ref().map(|_| format!("{caller_off_u64:#x}"));
        chain.push(CallChainEntry {
            depth,
            idx: cur_idx,
            pc: format!("{pc:#x}"),
            rel: base.map(|b| format!("{:#x}", pc.wrapping_sub(b))),
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
    Ok(Json(CallChainResponse {
        start_idx: q.idx,
        depth: chain.len(),
        chain,
    }))
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
    let Some(depths) = inner.frame_depths_if_ready() else {
        return replay_backtrace_response(inner, idx, limit);
    };
    let depth = depth_after_idx(inner, depths, idx);
    let want = depth.min(limit);
    let mut stack_rev: Vec<BacktraceFrame> = Vec::with_capacity(want);
    let mut returned_calls = 0usize;

    for i in (0..=idx).rev() {
        let record = inner.trace.record(i);
        let d = decode(record.pc, record.inst);
        if d.is_ret {
            returned_calls = returned_calls.saturating_add(1);
            continue;
        }
        if !d.is_call {
            continue;
        }
        if returned_calls > 0 {
            returned_calls -= 1;
            continue;
        }
        let callee = (i + 1 < inner.trace.len()).then(|| inner.trace.pc(i + 1));
        let fn_name = callee
            .map(|pc| inner.symbols.lookup(pc).0)
            .filter(|name| name != "?");
        stack_rev.push(BacktraceFrame {
            call_site_idx: i,
            call_pc: format!("{:#x}", record.pc),
            call_pc_fmt: Some(fmt_pc_inner(inner, record.pc)),
            callee_pc: callee.map(|pc| format!("{pc:#x}")),
            callee_pc_fmt: callee.map(|pc| fmt_pc_inner(inner, pc)),
            fn_name,
        });
        if stack_rev.len() >= want {
            break;
        }
    }
    stack_rev.reverse();
    let stack = stack_rev;
    let truncated = depth > stack.len();
    BacktraceResponse {
        status: "ready",
        idx,
        depth,
        returned: stack.len(),
        truncated,
        stack,
    }
}

fn replay_backtrace_response(
    inner: &crate::state::AppStateInner,
    idx: usize,
    limit: usize,
) -> BacktraceResponse {
    let mut stack: Vec<BacktraceFrame> = Vec::new();
    let mut events = Vec::<(usize, bool)>::new();
    for (&pc, idxs) in &inner.index.pc_to_idxs {
        let Some(&first_idx) = idxs.first() else {
            continue;
        };
        let d = decode(pc, inner.trace.inst(first_idx));
        if !d.is_call && !d.is_ret {
            continue;
        }
        let take = idxs.partition_point(|&i| i <= idx);
        events.extend(idxs[..take].iter().copied().map(|i| (i, d.is_call)));
    }
    events.sort_unstable_by_key(|(i, _)| *i);

    for (i, is_call) in events {
        let record = inner.trace.record(i);
        if is_call {
            stack.push(backtrace_frame(inner, i, record.pc));
        } else {
            stack.pop();
        }
    }

    let depth = stack.len();
    let truncated = depth > limit;
    if truncated {
        stack = stack.split_off(depth - limit);
    }
    BacktraceResponse {
        status: "ready",
        idx,
        depth,
        returned: stack.len(),
        truncated,
        stack,
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
        .filter(|name| name != "?");
    BacktraceFrame {
        call_site_idx,
        call_pc: format!("{call_pc:#x}"),
        call_pc_fmt: Some(fmt_pc_inner(inner, call_pc)),
        callee_pc: callee.map(|pc| format!("{pc:#x}")),
        callee_pc_fmt: callee.map(|pc| fmt_pc_inner(inner, pc)),
        fn_name,
    }
}

fn depth_after_idx(inner: &crate::state::AppStateInner, depths: &[u32], idx: usize) -> usize {
    let before = depths.get(idx).copied().unwrap_or(0) as usize;
    let record = inner.trace.record(idx);
    let d = decode(record.pc, record.inst);
    if d.is_call {
        before.saturating_add(1)
    } else if d.is_ret {
        before.saturating_sub(1)
    } else {
        before
    }
}

fn find_block_for_pc(state: &AppState, pc: u64) -> Option<&tracemiku_core::cfg::Block> {
    state
        .inner
        .cfg
        .blocks()
        .into_iter()
        .find(|block| pc >= block.start_pc && pc <= block.end_pc)
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
    let Some(module) = inner.meta.module.as_ref() else {
        return format!("{pc:#x}");
    };
    let Some(base) = parse_int(&module.base) else {
        return format!("{pc:#x}");
    };
    if pc < base || pc >= base.saturating_add(module.size) {
        return format!("{pc:#x}");
    }
    let (fn_name, off) = inner.symbols.lookup(pc);
    if fn_name != "?" {
        format!("{fn_name}+{off:#x}")
    } else {
        format!("+{:#x}", pc.wrapping_sub(base))
    }
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
