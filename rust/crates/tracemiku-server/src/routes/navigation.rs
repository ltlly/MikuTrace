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
        let Some(next_idx) = last_pc_before(&inner.trace, caller_pc, cur_idx) else {
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
    let inner = &state.inner;
    if q.idx >= inner.trace.len() {
        return Err(StatusCode::NOT_FOUND);
    }
    let mut stack: Vec<BacktraceFrame> = Vec::new();
    for i in 0..=q.idx {
        let record = inner.trace.record(i);
        let d = decode(record.pc, record.inst);
        if d.is_call {
            let callee = (i + 1 < inner.trace.len()).then(|| inner.trace.pc(i + 1));
            let fn_name = callee
                .map(|pc| inner.symbols.lookup(pc).0)
                .filter(|name| name != "?");
            stack.push(BacktraceFrame {
                call_site_idx: i,
                call_pc: format!("{:#x}", record.pc),
                call_pc_fmt: Some(fmt_pc(&state, record.pc)),
                callee_pc: callee.map(|pc| format!("{pc:#x}")),
                callee_pc_fmt: callee.map(|pc| fmt_pc(&state, pc)),
                fn_name,
            });
        } else if d.is_ret {
            stack.pop();
        }
    }
    Ok(Json(BacktraceResponse {
        status: "ready",
        idx: q.idx,
        depth: stack.len(),
        stack,
    }))
}

fn find_block_for_pc(state: &AppState, pc: u64) -> Option<&tracemiku_core::cfg::Block> {
    state
        .inner
        .cfg
        .blocks()
        .into_iter()
        .find(|block| pc >= block.start_pc && pc <= block.end_pc)
}

fn last_pc_before(trace: &Trace, pc: u64, before_idx: usize) -> Option<usize> {
    (0..before_idx).rev().find(|&i| trace.pc(i) == pc)
}

fn fmt_pc(state: &AppState, pc: u64) -> String {
    let Some(module) = state.inner.meta.module.as_ref() else {
        return format!("{pc:#x}");
    };
    let Some(base) = parse_int(&module.base) else {
        return format!("{pc:#x}");
    };
    if pc < base || pc >= base.saturating_add(module.size) {
        return format!("{pc:#x}");
    }
    let (fn_name, off) = state.inner.symbols.lookup(pc);
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
