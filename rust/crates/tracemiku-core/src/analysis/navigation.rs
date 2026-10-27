//! CFG/navigation endpoints: block lookup, loop SCCs, and dynamic backtrace.

use super::AnalysisError;
use std::collections::{BTreeMap, BTreeSet};

use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};

use crate::prelude::*;

use crate::analysis::context::AnalysisContext;
use crate::analysis::parse;

const MAX_CALL_CHAIN_DEPTH: usize = 256;
const MAX_BLOCK_INSNS: usize = 2_000;
const MAX_BLOCK_EXITS: usize = 1_000;

#[derive(Debug, Deserialize, Default)]
pub struct PcQuery {
    pub pc: String,
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

pub fn block(state: &AnalysisContext, q: PcQuery) -> Result<BlockDetail, AnalysisError> {
    let pc = parse::parse_hex_u64(&q.pc).ok_or(AnalysisError::invalid("invalid query"))?;
    let inner = state.inner.clone();
    let _ = inner.cfg()?;
    let detail = (block_detail_response(&inner, pc))
        .ok_or(AnalysisError::not_found("trace record or value not found"))?;
    Ok(detail)
}

fn block_detail_response(
    inner: &crate::analysis::context::AnalysisData,
    pc: u64,
) -> Option<BlockDetail> {
    let block = inner.cfg().expect("CFG preloaded").block_containing(pc)?;
    let (func_name, off_u64) = inner.symbols().lookup(block.start_pc);
    let func = (!func_name.is_empty()).then_some(func_name);
    let off = func.as_ref().map(|_| format!("{off_u64:#x}"));

    let mut pcs = inner
        .index()
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
                .index()
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
    let all_exits = inner
        .cfg()
        .expect("CFG preloaded")
        .edges_from(block.start_pc);
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

pub fn loops(state: &AnalysisContext) -> Result<LoopsResponse, AnalysisError> {
    let inner = state.inner.clone();
    let _ = inner.cfg()?;
    let response = loops_response(&inner);
    Ok(response)
}

fn loops_response(inner: &crate::analysis::context::AnalysisData) -> LoopsResponse {
    let mut groups: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
    for block in inner.cfg().expect("CFG preloaded").blocks() {
        groups.entry(block.scc_id).or_default().push(block.start_pc);
    }
    let self_edges: BTreeSet<u64> = inner
        .cfg()
        .expect("CFG preloaded")
        .graph
        .edge_references()
        .filter_map(|edge| {
            (edge.source() == edge.target()).then(|| {
                inner
                    .cfg()
                    .expect("CFG preloaded")
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

pub fn call_chain(
    state: &AnalysisContext,
    q: CallChainQuery,
) -> Result<CallChainResponse, AnalysisError> {
    let inner = state.inner.clone();
    if q.idx >= inner.trace.len() {
        return Err(AnalysisError::invalid("invalid query"));
    }
    let response = call_chain_response(&inner, q);
    Ok(response)
}

fn call_chain_response(
    inner: &crate::analysis::context::AnalysisData,
    q: CallChainQuery,
) -> CallChainResponse {
    let mut chain = Vec::new();
    let mut cur_idx = q.idx;
    let max_depth = effective_call_chain_depth(q.depth);
    for depth in 0..max_depth {
        let record = inner.trace.record(cur_idx);
        let pc = record.pc;
        let (func_name, off_u64) = inner.symbols().lookup(pc);
        let func = (!func_name.is_empty()).then_some(func_name);
        let off = func.as_ref().map(|_| format!("{off_u64:#x}"));
        let lr = record.reg_by_name("lr").unwrap_or(0);
        let caller_pc = lr.saturating_sub(4);
        let (caller_name, caller_off_u64) = if caller_pc != 0 {
            inner.symbols().lookup(caller_pc)
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

pub fn backtrace(
    state: &AnalysisContext,
    q: BacktraceQuery,
) -> Result<BacktraceResponse, AnalysisError> {
    let inner = state.inner.clone();
    if q.idx >= inner.trace.len() {
        return Err(AnalysisError::not_found("trace record or value not found"));
    }
    let response = backtrace_response(&inner, q.idx, q.limit);
    Ok(response)
}

fn backtrace_response(
    inner: &crate::analysis::context::AnalysisData,
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
    inner: &crate::analysis::context::AnalysisData,
    call_site_idx: usize,
    call_pc: u64,
) -> BacktraceFrame {
    let callee = (call_site_idx + 1 < inner.trace.len()).then(|| inner.trace.pc(call_site_idx + 1));
    let fn_name = callee
        .map(|pc| inner.symbols().lookup(pc).0)
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

fn last_pc_before(
    inner: &crate::analysis::context::AnalysisData,
    pc: u64,
    before_idx: usize,
) -> Option<usize> {
    let idxs = inner.index().pc_to_idxs.get(&pc)?;
    let pos = idxs.partition_point(|&i| i < before_idx);
    pos.checked_sub(1).map(|i| idxs[i])
}

fn fmt_pc_inner(inner: &crate::analysis::context::AnalysisData, pc: u64) -> String {
    let Some((_, rel)) = inner.modules.resolve_relative(pc) else {
        return format!("{pc:#x}");
    };
    let (fn_name, off) = inner.symbols().lookup(pc);
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

impl Default for BacktraceQuery {
    fn default() -> Self {
        Self {
            idx: Default::default(),
            limit: default_backtrace_limit(),
        }
    }
}

impl Default for CallChainQuery {
    fn default() -> Self {
        Self {
            idx: Default::default(),
            depth: default_call_chain_depth(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct BacktraceInspectQuery {
    pub idx: usize,
    pub limit: usize,
    pub lr_clues: bool,
}
#[derive(Debug, Serialize)]
pub struct BacktraceInspection {
    #[serde(flatten)]
    pub observed: BacktraceResponse,
    pub lr_clues: Option<CallChainResponse>,
}
pub fn inspect_backtrace(
    state: &AnalysisContext,
    q: BacktraceInspectQuery,
) -> Result<BacktraceInspection, AnalysisError> {
    let limit = q.limit.clamp(1, MAX_CALL_CHAIN_DEPTH);
    Ok(BacktraceInspection {
        observed: backtrace(state, BacktraceQuery { idx: q.idx, limit })?,
        lr_clues: q
            .lr_clues
            .then(|| {
                call_chain(
                    state,
                    CallChainQuery {
                        idx: q.idx,
                        depth: limit,
                    },
                )
            })
            .transpose()?,
    })
}
