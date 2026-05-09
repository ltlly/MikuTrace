//! GET /api/dep-graph.
//!
//! Backward dependency DAG backed by the persistent whole-trace analysis index.
//! A seed can be a concrete trace index, the last definition of a register
//! before a cursor, or the last write to an address before a cursor.

use std::collections::{HashSet, VecDeque};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use tracemiku_core::analysis_index::{DepEdge, DepKind};
use tracemiku_core::disasm::decode;

use crate::state::AppState;
use crate::taint_graph::expression_from_asm;

const DEFAULT_DEPTH: usize = 8;
const MAX_DEPTH: usize = 64;
const DEFAULT_LIMIT: usize = 160;
const MAX_LIMIT: usize = 2_000;

#[derive(Debug, Deserialize)]
pub struct DepGraphQuery {
    pub idx: Option<usize>,
    pub reg: Option<String>,
    pub addr: Option<String>,
    pub before: Option<usize>,
    #[serde(default = "default_depth")]
    pub depth: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_depth() -> usize {
    DEFAULT_DEPTH
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

#[derive(Debug, Serialize)]
pub struct DepGraphResponse {
    pub status: &'static str,
    pub seed: DepGraphSeed,
    pub graph: DepGraph,
}

#[derive(Debug, Serialize)]
pub struct DepGraphSeed {
    pub kind: &'static str,
    pub idx: Option<usize>,
    pub reg: Option<String>,
    pub addr: Option<String>,
    pub before: Option<usize>,
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DepGraph {
    pub nodes: Vec<DepGraphNode>,
    pub edges: Vec<DepGraphEdge>,
    pub node_count: usize,
    pub edge_count: usize,
    pub hidden_nodes: usize,
    pub hidden_edges: usize,
    pub truncated: bool,
    pub depth_limit: usize,
    pub node_limit: usize,
}

#[derive(Debug, Serialize)]
pub struct DepGraphNode {
    pub id: String,
    pub idx: usize,
    pub depth: usize,
    pub pc: String,
    pub func: Option<String>,
    pub asm: String,
    pub via: String,
    pub expression: String,
}

#[derive(Debug, Serialize)]
pub struct DepGraphEdge {
    pub from: String,
    pub to: String,
    pub kind: &'static str,
    pub label: &'static str,
}

pub async fn dep_graph_handler(
    State(state): State<AppState>,
    Query(q): Query<DepGraphQuery>,
) -> Result<Json<DepGraphResponse>, (StatusCode, String)> {
    let response = tokio::task::spawn_blocking(move || dep_graph_response(&state, q))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "dep-graph worker failed: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "dep-graph worker failed".to_string(),
            )
        })?;
    Ok(Json(response))
}

fn dep_graph_response(state: &AppState, q: DepGraphQuery) -> DepGraphResponse {
    let before = q.before.unwrap_or_else(|| state.inner.trace.len());
    let (seed_idx, mut seed) = resolve_seed(state, &q, before);
    let depth_limit = q.depth.min(MAX_DEPTH);
    let node_limit = q.limit.clamp(1, MAX_LIMIT);
    let graph = match seed_idx {
        Some(idx) if idx < state.inner.trace.len() => {
            seed.idx = Some(idx);
            build_graph(state, idx, seed.reg.as_deref(), depth_limit, node_limit)
        }
        Some(idx) => {
            seed.note = Some(format!("seed idx {idx} is outside trace"));
            empty_graph(depth_limit, node_limit)
        }
        None => empty_graph(depth_limit, node_limit),
    };
    DepGraphResponse {
        status: "ready",
        seed,
        graph,
    }
}

fn resolve_seed(
    state: &AppState,
    q: &DepGraphQuery,
    before: usize,
) -> (Option<usize>, DepGraphSeed) {
    if let Some(idx) = q.idx {
        return (
            Some(idx),
            DepGraphSeed {
                kind: "idx",
                idx: Some(idx),
                reg: q.reg.clone(),
                addr: None,
                before: q.before,
                note: None,
            },
        );
    }

    if let Some(reg) = q.reg.as_ref() {
        let idx = state.inner.index.last_def_before(reg, before);
        return (
            idx,
            DepGraphSeed {
                kind: "reg",
                idx,
                reg: Some(reg.clone()),
                addr: None,
                before: Some(before),
                note: idx
                    .is_none()
                    .then(|| format!("no definition of {reg} before #{before}")),
            },
        );
    }

    if let Some(addr_raw) = q.addr.as_ref() {
        let addr = parse_u64(addr_raw).unwrap_or(0);
        let idx = state
            .inner
            .index
            .mem_addr_to_writes
            .get(&addr)
            .and_then(|idxs| {
                let cut = idxs.partition_point(|idx| *idx < before);
                (cut > 0).then_some(idxs[cut - 1])
            });
        return (
            idx,
            DepGraphSeed {
                kind: "addr",
                idx,
                reg: None,
                addr: Some(format!("{addr:#x}")),
                before: Some(before),
                note: idx
                    .is_none()
                    .then(|| format!("no write to {addr:#x} before #{before}")),
            },
        );
    }

    (
        None,
        DepGraphSeed {
            kind: "none",
            idx: None,
            reg: None,
            addr: None,
            before: q.before,
            note: Some("provide idx, reg, or addr".to_string()),
        },
    )
}

fn build_graph(
    state: &AppState,
    seed_idx: usize,
    seed_reg: Option<&str>,
    depth_limit: usize,
    node_limit: usize,
) -> DepGraph {
    let analysis = state.inner.analysis_index();
    let mut queue = VecDeque::from([(seed_idx, 0usize)]);
    let mut seen = HashSet::<usize>::new();
    let mut nodes = Vec::new();
    let mut shown_idxs = HashSet::<usize>::new();
    let mut all_edges = Vec::<(DepEdge, usize)>::new();
    let mut full_node_count = 0usize;
    let mut full_edge_count = 0usize;

    while let Some((idx, depth)) = queue.pop_front() {
        if idx >= state.inner.trace.len() || !seen.insert(idx) {
            continue;
        }
        full_node_count += 1;
        if nodes.len() < node_limit {
            shown_idxs.insert(idx);
            nodes.push(node_for_idx(
                state,
                idx,
                depth,
                (idx == seed_idx).then_some(seed_reg).flatten(),
            ));
        }
        if depth >= depth_limit {
            full_edge_count += analysis.deps.row(idx).len();
            continue;
        }
        for edge in analysis.deps.row(idx) {
            full_edge_count += 1;
            all_edges.push((*edge, idx));
            if !seen.contains(&edge.idx) {
                queue.push_back((edge.idx, depth + 1));
            }
        }
    }

    let mut edges = Vec::new();
    for (edge, to_idx) in all_edges {
        if shown_idxs.contains(&edge.idx) && shown_idxs.contains(&to_idx) {
            edges.push(graph_edge(edge, to_idx));
        }
    }

    let hidden_nodes = full_node_count.saturating_sub(nodes.len());
    let hidden_edges = full_edge_count.saturating_sub(edges.len());
    DepGraph {
        nodes,
        edges,
        node_count: full_node_count,
        edge_count: full_edge_count,
        hidden_nodes,
        hidden_edges,
        truncated: hidden_nodes > 0 || hidden_edges > 0,
        depth_limit,
        node_limit,
    }
}

fn node_for_idx(
    state: &AppState,
    idx: usize,
    depth: usize,
    seed_reg: Option<&str>,
) -> DepGraphNode {
    let rec = state.inner.trace.record(idx);
    let decoded = decode(rec.pc, rec.inst);
    let asm = if decoded.op_str.is_empty() {
        decoded.mnemonic.clone()
    } else {
        format!("{} {}", decoded.mnemonic, decoded.op_str)
    };
    let via = seed_reg
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| node_via(&decoded));
    let func = state
        .inner
        .symbols
        .lookup_entry(rec.pc)
        .map(|entry| entry.name);
    DepGraphNode {
        id: node_id(idx),
        idx,
        depth,
        pc: format!("{:#x}", rec.pc),
        func,
        expression: expression_from_asm(&asm, &via, None),
        asm,
        via,
    }
}

fn node_via(decoded: &tracemiku_core::disasm::DecodedInsn) -> String {
    decoded
        .regs_def
        .first()
        .cloned()
        .or_else(|| {
            decoded
                .mem_op
                .iter()
                .any(|op| op.is_write)
                .then(|| "mem".to_string())
        })
        .unwrap_or_else(|| decoded.mnemonic.clone())
}

fn graph_edge(edge: DepEdge, to_idx: usize) -> DepGraphEdge {
    let kind = edge_kind(edge.kind);
    DepGraphEdge {
        from: node_id(edge.idx),
        to: node_id(to_idx),
        kind,
        label: edge_label(edge.kind),
    }
}

fn empty_graph(depth_limit: usize, node_limit: usize) -> DepGraph {
    DepGraph {
        nodes: Vec::new(),
        edges: Vec::new(),
        node_count: 0,
        edge_count: 0,
        hidden_nodes: 0,
        hidden_edges: 0,
        truncated: false,
        depth_limit,
        node_limit,
    }
}

fn node_id(idx: usize) -> String {
    format!("idx:{idx}")
}

fn edge_kind(kind: DepKind) -> &'static str {
    match kind {
        DepKind::Reg => "reg",
        DepKind::Address => "addr",
        DepKind::Mem => "mem",
        DepKind::Control => "control",
    }
}

fn edge_label(kind: DepKind) -> &'static str {
    match kind {
        DepKind::Reg => "reg",
        DepKind::Address => "addr",
        DepKind::Mem => "mem value",
        DepKind::Control => "control",
    }
}

fn parse_u64(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{default_depth, default_limit, parse_u64, DEFAULT_DEPTH, DEFAULT_LIMIT};

    #[test]
    fn defaults_are_stable() {
        assert_eq!(default_depth(), DEFAULT_DEPTH);
        assert_eq!(default_limit(), DEFAULT_LIMIT);
    }

    #[test]
    fn parse_u64_accepts_hex_and_decimal() {
        assert_eq!(parse_u64("0x7000"), Some(0x7000));
        assert_eq!(parse_u64("28672"), Some(0x7000));
    }
}
