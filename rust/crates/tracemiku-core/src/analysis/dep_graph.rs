//! 按种子查询有界依赖图。
//!
//! Backward dependency DAG backed by the persistent whole-trace analysis index.
//! A seed can be a concrete trace index, the last definition of a register
//! before a cursor, or the last write to an address before a cursor.

use super::AnalysisError;
use std::collections::VecDeque;

use crate::analysis_index::DepEdge;
use crate::bfs_slice::Bitset;
use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;
use crate::analysis::seed_resolver::{
    edge_kind_str, edge_label_str, node_id, render_dep_node, resolve_one, DepNode, ResolvedSeed,
};

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
    pub seed: ResolvedSeed,
    pub graph: DepGraph,
}

#[derive(Debug, Serialize)]
pub struct DepGraph {
    pub nodes: Vec<DepNode>,
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
pub struct DepGraphEdge {
    pub from: String,
    pub to: String,
    pub kind: &'static str,
    pub label: &'static str,
}

pub fn dep_graph(
    state: &AnalysisContext,
    q: DepGraphQuery,
) -> Result<DepGraphResponse, AnalysisError> {
    let response = dep_graph_response(state, q);
    Ok(response)
}

fn dep_graph_response(state: &AnalysisContext, q: DepGraphQuery) -> DepGraphResponse {
    let before = q.before.unwrap_or_else(|| state.inner.trace.len());
    let (seed_idx, mut seed) = resolve_one(
        state,
        q.idx,
        q.reg.as_deref(),
        q.addr.as_deref(),
        before,
        q.before,
    );
    let depth_limit = q.depth.min(MAX_DEPTH);
    let node_limit = q.limit.clamp(1, MAX_LIMIT);
    let graph = match seed_idx {
        Some(idx) if idx < state.inner.trace.len() => {
            seed.idx = Some(idx);
            build_graph(state, idx, q.reg.as_deref(), depth_limit, node_limit)
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

fn build_graph(
    state: &AnalysisContext,
    seed_idx: usize,
    seed_reg: Option<&str>,
    depth_limit: usize,
    node_limit: usize,
) -> DepGraph {
    let analysis = state.inner.analysis_index();
    let trace_len = state.inner.trace.len();
    let mut queue = VecDeque::from([(seed_idx, 0usize)]);
    // 1 bit per row keeps the visited set bounded even on 100M-row traces.
    let mut seen = Bitset::with_len(trace_len);
    let mut shown = Bitset::with_len(trace_len);
    let mut nodes = Vec::new();
    let mut all_edges = Vec::<(DepEdge, usize)>::new();
    let mut full_node_count = 0usize;
    let mut full_edge_count = 0usize;

    while let Some((idx, depth)) = queue.pop_front() {
        if idx >= trace_len {
            continue;
        }
        if !seen.set(idx) {
            continue;
        }
        full_node_count += 1;
        if nodes.len() < node_limit {
            shown.set(idx);
            nodes.push(render_dep_node(
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
            if edge.idx < trace_len && !seen.get(edge.idx) {
                queue.push_back((edge.idx, depth + 1));
            }
        }
    }

    let mut edges = Vec::new();
    for (edge, to_idx) in all_edges {
        if shown.get(edge.idx) && shown.get(to_idx) {
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

fn graph_edge(edge: DepEdge, to_idx: usize) -> DepGraphEdge {
    DepGraphEdge {
        from: node_id(edge.idx),
        to: node_id(to_idx),
        kind: edge_kind_str(edge.kind),
        label: edge_label_str(edge.kind),
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

#[cfg(test)]
mod tests {
    use super::{default_depth, default_limit, DEFAULT_DEPTH, DEFAULT_LIMIT};
    use crate::analysis::parse::parse_dec_u64;

    #[test]
    fn defaults_are_stable() {
        assert_eq!(default_depth(), DEFAULT_DEPTH);
        assert_eq!(default_limit(), DEFAULT_LIMIT);
    }

    #[test]
    fn parse_dec_u64_accepts_hex_and_decimal() {
        assert_eq!(parse_dec_u64("0x7000"), Some(0x7000));
        assert_eq!(parse_dec_u64("28672"), Some(0x7000));
    }
}

impl Default for DepGraphQuery {
    fn default() -> Self {
        Self {
            idx: Default::default(),
            reg: Default::default(),
            addr: Default::default(),
            before: Default::default(),
            depth: default_depth(),
            limit: default_limit(),
        }
    }
}
