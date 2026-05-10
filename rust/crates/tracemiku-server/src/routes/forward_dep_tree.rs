//! GET /api/forward-dep-tree — walk the persistent dependency CSR forward
//! (def→use direction) from a seed.
//!
//! The shape is intentionally compatible with `/api/dep-graph` so the same
//! frontend node/edge renderer can show both directions.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use tracemiku_core::forward_dep_tree::{forward_dep_tree, ForwardOptions};

use crate::routes::seed_resolver::{
    edge_kind_str, edge_label_str, node_id, render_dep_node, resolve_one, DepNode, ResolvedSeed,
};
use crate::state::AppState;

const DEFAULT_DEPTH: usize = 8;
const MAX_DEPTH: usize = 64;
const DEFAULT_LIMIT: usize = 160;
const MAX_LIMIT: usize = 2_000;

#[derive(Debug, Deserialize)]
pub struct ForwardDepTreeQuery {
    pub idx: Option<usize>,
    pub reg: Option<String>,
    pub addr: Option<String>,
    pub before: Option<usize>,
    #[serde(default = "default_depth")]
    pub depth: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub data_only: bool,
}

fn default_depth() -> usize {
    DEFAULT_DEPTH
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

#[derive(Debug, Serialize)]
pub struct ForwardDepTreeResponse {
    pub status: &'static str,
    pub seed: ResolvedSeed,
    pub graph: ForwardGraph,
}

#[derive(Debug, Serialize)]
pub struct ForwardGraph {
    pub nodes: Vec<DepNode>,
    pub edges: Vec<ForwardGraphEdge>,
    pub node_count: usize,
    pub edge_count: usize,
    pub hidden_edges: usize,
    pub truncated: bool,
    pub depth_limit: usize,
    pub node_limit: usize,
    pub data_only: bool,
}

#[derive(Debug, Serialize)]
pub struct ForwardGraphEdge {
    pub from: String,
    pub to: String,
    pub kind: &'static str,
    pub label: &'static str,
}

pub async fn forward_dep_tree_handler(
    State(state): State<AppState>,
    Query(q): Query<ForwardDepTreeQuery>,
) -> Result<Json<ForwardDepTreeResponse>, (StatusCode, String)> {
    let response = tokio::task::spawn_blocking(move || forward_dep_tree_response(&state, q))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "forward-dep-tree worker failed: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "forward-dep-tree worker failed".to_string(),
            )
        })?;
    Ok(Json(response))
}

fn forward_dep_tree_response(state: &AppState, q: ForwardDepTreeQuery) -> ForwardDepTreeResponse {
    let before = q.before.unwrap_or_else(|| state.inner.trace.len());
    let (seed_idx, mut seed) = resolve_one(
        state,
        q.idx,
        q.reg.as_deref(),
        q.addr.as_deref(),
        before,
        q.before,
    );
    // depth=0 means "seed only"; preserve the caller's intent rather than
    // silently rewriting to 1 (audit P0-1).
    let depth_limit = q.depth.min(MAX_DEPTH);
    let node_limit = q.limit.clamp(1, MAX_LIMIT);
    let graph = match seed_idx {
        Some(idx) if idx < state.inner.trace.len() => {
            seed.idx = Some(idx);
            build_forward_graph(state, idx, depth_limit, node_limit, q.data_only)
        }
        Some(idx) => {
            seed.note = Some(format!("seed idx {idx} is outside trace"));
            empty_forward_graph(depth_limit, node_limit, q.data_only)
        }
        None => empty_forward_graph(depth_limit, node_limit, q.data_only),
    };
    ForwardDepTreeResponse {
        status: "ready",
        seed,
        graph,
    }
}

fn build_forward_graph(
    state: &AppState,
    seed_idx: usize,
    depth_limit: usize,
    node_limit: usize,
    data_only: bool,
) -> ForwardGraph {
    let users = state.inner.dep_users();
    let result = forward_dep_tree(
        users,
        seed_idx,
        ForwardOptions {
            data_only,
            max_depth: depth_limit,
            max_nodes: node_limit,
        },
    );
    let nodes: Vec<DepNode> = result
        .nodes
        .iter()
        .map(|n| render_dep_node(state, n.idx, n.depth, None))
        .collect();
    let edges: Vec<ForwardGraphEdge> = result
        .edges
        .iter()
        .map(|e| ForwardGraphEdge {
            from: node_id(e.from),
            to: node_id(e.to),
            kind: edge_kind_str(e.kind),
            label: edge_label_str(e.kind),
        })
        .collect();
    ForwardGraph {
        node_count: nodes.len(),
        edge_count: edges.len(),
        hidden_edges: result.hidden_edges,
        truncated: result.truncated,
        depth_limit,
        node_limit,
        data_only,
        nodes,
        edges,
    }
}

fn empty_forward_graph(depth_limit: usize, node_limit: usize, data_only: bool) -> ForwardGraph {
    ForwardGraph {
        nodes: Vec::new(),
        edges: Vec::new(),
        node_count: 0,
        edge_count: 0,
        hidden_edges: 0,
        truncated: false,
        depth_limit,
        node_limit,
        data_only,
    }
}

#[cfg(test)]
mod tests {
    use super::{default_depth, default_limit, DEFAULT_DEPTH, DEFAULT_LIMIT};
    use crate::routes::seed_resolver::parse_u64;

    #[test]
    fn defaults_are_stable() {
        assert_eq!(default_depth(), DEFAULT_DEPTH);
        assert_eq!(default_limit(), DEFAULT_LIMIT);
    }

    #[test]
    fn parse_u64_accepts_hex_and_decimal() {
        assert_eq!(parse_u64("0x42"), Some(0x42));
        assert_eq!(parse_u64("42"), Some(42));
    }
}
