//! 前向/后向切片和图视图使用同一种子、边过滤及资源上限。
use super::dependency_seeds::{resolve_all_seeds, DependencySeeds, EdgeStats};
use super::seed_resolver::{
    annotate_outside_trace, edge_kind_str, edge_label_str, node_id, render_dep_node, DepNode,
    ResolvedSeed,
};
use super::{AnalysisContext, AnalysisError};
use crate::analysis_index::DepKind;
use crate::bfs_slice::{walk_slice, Bitset, SliceOptions, SliceResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct DependencyQuery {
    pub seeds: DependencySeeds,
    pub direction: String,
    pub view: String,
    pub depth: Option<usize>,
}
#[derive(Debug, Serialize)]
pub struct DependencyEdge {
    pub from: String,
    pub to: String,
    pub kind: &'static str,
    pub label: &'static str,
}
#[derive(Debug, Serialize)]
pub struct DependencyGraph {
    pub nodes: Vec<DepNode>,
    pub edges: Vec<DependencyEdge>,
    pub truncated: bool,
    pub node_count: usize,
    pub edge_count: usize,
}
#[derive(Debug, Serialize)]
pub struct DependencyResponse {
    pub status: &'static str,
    pub direction: String,
    pub view: String,
    pub mode: String,
    pub seed: ResolvedSeed,
    pub seeds: Vec<ResolvedSeed>,
    pub slice: Vec<usize>,
    pub rows: Vec<DepNode>,
    pub slice_count: usize,
    pub truncated: bool,
    pub rows_capped: bool,
    pub node_limit: usize,
    pub depth_limit: Option<usize>,
    pub data_only: bool,
    pub edge_stats: EdgeStats,
    pub graph: Option<DependencyGraph>,
}

pub fn dependencies(
    state: &AnalysisContext,
    q: DependencyQuery,
) -> Result<DependencyResponse, AnalysisError> {
    if !matches!(q.direction.as_str(), "forward" | "backward")
        || !matches!(q.view.as_str(), "slice" | "graph")
    {
        return Err(AnalysisError::invalid(
            "invalid dependency direction or view",
        ));
    }
    let mode = q.seeds.mode.as_deref().unwrap_or("union");
    if !matches!(mode, "union" | "intersection") || q.seeds.limit == 0 {
        return Err(AnalysisError::invalid("invalid mode or zero limit"));
    }
    let seed_count = [
        q.seeds.idx.is_some(),
        q.seeds.reg.is_some(),
        q.seeds.addr.is_some(),
    ]
    .into_iter()
    .filter(|v| *v)
    .count()
        + [&q.seeds.idxs, &q.seeds.regs, &q.seeds.addrs]
            .iter()
            .filter_map(|s| s.as_deref())
            .map(|s| s.split(',').filter(|v| !v.trim().is_empty()).count())
            .sum::<usize>();
    if seed_count == 0 || seed_count > 16 {
        return Err(AnalysisError::invalid("provide between 1 and 16 seeds"));
    }
    let n = state.inner.trace.len();
    let mut seeds = resolve_all_seeds(state, &q.seeds, q.seeds.before.unwrap_or(n));
    annotate_outside_trace(seeds.iter_mut(), n);
    let valid: Vec<_> = seeds
        .iter()
        .filter_map(|s| s.idx.filter(|&i| i < n))
        .collect();
    let cap = q
        .seeds
        .limit
        .min(if q.view == "graph" { 2000 } else { 200_000 });
    let opts = SliceOptions {
        data_only: q.seeds.data_only,
        max_nodes: cap,
    };
    let deps = &state.inner.analysis_index().deps;
    let users = (q.direction == "forward").then(|| state.inner.dep_users());
    let neighbours = |idx| -> Box<dyn Iterator<Item = (usize, DepKind)> + '_> {
        match users {
            Some(users) => Box::new(users.row(idx).map(|e| (e.idx, e.kind))),
            None => Box::new(deps.row(idx).iter().map(|e| (e.idx, e.kind))),
        }
    };
    let (mut result, mut depths) = if mode == "union" {
        walk_slice(n, &valid, opts, q.depth, neighbours)
    } else {
        let mut combined: Option<(SliceResult, std::collections::HashMap<usize, usize>)> = None;
        for seed in &valid {
            let (r, ds) = walk_slice(n, &[*seed], opts, q.depth, neighbours);
            if let Some((acc, prev_depths)) = &mut combined {
                acc.truncated |= r.truncated;
                acc.marked.intersect_in_place(&r.marked);
                acc.idxs.retain(|i| acc.marked.get(*i));
                prev_depths.retain(|i, _| acc.marked.get(*i));
            } else {
                combined = Some((r, ds));
            }
        }
        combined.unwrap_or_else(|| {
            (
                SliceResult {
                    marked: Bitset::with_len(n),
                    idxs: Vec::new(),
                    truncated: false,
                },
                std::collections::HashMap::new(),
            )
        })
    };
    if valid.len() != seeds.len() {
        result.truncated = true;
        if mode == "intersection" {
            result.idxs.clear();
            result.marked = Bitset::with_len(n);
            depths.clear();
        }
    }
    let rows = result
        .idxs
        .iter()
        .take(2000)
        .map(|&idx| render_dep_node(state, idx, depths.get(&idx).copied().unwrap_or(0), None))
        .collect::<Vec<_>>();
    let mut stats = EdgeStats::default();
    let mut edges = Vec::new();
    let mut edges_capped = false;
    // 图中箭头始终定义→使用，遍历方向不改变证据关系。
    for &idx in &result.idxs {
        for e in deps.row(idx) {
            if !result.marked.get(e.idx) || (q.seeds.data_only && e.kind == DepKind::Control) {
                continue;
            }
            match e.kind {
                DepKind::Reg => stats.reg += 1,
                DepKind::Address => stats.address += 1,
                DepKind::Mem => stats.mem += 1,
                DepKind::Control => stats.control += 1,
            };
            stats.total += 1;
            if q.view == "graph" {
                if edges.len() < 10_000 {
                    edges.push(DependencyEdge {
                        from: node_id(e.idx),
                        to: node_id(idx),
                        kind: edge_kind_str(e.kind),
                        label: edge_label_str(e.kind),
                    });
                } else {
                    edges_capped = true;
                }
            }
        }
    }
    let graph = (q.view == "graph").then(|| DependencyGraph {
        nodes: result
            .idxs
            .iter()
            .map(|&idx| render_dep_node(state, idx, depths[&idx], None))
            .collect(),
        edge_count: edges.len(),
        edges,
        node_count: result.idxs.len(),
        truncated: result.truncated || edges_capped,
    });
    Ok(DependencyResponse {
        status: "ready",
        direction: q.direction,
        view: q.view,
        mode: mode.to_string(),
        seed: seeds[0].clone(),
        seeds,
        slice_count: result.idxs.len(),
        rows_capped: rows.len() < result.idxs.len(),
        slice: result.idxs,
        rows,
        truncated: result.truncated || edges_capped,
        node_limit: cap,
        depth_limit: q.depth,
        data_only: q.seeds.data_only,
        edge_stats: stats,
        graph,
    })
}
