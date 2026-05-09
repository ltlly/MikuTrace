use std::collections::HashSet;

use serde::Serialize;

pub const TAINT_GRAPH_NODE_LIMIT: usize = 160;
pub const TAINT_GRAPH_EDGE_LIMIT: usize = 240;

#[derive(Debug, Serialize)]
pub struct TaintGraph {
    pub nodes: Vec<TaintGraphNode>,
    pub edges: Vec<TaintGraphEdge>,
    pub node_count: usize,
    pub edge_count: usize,
    pub hidden_nodes: usize,
    pub hidden_edges: usize,
    pub truncated: bool,
    pub node_limit: usize,
    pub edge_limit: usize,
}

#[derive(Debug, Serialize)]
pub struct TaintGraphNode {
    pub id: String,
    pub label: String,
    pub idx: Option<usize>,
    pub func: Option<String>,
    pub asm: String,
    pub via: String,
    pub kind: &'static str,
    pub taint_depth: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_kind: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TaintGraphEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub label: String,
}

pub trait TaintGraphRow {
    fn idx(&self) -> usize;
    fn func(&self) -> Option<&str>;
    fn asm(&self) -> &str;
    fn via(&self) -> &str;
    fn edge_kind(&self) -> Option<&str>;
    fn parent_idxs(&self) -> &[usize];
    fn taint_depth(&self) -> u32;
}

pub fn empty_taint_graph(from: usize, reg: &str) -> TaintGraph {
    TaintGraph {
        nodes: vec![seed_node(from, reg)],
        edges: Vec::new(),
        node_count: 1,
        edge_count: 0,
        hidden_nodes: 0,
        hidden_edges: 0,
        truncated: false,
        node_limit: TAINT_GRAPH_NODE_LIMIT,
        edge_limit: TAINT_GRAPH_EDGE_LIMIT,
    }
}

pub fn build_taint_graph<R: TaintGraphRow>(from: usize, reg: &str, rows: &[R]) -> TaintGraph {
    let has_start_row = rows.iter().any(|row| row.idx() == from);
    let include_synthetic_seed = !has_start_row;
    let node_count = rows.len() + usize::from(include_synthetic_seed);
    let edge_count = rows
        .iter()
        .map(|row| {
            if row.parent_idxs().is_empty() {
                usize::from(include_synthetic_seed)
            } else {
                unique_parent_count(row.parent_idxs())
            }
        })
        .sum::<usize>();

    let mut nodes = Vec::new();
    if include_synthetic_seed {
        nodes.push(seed_node(from, reg));
    }
    for row in rows {
        if nodes.len() >= TAINT_GRAPH_NODE_LIMIT {
            break;
        }
        nodes.push(TaintGraphNode {
            id: idx_node_id(row.idx()),
            label: format!("#{}", row.idx()),
            idx: Some(row.idx()),
            func: row.func().map(ToOwned::to_owned),
            asm: row.asm().to_string(),
            via: row.via().to_string(),
            kind: if row.idx() == from { "seed" } else { "record" },
            taint_depth: row.taint_depth(),
            edge_kind: row.edge_kind().map(ToOwned::to_owned),
        });
    }

    let shown = nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<HashSet<_>>();
    let mut edges = Vec::new();
    let mut hidden_edges = 0usize;
    for row in rows {
        let to = idx_node_id(row.idx());
        if !shown.contains(&to) {
            hidden_edges += graph_edge_count_for_row(row, include_synthetic_seed);
            continue;
        }
        if row.parent_idxs().is_empty() {
            if include_synthetic_seed {
                push_graph_edge(
                    &mut edges,
                    &mut hidden_edges,
                    "seed".to_string(),
                    to,
                    "seed",
                );
            }
            continue;
        }
        let mut seen_parents = HashSet::new();
        for parent in row.parent_idxs() {
            if !seen_parents.insert(*parent) {
                continue;
            }
            let from_id = idx_node_id(*parent);
            if shown.contains(&from_id) {
                push_graph_edge(
                    &mut edges,
                    &mut hidden_edges,
                    from_id,
                    to.clone(),
                    row.edge_kind().unwrap_or("reg"),
                );
            } else {
                hidden_edges += 1;
            }
        }
    }

    let hidden_nodes = node_count.saturating_sub(nodes.len());
    TaintGraph {
        nodes,
        edges,
        node_count,
        edge_count,
        hidden_nodes,
        hidden_edges,
        truncated: hidden_nodes > 0 || hidden_edges > 0,
        node_limit: TAINT_GRAPH_NODE_LIMIT,
        edge_limit: TAINT_GRAPH_EDGE_LIMIT,
    }
}

fn seed_node(from: usize, reg: &str) -> TaintGraphNode {
    TaintGraphNode {
        id: "seed".to_string(),
        label: format!("#{from} seed"),
        idx: Some(from),
        func: None,
        asm: format!("seed {reg}"),
        via: reg.to_string(),
        kind: "seed",
        taint_depth: 0,
        edge_kind: Some("seed".to_string()),
    }
}

fn idx_node_id(idx: usize) -> String {
    format!("idx:{idx}")
}

fn graph_edge_count_for_row<R: TaintGraphRow>(row: &R, include_synthetic_seed: bool) -> usize {
    if row.parent_idxs().is_empty() {
        usize::from(include_synthetic_seed)
    } else {
        unique_parent_count(row.parent_idxs())
    }
}

fn unique_parent_count(parent_idxs: &[usize]) -> usize {
    parent_idxs.iter().copied().collect::<HashSet<_>>().len()
}

fn push_graph_edge(
    edges: &mut Vec<TaintGraphEdge>,
    hidden_edges: &mut usize,
    from: String,
    to: String,
    kind: &str,
) {
    if edges.len() >= TAINT_GRAPH_EDGE_LIMIT {
        *hidden_edges += 1;
        return;
    }
    edges.push(TaintGraphEdge {
        from,
        to,
        kind: kind.to_string(),
        label: edge_label(kind),
    });
}

fn edge_label(kind: &str) -> String {
    match kind {
        "addr" => "addr",
        "mem" => "mem value",
        "store-src" => "store src",
        "reg+mem" => "reg+mem",
        "control" => "control",
        "control-reg" => "control reg",
        "seed" => "seed",
        "reg" => "reg",
        _ => kind,
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{build_taint_graph, TaintGraphRow};

    struct Row {
        idx: usize,
        parents: Vec<usize>,
        edge_kind: Option<&'static str>,
    }

    impl TaintGraphRow for Row {
        fn idx(&self) -> usize {
            self.idx
        }

        fn func(&self) -> Option<&str> {
            None
        }

        fn asm(&self) -> &str {
            "add x0, x0, #1"
        }

        fn via(&self) -> &str {
            "x0"
        }

        fn edge_kind(&self) -> Option<&str> {
            self.edge_kind
        }

        fn parent_idxs(&self) -> &[usize] {
            &self.parents
        }

        fn taint_depth(&self) -> u32 {
            0
        }
    }

    #[test]
    fn backward_start_row_with_parents_does_not_add_orphan_seed() {
        let rows = vec![
            Row {
                idx: 3,
                parents: vec![4],
                edge_kind: Some("reg"),
            },
            Row {
                idx: 4,
                parents: vec![5],
                edge_kind: Some("mem"),
            },
        ];
        let graph = build_taint_graph(4, "x0", &rows);
        assert!(!graph.nodes.iter().any(|node| node.id == "seed"));
        let start = graph
            .nodes
            .iter()
            .find(|node| node.id == "idx:4")
            .expect("start row should be represented by its real record node");
        assert_eq!(start.kind, "seed");
        assert_eq!(graph.edge_count, 2);
        assert_eq!(graph.hidden_edges, 1, "parent #5 is outside visible rows");
    }

    #[test]
    fn forward_roots_without_start_row_link_to_synthetic_seed() {
        let rows = vec![
            Row {
                idx: 1,
                parents: Vec::new(),
                edge_kind: Some("reg"),
            },
            Row {
                idx: 2,
                parents: vec![1, 1],
                edge_kind: Some("reg"),
            },
        ];
        let graph = build_taint_graph(0, "x0", &rows);
        assert!(graph.nodes.iter().any(|node| node.id == "seed"));
        assert!(graph
            .edges
            .iter()
            .any(|edge| edge.from == "seed" && edge.to == "idx:1"));
        assert_eq!(
            graph
                .edges
                .iter()
                .filter(|edge| edge.from == "idx:1" && edge.to == "idx:2")
                .count(),
            1,
            "duplicate parent ids should not render duplicate graph edges"
        );
        assert_eq!(graph.edge_count, 2);
        assert_eq!(graph.hidden_edges, 0);
    }
}
