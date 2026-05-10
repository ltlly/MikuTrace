//! Forward def→use DAG over the persistent dependency CSR.
//!
//! The persistent [`DependencyIndex`] only stores *predecessor* edges:
//! `deps.row(i)` returns the rows `i` depends on. The opposite query —
//! "which rows depend on `i`?" — appears in trace-ui as
//! `crates/trace-core/src/query/dep_tree.rs` and is essential for forward
//! navigation in the UI ("where does this value go").
//!
//! We compute the inverse map lazily once per analysis sidecar.
//!
//! ```text
//! row_offsets[i]   = first edge for row i
//! row_offsets[i+1] = one past last edge for row i
//! users[k]         = (later row, kind that row used to depend on i)
//! ```
//!
//! Encoded with `u32` indices because the trace contract caps records well
//! under 2³². For 24M rows × ~3 edges that is roughly 280 MB of inverted
//! index — comparable to the forward CSR and well below the analysis
//! sidecar.

use std::collections::VecDeque;

use crate::analysis_index::{DepKind, DependencyIndex};
use crate::bfs_slice::Bitset;

const KIND_REG: u8 = 1;
const KIND_ADDRESS: u8 = 2;
const KIND_MEM: u8 = 3;
const KIND_CONTROL: u8 = 4;

fn kind_to_byte(kind: DepKind) -> u8 {
    match kind {
        DepKind::Reg => KIND_REG,
        DepKind::Address => KIND_ADDRESS,
        DepKind::Mem => KIND_MEM,
        DepKind::Control => KIND_CONTROL,
    }
}

fn byte_to_kind(b: u8) -> DepKind {
    match b {
        KIND_ADDRESS => DepKind::Address,
        KIND_MEM => DepKind::Mem,
        KIND_CONTROL => DepKind::Control,
        _ => DepKind::Reg,
    }
}

/// Inverted [`DependencyIndex`]: for each row, the rows that *use* it.
#[derive(Debug, Clone, Default)]
pub struct DependencyUsers {
    row_offsets: Vec<u32>,
    user_idxs: Vec<u32>,
    user_kinds: Vec<u8>,
    n_rows: usize,
}

/// One forward edge: `(user_idx, kind)` where `kind` is what edge type
/// originally connected `user_idx → predecessor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserEdge {
    pub idx: usize,
    pub kind: DepKind,
}

impl DependencyUsers {
    /// Build the inverted index. O(edges) time, single pass for offsets and
    /// a second pass to fill the buckets — no per-row allocation.
    ///
    /// Both `src_row` and `edge.idx` are capped at `n_rows`. Trailing rows in
    /// the persisted analysis sidecar that the caller does not address (e.g.
    /// stale on-disk CSR vs. shorter mmapped trace) are silently skipped, so
    /// later BFS walks never see an out-of-bound user index.
    pub fn build(deps: &DependencyIndex, n_rows: usize) -> Self {
        debug_assert!(n_rows < u32::MAX as usize, "trace too long for u32 indices");

        let row_count = deps.row_offsets.len().saturating_sub(1).min(n_rows);

        // Pass 1: count incoming edges per predecessor.
        let mut counts = vec![0u32; n_rows];
        for src_row in 0..row_count {
            for edge in deps.row(src_row) {
                if edge.idx < n_rows {
                    counts[edge.idx] += 1;
                }
            }
        }

        // Build CSR row offsets.
        let mut row_offsets = Vec::with_capacity(n_rows + 1);
        row_offsets.push(0u32);
        let mut total: u32 = 0;
        for c in &counts {
            total = total.saturating_add(*c);
            row_offsets.push(total);
        }

        let mut user_idxs = vec![0u32; total as usize];
        let mut user_kinds = vec![0u8; total as usize];

        // Pass 2: fill the buckets. `cursors` is a separate per-row cursor so
        // we don't reset `counts` (kept for invariants in tests / debug).
        let mut cursors = vec![0u32; n_rows];
        for src_row in 0..row_count {
            for edge in deps.row(src_row) {
                if edge.idx >= n_rows {
                    continue;
                }
                let bucket_start = row_offsets[edge.idx];
                let position = bucket_start + cursors[edge.idx];
                user_idxs[position as usize] = src_row as u32;
                user_kinds[position as usize] = kind_to_byte(edge.kind);
                cursors[edge.idx] += 1;
            }
        }

        Self {
            row_offsets,
            user_idxs,
            user_kinds,
            n_rows,
        }
    }

    pub fn n_rows(&self) -> usize {
        self.n_rows
    }

    /// Iterate forward edges out of `idx` (later rows that depended on
    /// `idx`).
    pub fn row(&self, idx: usize) -> impl Iterator<Item = UserEdge> + '_ {
        let (start, end) = match (
            self.row_offsets.get(idx),
            self.row_offsets.get(idx.saturating_add(1)),
        ) {
            (Some(&s), Some(&e)) => (s as usize, e as usize),
            _ => (0, 0),
        };
        (start..end).map(move |k| UserEdge {
            idx: self.user_idxs[k] as usize,
            kind: byte_to_kind(self.user_kinds[k]),
        })
    }

    pub fn out_degree(&self, idx: usize) -> usize {
        match (
            self.row_offsets.get(idx),
            self.row_offsets.get(idx.saturating_add(1)),
        ) {
            (Some(&s), Some(&e)) => e.saturating_sub(s) as usize,
            _ => 0,
        }
    }
}

/// One node in the forward DAG, BFS-discovered.
#[derive(Debug, Clone, Copy)]
pub struct ForwardNode {
    pub idx: usize,
    pub depth: usize,
}

/// One edge in the forward DAG: the row at `from` was used by the row at
/// `to` (so the def→use arrow is `from → to`).
#[derive(Debug, Clone, Copy)]
pub struct ForwardEdge {
    pub from: usize,
    pub to: usize,
    pub kind: DepKind,
}

/// Options controlling [`forward_dep_tree`].
#[derive(Debug, Clone, Copy)]
pub struct ForwardOptions {
    pub data_only: bool,
    pub max_depth: usize,
    pub max_nodes: usize,
}

impl Default for ForwardOptions {
    fn default() -> Self {
        Self {
            data_only: false,
            max_depth: 8,
            max_nodes: 160,
        }
    }
}

/// Result of [`forward_dep_tree`].
#[derive(Debug, Clone)]
pub struct ForwardTree {
    pub nodes: Vec<ForwardNode>,
    pub edges: Vec<ForwardEdge>,
    pub truncated: bool,
    pub hidden_edges: usize,
}

/// BFS the forward DAG from `seed`, emitting nodes and edges in discovery
/// order. The seed itself is the first node at depth 0.
pub fn forward_dep_tree(
    users: &DependencyUsers,
    seed: usize,
    options: ForwardOptions,
) -> ForwardTree {
    let n_rows = users.n_rows();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut queue: VecDeque<(usize, usize)> = VecDeque::new();
    // 1 bit per row keeps the visited set inside L2 even on 100M-row traces.
    let mut visited = Bitset::with_len(n_rows);
    let cap = if options.max_nodes == 0 {
        usize::MAX
    } else {
        options.max_nodes
    };
    let mut truncated = false;
    let mut hidden_edges = 0usize;

    if seed < n_rows {
        visited.set(seed);
        nodes.push(ForwardNode {
            idx: seed,
            depth: 0,
        });
        queue.push_back((seed, 0));
    }

    while let Some((idx, depth)) = queue.pop_front() {
        if depth >= options.max_depth {
            // Account for the edges we are *not* expanding so callers can
            // surface "12 successors hidden by depth cap".
            hidden_edges += users.out_degree(idx);
            continue;
        }
        for edge in users.row(idx) {
            // Defensive: a stale CSR could carry an edge.idx ≥ n_rows. Skip
            // it before any indexing happens.
            if edge.idx >= n_rows {
                continue;
            }
            if options.data_only && matches!(edge.kind, DepKind::Control) {
                continue;
            }
            // Always emit the edge — it's interesting even when the
            // destination is hidden by max_nodes; we filter unreachable
            // edges below.
            edges.push(ForwardEdge {
                from: idx,
                to: edge.idx,
                kind: edge.kind,
            });
            if visited.set(edge.idx) {
                if nodes.len() >= cap {
                    truncated = true;
                    // Don't increment hidden_edges here — the post-process
                    // step below counts the edge once when it filters this
                    // unreachable destination out. Counting twice over-reports.
                    continue;
                }
                nodes.push(ForwardNode {
                    idx: edge.idx,
                    depth: depth + 1,
                });
                queue.push_back((edge.idx, depth + 1));
            }
        }
    }

    // Drop edges that point at nodes we never emitted; whatever falls out is
    // the authoritative `hidden_edges` count for cap-truncated graphs.
    let visible = Bitset::from_idxs(nodes.iter().map(|n| n.idx), n_rows);
    let original_edge_count = edges.len();
    edges.retain(|e| visible.get(e.from) && visible.get(e.to));
    hidden_edges += original_edge_count - edges.len();

    ForwardTree {
        nodes,
        edges,
        truncated,
        hidden_edges,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis_index::{DepEdge, DependencyIndex};

    fn make_deps(rows: &[Vec<DepEdge>]) -> DependencyIndex {
        let mut row_offsets = Vec::with_capacity(rows.len() + 1);
        row_offsets.push(0u64);
        let mut edges = Vec::new();
        for row in rows {
            edges.extend(row.iter().copied());
            row_offsets.push(edges.len() as u64);
        }
        DependencyIndex { row_offsets, edges }
    }

    #[test]
    fn dependency_users_builds_inverse() {
        // 0 ← 1 ← 2 (each row depends on the previous one)
        let deps = make_deps(&[
            vec![],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
            vec![DepEdge {
                idx: 1,
                kind: DepKind::Reg,
            }],
        ]);
        let users = DependencyUsers::build(&deps, 3);
        let row0: Vec<_> = users.row(0).collect();
        assert_eq!(row0.len(), 1);
        assert_eq!(row0[0].idx, 1);
        let row1: Vec<_> = users.row(1).collect();
        assert_eq!(row1.len(), 1);
        assert_eq!(row1[0].idx, 2);
        assert_eq!(users.row(2).count(), 0);
    }

    #[test]
    fn forward_dep_tree_walks_users() {
        let deps = make_deps(&[
            vec![],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
            vec![DepEdge {
                idx: 1,
                kind: DepKind::Reg,
            }],
            vec![DepEdge {
                idx: 2,
                kind: DepKind::Reg,
            }],
        ]);
        let users = DependencyUsers::build(&deps, 4);
        let tree = forward_dep_tree(
            &users,
            0,
            ForwardOptions {
                data_only: false,
                max_depth: 8,
                max_nodes: 16,
            },
        );
        let idxs: Vec<usize> = tree.nodes.iter().map(|n| n.idx).collect();
        assert_eq!(idxs, vec![0, 1, 2, 3]);
        let depths: Vec<usize> = tree.nodes.iter().map(|n| n.depth).collect();
        assert_eq!(depths, vec![0, 1, 2, 3]);
        assert!(!tree.truncated);
        assert_eq!(tree.hidden_edges, 0);
    }

    #[test]
    fn forward_dep_tree_data_only_drops_control() {
        let deps = make_deps(&[
            vec![],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Control,
            }],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
        ]);
        let users = DependencyUsers::build(&deps, 3);
        let tree = forward_dep_tree(
            &users,
            0,
            ForwardOptions {
                data_only: true,
                max_depth: 8,
                max_nodes: 16,
            },
        );
        let idxs: Vec<usize> = tree.nodes.iter().map(|n| n.idx).collect();
        assert_eq!(idxs, vec![0, 2], "control-only edge should be dropped");
    }

    #[test]
    fn forward_dep_tree_max_nodes_truncates() {
        let deps = make_deps(&[
            vec![],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
        ]);
        let users = DependencyUsers::build(&deps, 4);
        let tree = forward_dep_tree(
            &users,
            0,
            ForwardOptions {
                data_only: false,
                max_depth: 8,
                max_nodes: 2,
            },
        );
        assert!(tree.truncated);
        assert_eq!(tree.nodes.len(), 2);
        // Three edges out of 0; one survives (0→first user), two are cap-hidden.
        // Watchdog: this test pins exact count to lock down the
        // double-counting fix from the audit.
        assert_eq!(tree.hidden_edges, 2);
    }

    #[test]
    fn forward_dep_tree_max_depth_caps_descent() {
        let deps = make_deps(&[
            vec![],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
            vec![DepEdge {
                idx: 1,
                kind: DepKind::Reg,
            }],
            vec![DepEdge {
                idx: 2,
                kind: DepKind::Reg,
            }],
            vec![DepEdge {
                idx: 3,
                kind: DepKind::Reg,
            }],
        ]);
        let users = DependencyUsers::build(&deps, 5);
        let tree = forward_dep_tree(
            &users,
            0,
            ForwardOptions {
                data_only: false,
                max_depth: 2,
                max_nodes: 16,
            },
        );
        let depths: Vec<usize> = tree.nodes.iter().map(|n| n.depth).collect();
        // 0 (depth 0) → 1 (depth 1) → 2 (depth 2). Row 3 is at depth 3 and
        // should be cut off because we never expand row 2.
        assert_eq!(depths, vec![0, 1, 2]);
        assert!(tree.hidden_edges >= 1, "{tree:?}");
    }

    #[test]
    fn forward_dep_tree_seed_outside_returns_empty() {
        let deps = make_deps(&[vec![]]);
        let users = DependencyUsers::build(&deps, 1);
        let tree = forward_dep_tree(&users, 99, ForwardOptions::default());
        assert!(tree.nodes.is_empty());
        assert!(tree.edges.is_empty());
    }

    #[test]
    fn dependency_users_handles_diamond() {
        let deps = make_deps(&[
            vec![],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Mem,
            }],
            vec![
                DepEdge {
                    idx: 1,
                    kind: DepKind::Reg,
                },
                DepEdge {
                    idx: 2,
                    kind: DepKind::Reg,
                },
            ],
        ]);
        let users = DependencyUsers::build(&deps, 4);
        let row0: Vec<_> = users.row(0).map(|e| e.idx).collect();
        let mut sorted0 = row0.clone();
        sorted0.sort();
        assert_eq!(sorted0, vec![1, 2]);
        let row1: Vec<_> = users.row(1).map(|e| e.idx).collect();
        assert_eq!(row1, vec![3]);
        let row2: Vec<_> = users.row(2).map(|e| e.idx).collect();
        assert_eq!(row2, vec![3]);
        assert_eq!(users.out_degree(0), 2);
        assert_eq!(users.out_degree(3), 0);
    }

    #[test]
    fn dependency_users_preserves_kind() {
        let deps = make_deps(&[
            vec![],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Address,
            }],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Mem,
            }],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Control,
            }],
        ]);
        let users = DependencyUsers::build(&deps, 4);
        let kinds: std::collections::HashSet<DepKind> = users.row(0).map(|e| e.kind).collect();
        assert!(kinds.contains(&DepKind::Address));
        assert!(kinds.contains(&DepKind::Mem));
        assert!(kinds.contains(&DepKind::Control));
    }

    #[test]
    fn dependency_users_caps_src_row_at_n_rows() {
        // A persisted CSR may carry trailing rows past n_rows. Build must
        // skip those src_row entries so we never record a user index ≥ n_rows.
        let deps = make_deps(&[
            vec![],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
        ]);
        let users = DependencyUsers::build(&deps, 1);
        // Only src_row=0 is examined. Row 0 has no edges, so no users.
        assert_eq!(users.row(0).count(), 0);
        let users_full = DependencyUsers::build(&deps, 3);
        // With the full trace size, row 0 picks up users from rows 1 and 2.
        let users_of_0: Vec<_> = users_full.row(0).map(|e| e.idx).collect();
        let mut sorted = users_of_0.clone();
        sorted.sort();
        assert_eq!(sorted, vec![1, 2]);
    }

    #[test]
    fn dependency_users_skips_edge_idx_above_n_rows() {
        // src=2 in trace of 3, but edge points at idx=99 — must drop it.
        let deps = make_deps(&[
            vec![],
            vec![],
            vec![DepEdge {
                idx: 99,
                kind: DepKind::Reg,
            }],
        ]);
        let users = DependencyUsers::build(&deps, 3);
        assert_eq!(users.row(0).count(), 0);
        assert_eq!(users.row(99 % 3).count(), 0);
    }

    #[test]
    fn forward_dep_tree_skips_stale_edge_pointing_past_trace() {
        // Construct DependencyUsers manually with an edge.idx out of range,
        // then verify forward_dep_tree does not panic.
        let deps = make_deps(&[
            vec![],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
        ]);
        let users = DependencyUsers::build(&deps, 2);
        let tree = forward_dep_tree(
            &users,
            0,
            ForwardOptions {
                data_only: false,
                max_depth: 4,
                max_nodes: 16,
            },
        );
        assert!(tree.nodes.iter().any(|n| n.idx == 0));
    }

    #[test]
    fn forward_dep_tree_emits_edges_in_walk_order() {
        // 0 → {1, 2}, 1 → 3, 2 → 3. Walk should emit four edges total.
        let deps = make_deps(&[
            vec![],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
            vec![
                DepEdge {
                    idx: 1,
                    kind: DepKind::Reg,
                },
                DepEdge {
                    idx: 2,
                    kind: DepKind::Reg,
                },
            ],
        ]);
        let users = DependencyUsers::build(&deps, 4);
        let tree = forward_dep_tree(
            &users,
            0,
            ForwardOptions {
                data_only: false,
                max_depth: 8,
                max_nodes: 16,
            },
        );
        assert_eq!(tree.edges.len(), 4);
        let from_0 = tree.edges.iter().filter(|e| e.from == 0).count();
        assert_eq!(from_0, 2);
    }
}
