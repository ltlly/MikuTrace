//! Backward BFS slicing on the persistent dependency CSR.
//!
//! Borrowed from `imj01y/trace-ui` (`crates/trace-core/src/query/slice.rs`).
//! Given a seed trace index, walk the dependency edges in
//! [`crate::analysis_index::DependencyIndex`] backwards (predecessor
//! direction) and return the rows the seed transitively depends on.
//!
//! The walk uses a packed bitset (`Bitset`) for the visited set: 1 bit per
//! trace row keeps the working set inside L2 even on 100M-row traces. The
//! function also returns the slice rows in walk order so callers that just
//! need a list of indices can skip a sort over the bitset.
//!
//! `data_only` filters control edges out at the *edge* level. This is
//! deliberately the same shape as trace-ui — controlling on the node loses
//! information when a row has both a data and a control predecessor.

use std::collections::VecDeque;

use crate::analysis_index::{DepKind, DependencyIndex};

/// Compact bitset over trace row indices.
///
/// Stored as `Vec<u64>`, so a 100M-row trace fits in ~12.5 MB. Operations
/// are inline and branchless on the hot path.
#[derive(Debug, Clone, Default)]
pub struct Bitset {
    words: Vec<u64>,
    len: usize,
}

impl Bitset {
    /// Allocate a bitset that covers `len` rows. All bits are clear.
    pub fn with_len(len: usize) -> Self {
        let n_words = len.div_ceil(64);
        Self {
            words: vec![0; n_words],
            len,
        }
    }

    /// Build a bitset of `len` rows pre-populated with the given indices.
    /// Out-of-range indices are silently ignored (same contract as
    /// [`Self::set`]).
    pub fn from_idxs<I: IntoIterator<Item = usize>>(idxs: I, len: usize) -> Self {
        let mut bs = Self::with_len(len);
        for idx in idxs {
            bs.set(idx);
        }
        bs
    }

    /// In-place AND with another bitset. The shorter operand wins; trailing
    /// words past the shorter `len` stay zero. Both bitsets must address the
    /// same trace length.
    pub fn intersect_in_place(&mut self, other: &Bitset) {
        debug_assert_eq!(self.len, other.len, "intersect requires matching lengths");
        let n = self.words.len().min(other.words.len());
        for i in 0..n {
            self.words[i] &= other.words[i];
        }
        // If `self` is longer than `other` for any reason, zero the trailing
        // words so we don't keep stale bits.
        for i in n..self.words.len() {
            self.words[i] = 0;
        }
    }

    /// In-place OR with another bitset.
    pub fn union_in_place(&mut self, other: &Bitset) {
        debug_assert_eq!(self.len, other.len, "union requires matching lengths");
        let n = self.words.len().min(other.words.len());
        for i in 0..n {
            self.words[i] |= other.words[i];
        }
    }

    /// Number of trace rows this bitset addresses.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True iff [`Self::len`] is zero.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return the bit at `idx`. Out-of-range queries are false.
    #[inline]
    pub fn get(&self, idx: usize) -> bool {
        if idx >= self.len {
            return false;
        }
        let (w, b) = (idx >> 6, idx & 63);
        (self.words[w] >> b) & 1 == 1
    }

    /// Set the bit at `idx`. Returns true iff the bit was previously clear.
    /// Out-of-range writes are silent no-ops (the seed loop uses this to skip
    /// trailing seeds without an extra branch).
    #[inline]
    pub fn set(&mut self, idx: usize) -> bool {
        if idx >= self.len {
            return false;
        }
        let (w, b) = (idx >> 6, idx & 63);
        let mask = 1u64 << b;
        let was = (self.words[w] & mask) != 0;
        self.words[w] |= mask;
        !was
    }

    /// Number of set bits.
    pub fn count_ones(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Iterate set bit indices in ascending order. The trailing word is
    /// masked to `len` so iter never produces out-of-range indices, even if
    /// the underlying buffer happens to carry stale dirty bits past `len`.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        let len = self.len;
        self.words.iter().enumerate().flat_map(move |(w, &word)| {
            let base = w * 64;
            (0..64).filter_map(move |b| {
                let idx = base + b;
                (idx < len && (word >> b) & 1 == 1).then_some(idx)
            })
        })
    }
}

/// Options controlling [`bfs_slice`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SliceOptions {
    /// Skip control edges (`DepKind::Control`) when set. Use when the caller
    /// only cares about value-flow ancestors.
    pub data_only: bool,
    /// Cap on the number of nodes returned in `idxs` and the BFS frontier.
    /// 0 means uncapped.
    pub max_nodes: usize,
}

/// Result of [`bfs_slice`].
#[derive(Debug, Clone)]
pub struct SliceResult {
    /// Bitset of slice rows. `marked.get(i)` is true iff `i` is in the slice.
    pub marked: Bitset,
    /// Slice rows in BFS-discovery order. Useful when the caller wants the
    /// list directly without scanning the bitset.
    pub idxs: Vec<usize>,
    /// True iff `max_nodes` truncated the walk before exhaustion.
    pub truncated: bool,
}

/// Walk the dependency CSR backwards from `seeds`, returning every row the
/// seeds transitively depend on plus the seeds themselves.
///
/// `n_rows` is the trace length — passed explicitly so this works on
/// `DependencyIndex` views that don't know the trace size (it cannot be
/// derived from `row_offsets.len() - 1` because edges may reference indices
/// strictly outside the persisted row range; we still cap to the trace
/// length the caller knows about).
///
/// Edges that point at indices past `n_rows` are silently ignored — this can
/// happen if the analysis sidecar was built against a longer mmap than the
/// runtime trace mapping.
pub fn bfs_slice(
    deps: &DependencyIndex,
    n_rows: usize,
    seeds: &[usize],
    options: SliceOptions,
) -> SliceResult {
    let mut marked = Bitset::with_len(n_rows);
    let mut idxs: Vec<usize> = Vec::new();
    let mut queue: VecDeque<usize> = VecDeque::new();
    let cap = if options.max_nodes == 0 {
        usize::MAX
    } else {
        options.max_nodes
    };
    let mut truncated = false;

    for &seed in seeds {
        if seed >= n_rows {
            continue;
        }
        if marked.set(seed) {
            idxs.push(seed);
            queue.push_back(seed);
            if idxs.len() >= cap {
                truncated = true;
                break;
            }
        }
    }

    while let Some(idx) = queue.pop_front() {
        if idxs.len() >= cap {
            truncated = true;
            break;
        }
        for edge in deps.row(idx) {
            if options.data_only && matches!(edge.kind, DepKind::Control) {
                continue;
            }
            let target = edge.idx;
            if target >= n_rows {
                continue;
            }
            if marked.set(target) {
                idxs.push(target);
                queue.push_back(target);
                if idxs.len() >= cap {
                    truncated = true;
                    break;
                }
            }
        }
    }

    SliceResult {
        marked,
        idxs,
        truncated,
    }
}

/// Convenience: walk a single seed.
pub fn bfs_slice_one(
    deps: &DependencyIndex,
    n_rows: usize,
    seed: usize,
    options: SliceOptions,
) -> SliceResult {
    bfs_slice(deps, n_rows, &[seed], options)
}

/// Multi-seed combination mode for [`bfs_slice_multi`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceMode {
    /// Union: row is in the result if it is in **any** seed's slice. This is
    /// equivalent to passing all seeds to [`bfs_slice`] in one call but with
    /// per-seed bookkeeping kept separate.
    Union,
    /// Intersection: row is in the result if it is in **every** seed's
    /// slice. Useful for "common ancestors of operations X and Y" — the
    /// algorithmic equivalent of slicing two seeds and asking where the
    /// dataflow lineages meet.
    Intersection,
}

/// Multi-seed slice. Each seed is sliced independently, then the resulting
/// bitsets are combined via `mode`.
///
/// Cost is O(seeds × per-seed BFS). For most realistic queries (2–4 seeds)
/// this is the same cost order as a single combined walk.
pub fn bfs_slice_multi(
    deps: &DependencyIndex,
    n_rows: usize,
    seeds: &[usize],
    mode: SliceMode,
    options: SliceOptions,
) -> SliceResult {
    if seeds.is_empty() {
        return SliceResult {
            marked: Bitset::with_len(n_rows),
            idxs: Vec::new(),
            truncated: false,
        };
    }
    if seeds.len() == 1 {
        return bfs_slice_one(deps, n_rows, seeds[0], options);
    }
    let mut combined: Option<Bitset> = None;
    let mut any_truncated = false;
    for &seed in seeds {
        let result = bfs_slice_one(deps, n_rows, seed, options);
        any_truncated |= result.truncated;
        combined = Some(match (combined, mode) {
            (None, _) => result.marked,
            (Some(mut acc), SliceMode::Union) => {
                acc.union_in_place(&result.marked);
                acc
            }
            (Some(mut acc), SliceMode::Intersection) => {
                acc.intersect_in_place(&result.marked);
                acc
            }
        });
    }
    let marked = combined.unwrap_or_else(|| Bitset::with_len(n_rows));
    let idxs: Vec<usize> = marked.iter().collect();
    SliceResult {
        marked,
        idxs,
        truncated: any_truncated,
    }
}

/// Per-edge-kind counts of edges that lead **into the slice from outside**
/// or stay within the slice. Useful for UI surfaces that want to tell the
/// user "this slice has 12 reg edges and 3 mem edges."
#[derive(Debug, Clone, Copy, Default)]
pub struct SliceEdgeStats {
    pub reg: usize,
    pub address: usize,
    pub mem: usize,
    pub control: usize,
}

impl SliceEdgeStats {
    pub fn total(&self) -> usize {
        self.reg + self.address + self.mem + self.control
    }
}

/// Count edges between rows in the slice, grouped by [`DepKind`]. Walks the
/// CSR once over the slice rows. Assumes `result.idxs` is consistent with
/// `result.marked`, which is the contract returned by [`bfs_slice`].
pub fn slice_edge_stats(deps: &DependencyIndex, result: &SliceResult) -> SliceEdgeStats {
    let mut stats = SliceEdgeStats::default();
    for &idx in &result.idxs {
        for edge in deps.row(idx) {
            if !result.marked.get(edge.idx) {
                continue;
            }
            match edge.kind {
                DepKind::Reg => stats.reg += 1,
                DepKind::Address => stats.address += 1,
                DepKind::Mem => stats.mem += 1,
                DepKind::Control => stats.control += 1,
            }
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis_index::DepEdge;

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
    fn bitset_round_trip() {
        let mut bs = Bitset::with_len(130);
        assert!(bs.set(0));
        assert!(bs.set(63));
        assert!(bs.set(64));
        assert!(bs.set(129));
        assert!(!bs.set(0));
        assert!(bs.get(0));
        assert!(!bs.get(1));
        assert!(bs.get(129));
        assert!(!bs.get(130));
        assert_eq!(bs.count_ones(), 4);
        let collected: Vec<_> = bs.iter().collect();
        assert_eq!(collected, vec![0, 63, 64, 129]);
    }

    #[test]
    fn bitset_iter_masks_trailing_word() {
        // Construct a bitset where the trailing word has a dirty bit past
        // `len`. Manually poke at the underlying buffer to simulate stale
        // input — `set` itself will refuse the write.
        let mut bs = Bitset::with_len(65);
        bs.set(64);
        // Force-set a bit at position 70 by mutating words directly. iter()
        // must still mask it out.
        bs.words[1] |= 1u64 << 6;
        let visible: Vec<_> = bs.iter().collect();
        assert_eq!(visible, vec![64]);
    }

    #[test]
    fn bitset_from_idxs_skips_out_of_range() {
        let bs = Bitset::from_idxs([0usize, 5, 99], 8);
        assert!(bs.get(0));
        assert!(bs.get(5));
        assert!(!bs.get(99));
        assert_eq!(bs.count_ones(), 2);
    }

    #[test]
    fn bfs_slice_walks_predecessors() {
        // 0 → 1 → 2 → 3 (each row's dep points back one step)
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
        let result = bfs_slice_one(&deps, 4, 3, SliceOptions::default());
        assert!(!result.truncated);
        assert_eq!(result.idxs.len(), 4);
        for i in 0..4 {
            assert!(result.marked.get(i), "row {i} missing from slice");
        }
    }

    #[test]
    fn bfs_slice_data_only_drops_control() {
        let deps = make_deps(&[
            vec![],
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
                    idx: 0,
                    kind: DepKind::Control,
                },
            ],
        ]);
        let loose = bfs_slice_one(
            &deps,
            3,
            2,
            SliceOptions {
                data_only: false,
                max_nodes: 0,
            },
        );
        assert_eq!(loose.idxs.len(), 3);
        let strict = bfs_slice_one(
            &deps,
            3,
            2,
            SliceOptions {
                data_only: true,
                max_nodes: 0,
            },
        );
        // strict still includes seed 2 + value-flow 1 + value-flow 0 because 0
        // is reachable through the reg edge from 1.
        assert_eq!(strict.idxs.len(), 3);
        // But control edges in node 2 are filtered, so the *order of discovery*
        // suppresses the duplicate enqueue: 2 → 1 → 0 (no second push of 0
        // through the control edge).
        assert_eq!(strict.idxs, vec![2, 1, 0]);
    }

    #[test]
    fn bfs_slice_max_nodes_truncates() {
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
        let result = bfs_slice_one(
            &deps,
            4,
            3,
            SliceOptions {
                data_only: false,
                max_nodes: 2,
            },
        );
        assert!(result.truncated);
        assert_eq!(result.idxs.len(), 2);
    }

    #[test]
    fn slice_edge_stats_counts_only_internal_edges() {
        let deps = make_deps(&[
            vec![],
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
                    idx: 0,
                    kind: DepKind::Mem,
                },
            ],
        ]);
        let result = bfs_slice_one(&deps, 3, 2, SliceOptions::default());
        let stats = slice_edge_stats(&deps, &result);
        assert_eq!(stats.reg, 2);
        assert_eq!(stats.mem, 1);
        assert_eq!(stats.total(), 3);
    }

    #[test]
    fn bfs_slice_seed_outside_trace_is_ignored() {
        let deps = make_deps(&[vec![]]);
        let result = bfs_slice(&deps, 1, &[5, 0], SliceOptions::default());
        assert_eq!(result.idxs, vec![0]);
    }

    #[test]
    fn bfs_slice_handles_diamond_graph() {
        // 0 ← 1 ← {2,3} ← 4
        // i.e. row 4 depends on 2 and 3; both depend on 1; 1 depends on 0.
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
                idx: 1,
                kind: DepKind::Reg,
            }],
            vec![
                DepEdge {
                    idx: 2,
                    kind: DepKind::Reg,
                },
                DepEdge {
                    idx: 3,
                    kind: DepKind::Mem,
                },
            ],
        ]);
        let result = bfs_slice_one(&deps, 5, 4, SliceOptions::default());
        let mut sorted = result.idxs.clone();
        sorted.sort();
        assert_eq!(sorted, vec![0, 1, 2, 3, 4]);
        // each node visited exactly once
        assert_eq!(result.marked.count_ones(), 5);
        let stats = slice_edge_stats(&deps, &result);
        // Internal edges: 1→0 (reg), 2→1 (reg), 3→1 (reg), 4→2 (reg), 4→3 (mem)
        assert_eq!(stats.reg, 4);
        assert_eq!(stats.mem, 1);
        assert_eq!(stats.total(), 5);
    }

    #[test]
    fn bfs_slice_self_loop_does_not_revisit() {
        let deps = make_deps(&[
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
        ]);
        let result = bfs_slice_one(&deps, 2, 1, SliceOptions::default());
        assert_eq!(result.idxs, vec![1, 0]);
    }

    #[test]
    fn bitset_clamps_out_of_range_writes() {
        let mut bs = Bitset::with_len(4);
        assert!(!bs.set(10));
        assert!(!bs.get(10));
        assert!(bs.set(3));
        assert!(bs.get(3));
    }

    #[test]
    fn bfs_slice_caps_seeds_when_max_nodes_smaller_than_seed_count() {
        let deps = make_deps(&[vec![], vec![], vec![]]);
        let result = bfs_slice(
            &deps,
            3,
            &[0, 1, 2],
            SliceOptions {
                data_only: false,
                max_nodes: 2,
            },
        );
        assert!(result.truncated);
        assert_eq!(result.idxs.len(), 2);
    }

    #[test]
    fn bfs_slice_edge_pointing_outside_trace_is_skipped() {
        // Edge from row 0 points at row 99 which is past our claimed
        // n_rows = 1. Walk should not panic and the slice stays at row 0.
        let deps = make_deps(&[vec![DepEdge {
            idx: 99,
            kind: DepKind::Reg,
        }]]);
        let result = bfs_slice_one(&deps, 1, 0, SliceOptions::default());
        assert_eq!(result.idxs, vec![0]);
    }

    #[test]
    fn bfs_slice_multi_union_combines_seed_lineages() {
        // 0 ← 1 ← 2,  3 ← 4 ← 5 (two unrelated chains)
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
            vec![],
            vec![DepEdge {
                idx: 3,
                kind: DepKind::Reg,
            }],
            vec![DepEdge {
                idx: 4,
                kind: DepKind::Reg,
            }],
        ]);
        let result = bfs_slice_multi(&deps, 6, &[2, 5], SliceMode::Union, SliceOptions::default());
        let mut idxs = result.idxs.clone();
        idxs.sort();
        assert_eq!(idxs, vec![0, 1, 2, 3, 4, 5]);
        assert!(!result.truncated);
    }

    #[test]
    fn bfs_slice_multi_intersection_finds_common_ancestor() {
        // Diamond: row 0 is the shared ancestor. Two parallel chains
        // converge from below:
        //   0 ← 1 ← 2 ← 3
        //   0 ← 4 ← 5 ← 6
        //
        // Slice from 3 = {0, 1, 2, 3}; slice from 6 = {0, 4, 5, 6}.
        // Intersection = {0}.
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
                idx: 0,
                kind: DepKind::Reg,
            }],
            vec![DepEdge {
                idx: 4,
                kind: DepKind::Reg,
            }],
            vec![DepEdge {
                idx: 5,
                kind: DepKind::Reg,
            }],
        ]);
        let result = bfs_slice_multi(
            &deps,
            7,
            &[3, 6],
            SliceMode::Intersection,
            SliceOptions::default(),
        );
        assert_eq!(result.idxs, vec![0]);
    }

    #[test]
    fn bfs_slice_multi_intersection_empty_when_chains_dont_meet() {
        let deps = make_deps(&[
            vec![],
            vec![DepEdge {
                idx: 0,
                kind: DepKind::Reg,
            }],
            vec![],
            vec![DepEdge {
                idx: 2,
                kind: DepKind::Reg,
            }],
        ]);
        let result = bfs_slice_multi(
            &deps,
            4,
            &[1, 3],
            SliceMode::Intersection,
            SliceOptions::default(),
        );
        assert!(result.idxs.is_empty());
        assert_eq!(result.marked.count_ones(), 0);
    }

    #[test]
    fn bfs_slice_multi_with_no_seeds_returns_empty() {
        let deps = make_deps(&[vec![]]);
        let result = bfs_slice_multi(&deps, 1, &[], SliceMode::Union, SliceOptions::default());
        assert!(result.idxs.is_empty());
    }

    #[test]
    fn bfs_slice_multi_single_seed_matches_single_walk() {
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
        let single = bfs_slice_one(&deps, 3, 2, SliceOptions::default());
        let multi = bfs_slice_multi(
            &deps,
            3,
            &[2],
            SliceMode::Intersection,
            SliceOptions::default(),
        );
        let mut single_sorted = single.idxs.clone();
        single_sorted.sort();
        let mut multi_sorted = multi.idxs.clone();
        multi_sorted.sort();
        assert_eq!(single_sorted, multi_sorted);
    }

    #[test]
    fn bitset_intersection_clears_extra_bits() {
        let mut a = Bitset::with_len(4);
        a.set(0);
        a.set(1);
        a.set(3);
        let mut b = Bitset::with_len(4);
        b.set(1);
        b.set(2);
        a.intersect_in_place(&b);
        assert!(!a.get(0));
        assert!(a.get(1));
        assert!(!a.get(2));
        assert!(!a.get(3));
        assert_eq!(a.count_ones(), 1);
    }

    #[test]
    fn bitset_union_combines_inputs() {
        let mut a = Bitset::with_len(4);
        a.set(0);
        let mut b = Bitset::with_len(4);
        b.set(2);
        a.union_in_place(&b);
        assert!(a.get(0));
        assert!(a.get(2));
        assert_eq!(a.count_ones(), 2);
    }
}
