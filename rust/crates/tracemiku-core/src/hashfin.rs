//! Hash finalize output-region heuristics.

use serde::Serialize;

use crate::memshadow::MemShadow;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HashFinalizeCandidate {
    pub addr: String,
    pub size: u64,
    pub enter_idx: usize,
    pub exit_idx: usize,
    pub kind: &'static str,
    pub guess: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct WriteRunEntry {
    idx: usize,
    addr: u64,
    size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashFinalizeIndex {
    runs: Vec<HashFinalizeRun>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HashFinalizeRun {
    addr: u64,
    size: u64,
    enter_idx: usize,
    exit_idx: usize,
    kind: &'static str,
    guess: Option<&'static str>,
}

impl HashFinalizeIndex {
    pub fn build(memshadow: &MemShadow) -> Self {
        let mut writes = memshadow
            .writes
            .iter()
            .map(|w| WriteRunEntry {
                idx: w.idx,
                addr: w.addr,
                size: w.size as u64,
            })
            .collect::<Vec<_>>();
        writes.sort_by_key(|w| w.addr);

        let mut runs = Vec::new();
        let mut i = 0usize;
        while i < writes.len() {
            let run_start = writes[i].addr;
            let mut run_end = writes[i].addr.saturating_add(writes[i].size);
            let mut run_min_idx = writes[i].idx;
            let mut run_max_idx = writes[i].idx;
            let first_size = writes[i].size;
            let mut uniform_size = true;
            let mut j = i + 1;
            while j < writes.len() && writes[j].addr == run_end {
                run_end = writes[j].addr.saturating_add(writes[j].size);
                run_min_idx = run_min_idx.min(writes[j].idx);
                run_max_idx = run_max_idx.max(writes[j].idx);
                uniform_size &= writes[j].size == first_size;
                j += 1;
            }
            let run_size = run_end.saturating_sub(run_start);
            let kind = if uniform_size && first_size == 4 && run_size >= 20 {
                "u32x5"
            } else if uniform_size && first_size == 1 {
                "byte_seq"
            } else {
                "mixed"
            };
            runs.push(HashFinalizeRun {
                addr: run_start,
                size: run_size,
                enter_idx: run_min_idx,
                exit_idx: run_max_idx,
                kind,
                guess: digest_size_to_guess(run_size),
            });
            i = j;
        }

        Self { runs }
    }

    pub fn detect(&self, window: usize, min_size: u64) -> Vec<HashFinalizeCandidate> {
        self.runs
            .iter()
            .filter(|run| {
                run.size >= min_size && run.exit_idx.saturating_sub(run.enter_idx) <= window
            })
            .map(|run| HashFinalizeCandidate {
                addr: format!("{:#x}", run.addr),
                size: run.size,
                enter_idx: run.enter_idx,
                exit_idx: run.exit_idx,
                kind: run.kind,
                guess: run.guess,
            })
            .collect()
    }
}

pub fn hash_finalize_detect(
    memshadow: &MemShadow,
    window: usize,
    min_size: u64,
) -> Vec<HashFinalizeCandidate> {
    HashFinalizeIndex::build(memshadow).detect(window, min_size)
}

fn digest_size_to_guess(size: u64) -> Option<&'static str> {
    match size {
        16 => Some("md5"),
        20 => Some("sha1"),
        28 => Some("sha224"),
        32 => Some("sha256"),
        64 => Some("sha512"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memshadow::{MemRec, MemShadow};
    use std::collections::BTreeMap;

    fn memshadow_with_writes(spacing: u64) -> MemShadow {
        MemShadow {
            writes: (0..4)
                .map(|i| MemRec {
                    idx: i as usize,
                    addr: 0x7000 + i * spacing,
                    size: 8,
                    value: 0x41424344 + i,
                })
                .collect(),
            reads: Vec::new(),
            bytes: BTreeMap::new(),
        }
    }

    #[test]
    fn hash_finalize_index_matches_direct_detect() {
        let mem = memshadow_with_writes(8);
        let direct = hash_finalize_detect(&mem, 10, 16);
        let indexed = HashFinalizeIndex::build(&mem).detect(10, 16);
        assert_eq!(direct, indexed);
        assert_eq!(indexed.len(), 1);
        assert_eq!(indexed[0].addr, "0x7000");
        assert_eq!(indexed[0].size, 32);
        assert_eq!(indexed[0].guess, Some("sha256"));
    }

    #[test]
    fn hash_finalize_index_reuses_runs_for_different_params() {
        let mem = memshadow_with_writes(8);
        let index = HashFinalizeIndex::build(&mem);
        assert_eq!(index.detect(10, 16).len(), 1);
        assert_eq!(index.detect(2, 16).len(), 0);
        assert_eq!(index.detect(10, 64).len(), 0);
    }

    #[test]
    fn hash_finalize_index_preserves_same_addr_trace_order() {
        let mem = MemShadow {
            writes: vec![
                MemRec {
                    idx: 0,
                    addr: 0x1000,
                    size: 4,
                    value: 0,
                },
                MemRec {
                    idx: 1,
                    addr: 0x1004,
                    size: 4,
                    value: 0,
                },
                MemRec {
                    idx: 2,
                    addr: 0x1000,
                    size: 4,
                    value: 0,
                },
                MemRec {
                    idx: 3,
                    addr: 0x1008,
                    size: 4,
                    value: 0,
                },
            ],
            reads: Vec::new(),
            bytes: BTreeMap::new(),
        };
        let candidates = HashFinalizeIndex::build(&mem).detect(10, 8);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].addr, "0x1000");
        assert_eq!(candidates[0].size, 12);
        assert_eq!(candidates[0].enter_idx, 1);
        assert_eq!(candidates[0].exit_idx, 3);
    }
}
