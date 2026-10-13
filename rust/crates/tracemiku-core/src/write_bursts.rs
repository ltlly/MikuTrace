//! 按地址连续性与记录时间窗检索内存写入区间。

use serde::Serialize;

use crate::memshadow::MemShadow;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WriteBurstCandidate {
    pub addr: String,
    pub size: u64,
    pub enter_idx: usize,
    pub exit_idx: usize,
    pub kind: &'static str,
}

#[derive(Debug, Clone)]
struct WriteRunEntry {
    idx: usize,
    addr: u64,
    size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteBurstIndex {
    runs: Vec<WriteBurstRun>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WriteBurstRun {
    addr: u64,
    size: u64,
    enter_idx: usize,
    exit_idx: usize,
    kind: &'static str,
}

impl WriteBurstIndex {
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
            let kind = if uniform_size && first_size == 4 {
                "u32_seq"
            } else if uniform_size && first_size == 1 {
                "byte_seq"
            } else {
                "mixed"
            };
            runs.push(WriteBurstRun {
                addr: run_start,
                size: run_size,
                enter_idx: run_min_idx,
                exit_idx: run_max_idx,
                kind,
            });
            i = j;
        }

        Self { runs }
    }

    pub fn detect(&self, window: usize, min_size: u64) -> Vec<WriteBurstCandidate> {
        self.detect_limited(window, min_size, usize::MAX).1
    }

    pub fn detect_limited(
        &self,
        window: usize,
        min_size: u64,
        limit: usize,
    ) -> (usize, Vec<WriteBurstCandidate>) {
        let mut count = 0usize;
        let mut candidates = Vec::with_capacity(limit.min(1024));
        for run in self
            .runs
            .iter()
            .filter(|run| write_run_matches(run, window, min_size))
        {
            count += 1;
            if candidates.len() < limit {
                candidates.push(write_run_to_candidate(run));
            }
        }
        (count, candidates)
    }
}

pub fn mem_write_bursts(
    memshadow: &MemShadow,
    window: usize,
    min_size: u64,
) -> Vec<WriteBurstCandidate> {
    WriteBurstIndex::build(memshadow).detect(window, min_size)
}

fn write_run_matches(run: &WriteBurstRun, window: usize, min_size: u64) -> bool {
    run.size >= min_size && run.exit_idx.saturating_sub(run.enter_idx) <= window
}

fn write_run_to_candidate(run: &WriteBurstRun) -> WriteBurstCandidate {
    WriteBurstCandidate {
        addr: format!("{:#x}", run.addr),
        size: run.size,
        enter_idx: run.enter_idx,
        exit_idx: run.exit_idx,
        kind: run.kind,
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
            snapshot: None,
        }
    }

    #[test]
    fn write_burst_index_matches_direct_detect() {
        let mem = memshadow_with_writes(8);
        let direct = mem_write_bursts(&mem, 10, 16);
        let indexed = WriteBurstIndex::build(&mem).detect(10, 16);
        assert_eq!(direct, indexed);
        assert_eq!(indexed.len(), 1);
        assert_eq!(indexed[0].addr, "0x7000");
        assert_eq!(indexed[0].size, 32);
    }

    #[test]
    fn write_burst_index_reuses_runs_for_different_params() {
        let mem = memshadow_with_writes(8);
        let index = WriteBurstIndex::build(&mem);
        assert_eq!(index.detect(10, 16).len(), 1);
        assert_eq!(index.detect(2, 16).len(), 0);
        assert_eq!(index.detect(10, 64).len(), 0);
    }

    #[test]
    fn mem_write_bursts_limited_counts_all_matches() {
        let mem = memshadow_with_writes(16);
        let index = WriteBurstIndex::build(&mem);
        let (count, candidates) = index.detect_limited(10, 4, 2);
        assert_eq!(count, 4);
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn write_burst_index_preserves_same_addr_trace_order() {
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
            snapshot: None,
        };
        let candidates = WriteBurstIndex::build(&mem).detect(10, 8);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].addr, "0x1000");
        assert_eq!(candidates[0].size, 12);
        assert_eq!(candidates[0].enter_idx, 1);
        assert_eq!(candidates[0].exit_idx, 3);
    }
}
