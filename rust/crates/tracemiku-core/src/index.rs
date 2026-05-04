//! Per-register def-use indices over a Trace. Used by taint and the
//! `last-write-of-reg` family of endpoints.
//!
//! M2-ζ: also populates `mem_writes` / `mem_reads` / `mem_addr_to_writes`
//! in the same single trace-walk that drives the reg side. Mirrors
//! `viewer/index.py:41-54`.

use std::collections::HashMap;
use std::thread;

use crate::disasm::{addr_of, decode};
use crate::trace::Trace;

const PARALLEL_MIN_RECORDS: usize = 250_000;
const MIN_CHUNK_RECORDS: usize = 200_000;

/// One memory-side index entry: which record touched which (addr, size).
/// `value` is `None` at index-build time; MemShadow may populate it later
/// from the source/dest register that was observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemRec {
    pub idx: usize,
    pub addr: u64,
    pub size: u32,
    pub value: Option<u64>,
}

/// Inverted index: register name → sorted list of record indices, plus a
/// memory-side companion for taint/MemShadow consumers.
#[derive(Debug, Default, Clone)]
pub struct Index {
    /// `reg_defs[r]` = sorted record indices that WRITE to `r`.
    pub reg_defs: HashMap<String, Vec<usize>>,
    /// `reg_uses[r]` = sorted record indices that READ from `r`.
    pub reg_uses: HashMap<String, Vec<usize>>,
    /// All memory-write entries in trace order.
    pub mem_writes: Vec<MemRec>,
    /// All memory-read entries in trace order.
    pub mem_reads: Vec<MemRec>,
    /// `pc → sorted record indices`. Used by hot UI navigation paths such as
    /// CFG/HLIL clicks, hash deep-links, and Trace-for-PC.
    pub pc_to_idxs: HashMap<u64, Vec<usize>>,
    /// `addr → indices of mem_writes that wrote to that addr`. Fast
    /// "who wrote here?" lookup for backward taint and the
    /// `last-write-of-addr` endpoint family.
    pub mem_addr_to_writes: HashMap<u64, Vec<usize>>,
}

impl Index {
    /// Walk every record in `trace`, decode the instruction, and accumulate
    /// def/use entries by register name plus memory-op entries by addr.
    /// Large traces are split across worker threads; each worker builds a
    /// local index over a contiguous record range, then the main thread merges
    /// chunks in range order so all `Vec<idx>` outputs stay sorted.
    pub fn build(trace: &Trace) -> Self {
        let n = trace.len();
        let workers = index_worker_count(n);
        if workers <= 1 {
            return build_range(trace, 0, n);
        }

        let chunk_size = n.div_ceil(workers);
        let partials = thread::scope(|scope| {
            let mut handles = Vec::with_capacity(workers);
            for worker in 0..workers {
                let start = worker * chunk_size;
                let end = (start + chunk_size).min(n);
                if start >= end {
                    continue;
                }
                handles.push(scope.spawn(move || build_range(trace, start, end)));
            }
            handles
                .into_iter()
                .map(|handle| handle.join().expect("index worker panicked"))
                .collect::<Vec<_>>()
        });

        merge_partials(partials)
    }

    /// Last def index for `reg` strictly before `cursor`. Binary search.
    /// Returns None if `reg` has no defs before cursor.
    pub fn last_def_before(&self, reg: &str, cursor: usize) -> Option<usize> {
        let defs = self.reg_defs.get(reg)?;
        match defs.binary_search(&cursor) {
            Ok(i) => {
                if i == 0 {
                    None
                } else {
                    Some(defs[i - 1])
                }
            }
            Err(i) => {
                if i == 0 {
                    None
                } else {
                    Some(defs[i - 1])
                }
            }
        }
    }
}

fn index_worker_count(n: usize) -> usize {
    let requested = std::env::var("TRACEMIKU_INDEX_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&v| v > 0);
    let available = requested.unwrap_or_else(|| {
        thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });
    if available <= 1 || (requested.is_none() && n < PARALLEL_MIN_RECORDS) {
        return 1;
    }
    let chunk_cap = n.div_ceil(MIN_CHUNK_RECORDS).max(1);
    available.min(chunk_cap).max(1)
}

fn build_range(trace: &Trace, start: usize, end: usize) -> Index {
    let mut idx = Index::default();
    for i in start..end {
        let pc = trace.pc(i);
        idx.pc_to_idxs.entry(pc).or_default().push(i);
        let inst = trace.inst(i);
        let d = decode(pc, inst);
        for r in &d.regs_def {
            idx.reg_defs.entry(r.clone()).or_default().push(i);
        }
        for r in &d.regs_use {
            idx.reg_uses.entry(r.clone()).or_default().push(i);
        }
        // Mem-op side: skip MemOps with empty base (rare PC-relative form
        // capstone reports as REG_INVALID — Python does the same).
        if !d.mem_op.is_empty() {
            let rec = trace.record(i);
            for op in &d.mem_op {
                if op.base.is_empty() {
                    continue;
                }
                let addr = addr_of(&rec, op);
                let mr = MemRec {
                    idx: i,
                    addr,
                    size: op.size,
                    value: None,
                };
                if op.is_write {
                    idx.mem_writes.push(mr);
                    idx.mem_addr_to_writes.entry(addr).or_default().push(i);
                } else {
                    idx.mem_reads.push(mr);
                }
            }
        }
    }
    idx
}

fn merge_partials(partials: Vec<Index>) -> Index {
    let mut out = Index::default();
    for partial in partials {
        for (reg, mut values) in partial.reg_defs {
            out.reg_defs.entry(reg).or_default().append(&mut values);
        }
        for (reg, mut values) in partial.reg_uses {
            out.reg_uses.entry(reg).or_default().append(&mut values);
        }
        out.mem_writes.extend(partial.mem_writes);
        out.mem_reads.extend(partial.mem_reads);
        for (pc, mut values) in partial.pc_to_idxs {
            out.pc_to_idxs.entry(pc).or_default().append(&mut values);
        }
        for (addr, mut values) in partial.mem_addr_to_writes {
            out.mem_addr_to_writes
                .entry(addr)
                .or_default()
                .append(&mut values);
        }
    }
    out
}
