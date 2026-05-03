//! Per-register def-use indices over a Trace. Used by taint and the
//! `last-write-of-reg` family of endpoints.
//!
//! M2-ζ: also populates `mem_writes` / `mem_reads` / `mem_addr_to_writes`
//! in the same single trace-walk that drives the reg side. Mirrors
//! `viewer/index.py:41-54`.

use std::collections::HashMap;

use crate::disasm::{addr_of, decode};
use crate::trace::Trace;

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
    /// `addr → indices of mem_writes that wrote to that addr`. Fast
    /// "who wrote here?" lookup for backward taint and the
    /// `last-write-of-addr` endpoint family.
    pub mem_addr_to_writes: HashMap<u64, Vec<usize>>,
}

impl Index {
    /// Walk every record in `trace`, decode the instruction, and accumulate
    /// def/use entries by register name plus memory-op entries by addr.
    /// Sequential — one cached decode call per record.
    pub fn build(trace: &Trace) -> Self {
        let mut idx = Index::default();
        for i in 0..trace.len() {
            let pc = trace.pc(i);
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
                        let n = idx.mem_writes.len();
                        idx.mem_writes.push(mr);
                        idx.mem_addr_to_writes.entry(addr).or_default().push(n);
                    } else {
                        idx.mem_reads.push(mr);
                    }
                }
            }
        }
        idx
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
