//! Per-register def-use indices over a Trace. Used by taint and the
//! `last-write-of-reg` family of endpoints.
//!
//! M2-γ: reg_defs / reg_uses only. mem_writes / mem_reads come in M2-δ
//! when MemShadow lands and taint actually consumes them.

use std::collections::HashMap;

use crate::disasm::decode;
use crate::trace::Trace;

/// Inverted index: register name → sorted list of record indices.
#[derive(Debug, Default, Clone)]
pub struct Index {
    /// `reg_defs[r]` = sorted record indices that WRITE to `r`.
    pub reg_defs: HashMap<String, Vec<usize>>,
    /// `reg_uses[r]` = sorted record indices that READ from `r`.
    pub reg_uses: HashMap<String, Vec<usize>>,
}

impl Index {
    /// Walk every record in `trace`, decode the instruction, and accumulate
    /// def/use entries by register name. Sequential — one cached decode call
    /// per record.
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
