//! Trace-backed UIDF observations for LLIL SSA definitions.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::index::Index;
use crate::llil::expr::LlilExpr;
use crate::llil::util::{parse_ssa_reg, set_reg_dst};
use crate::trace::Trace;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservedValues {
    pub pc: u64,
    pub reg: String,
    pub n_hits: usize,
    pub distinct_count: usize,
    pub first: Option<u64>,
    pub last: Option<u64>,
    pub sample: Vec<u64>,
}

impl ObservedValues {
    pub fn is_const(&self) -> bool {
        self.distinct_count == 1
    }
}

pub fn collect_uidf(
    trace: &Trace,
    exprs: &[LlilExpr],
    max_hits_per_pc: usize,
) -> BTreeMap<usize, ObservedValues> {
    let mut out = BTreeMap::new();
    for (root_idx, expr) in exprs.iter().enumerate() {
        let Some(dst) = set_reg_dst(expr) else {
            continue;
        };
        let Some((reg, _version)) = parse_ssa_reg(dst) else {
            continue;
        };
        let Some(reg_name) = canonical_trace_reg(reg) else {
            continue;
        };
        let idxs = (0..trace.len()).filter(|&idx| trace.pc(idx) == expr.pc);
        if let Some(obs) =
            collect_observed_values(trace, expr.pc, reg, reg_name, max_hits_per_pc, idxs)
        {
            out.insert(root_idx, obs);
        }
    }
    out
}

pub fn collect_uidf_indexed(
    trace: &Trace,
    index: &Index,
    exprs: &[LlilExpr],
    max_hits_per_pc: usize,
) -> BTreeMap<usize, ObservedValues> {
    let mut out = BTreeMap::new();
    for (root_idx, expr) in exprs.iter().enumerate() {
        let Some(dst) = set_reg_dst(expr) else {
            continue;
        };
        let Some((reg, _version)) = parse_ssa_reg(dst) else {
            continue;
        };
        let Some(reg_name) = canonical_trace_reg(reg) else {
            continue;
        };
        let Some(idxs) = index.pc_to_idxs.get(&expr.pc) else {
            continue;
        };
        if let Some(obs) = collect_observed_values(
            trace,
            expr.pc,
            reg,
            reg_name,
            max_hits_per_pc,
            idxs.iter().copied(),
        ) {
            out.insert(root_idx, obs);
        }
    }
    out
}

fn collect_observed_values<I>(
    trace: &Trace,
    pc: u64,
    reg: &str,
    reg_name: &str,
    max_hits_per_pc: usize,
    idxs: I,
) -> Option<ObservedValues>
where
    I: IntoIterator<Item = usize>,
{
    let mut vals = Vec::new();
    let mut n_hits = 0usize;
    for idx in idxs {
        n_hits += 1;
        if vals.len() >= max_hits_per_pc {
            continue;
        }
        let value_idx = idx.saturating_add(1).min(trace.len().saturating_sub(1));
        vals.push(trace.record(value_idx).reg_by_name(reg_name).unwrap_or(0));
    }
    if n_hits == 0 {
        return None;
    }
    let mut sample = Vec::new();
    for v in &vals {
        if !sample.contains(v) {
            sample.push(*v);
        }
        if sample.len() >= 8 {
            break;
        }
    }
    Some(ObservedValues {
        pc,
        reg: reg.to_string(),
        n_hits,
        distinct_count: sample.len(),
        first: vals.first().copied(),
        last: vals.last().copied(),
        sample,
    })
}

fn canonical_trace_reg(reg: &str) -> Option<&str> {
    if reg == "sp" || reg == "fp" || reg == "lr" {
        return Some(reg);
    }
    if reg.starts_with('x') && reg[1..].parse::<u8>().ok().is_some_and(|n| n <= 30) {
        return Some(reg);
    }
    None
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::llil::expr::{konst, set_reg};
    use crate::trace::{Trace, REC_SIZE};

    use super::*;

    #[test]
    fn collects_post_instruction_value() {
        let dir = tempfile::tempdir().unwrap();
        let mut buf = vec![0u8; REC_SIZE * 2];
        buf[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        buf[268..272].copy_from_slice(&0xd503201fu32.to_le_bytes());
        let off = REC_SIZE;
        buf[off..off + 8].copy_from_slice(&0x1004u64.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&0x42u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
        fs::write(dir.path().join("trace.bin"), buf).unwrap();
        let trace = Trace::load(dir.path()).unwrap();
        let exprs = vec![set_reg("x0#1", konst(1), 0x1000)];
        let obs = collect_uidf(&trace, &exprs, 8);
        assert_eq!(obs.get(&0).unwrap().first, Some(0x42));
    }

    #[test]
    fn indexed_collection_matches_sequential() {
        let dir = tempfile::tempdir().unwrap();
        let mut buf = vec![0u8; REC_SIZE * 3];
        for i in 0..3usize {
            let off = i * REC_SIZE;
            let pc = if i == 2 {
                0x1000u64
            } else {
                0x1000u64 + i as u64 * 4
            };
            buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
            buf[off + 8..off + 16].copy_from_slice(&(0x40u64 + i as u64).to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
        }
        fs::write(dir.path().join("trace.bin"), buf).unwrap();
        let trace = Trace::load(dir.path()).unwrap();
        let index = crate::index::Index::build(&trace);
        let exprs = vec![set_reg("x0#1", konst(1), 0x1000)];

        assert_eq!(
            collect_uidf(&trace, &exprs, 8),
            collect_uidf_indexed(&trace, &index, &exprs, 8)
        );
    }
}
