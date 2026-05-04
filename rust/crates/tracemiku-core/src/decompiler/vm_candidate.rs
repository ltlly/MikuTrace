//! VM bytecode 候选区段检测 (DEC3-D). Direct port of
//! viewer/decompiler/vm_candidate.py.
//!
//! Pipeline:
//!   1. ollvm_detect_vm(trace) → dispatcher candidates
//!   2. Find hottest self-update load (ldrh/ldrb/ldr with `!`) in trace
//!   3. min/max of base-reg values across all reader-PC hits → bytecode range
//!   4. memshadow.hex_dump(min_addr, last_idx, 16, 16) → LLM-readable hex
//!   5. Emit VmCandidateIR; never decode bytecode.

use crate::cfg::CFG;
use crate::decompiler::ir::VmCandidateIR;
use crate::disasm::decode;
use crate::index::Index;
use crate::memshadow::MemShadow;
use crate::ollvmdet::{ollvm_detect_vm, ollvm_detect_vm_indexed, OllvmFinding};
use crate::trace::Trace;

/// Find self-update loads in [lo, hi]: returns (pc, hits, mnem_op_str, base_reg).
/// Mirrors Python `_find_self_update_loads`.
fn find_self_update_loads(
    trace: &Trace,
    lo: usize,
    hi: usize,
    min_hits: u64,
    max_step: i64,
) -> Vec<(u64, u64, String, String)> {
    use std::collections::HashMap;

    if hi < lo || trace.is_empty() {
        return Vec::new();
    }

    // Frequency count over PCs in [lo, hi].
    let mut freq: HashMap<u64, u64> = HashMap::new();
    let cap = hi.min(trace.len() - 1);
    for i in lo..=cap {
        *freq.entry(trace.pc(i)).or_insert(0) += 1;
    }
    // Sort by hits desc; take top 200 (Python parity).
    let mut sorted: Vec<(u64, u64)> = freq.into_iter().collect();
    sorted.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    sorted.truncate(200);

    // For each candidate PC, decode its first-seen instance + apply filters.
    let mut hits_seen: Vec<(u64, u64, String, String)> = Vec::new();
    for (pc, cnt) in sorted {
        if cnt < min_hits {
            continue;
        }
        // Find first idx in [lo,hi] with this pc.
        let mut first_idx: Option<usize> = None;
        for i in lo..=cap {
            if trace.pc(i) == pc {
                first_idx = Some(i);
                break;
            }
        }
        let Some(idx) = first_idx else { continue };
        let inst = trace.inst(idx);
        let d = decode(pc, inst);
        let m = d.mnemonic.as_str();
        if m != "ldrh" && m != "ldrb" && m != "ldr" {
            continue;
        }
        if !d.op_str.contains('!') {
            continue;
        }
        let Some(mem_op) = d.mem_op.first() else {
            continue;
        };
        if mem_op.disp.unsigned_abs() as i64 > max_step {
            continue;
        }
        let mnem_op = format!("{} {}", d.mnemonic, d.op_str);
        hits_seen.push((pc, cnt, mnem_op, mem_op.base.clone()));
    }
    hits_seen.sort_by_key(|(_, c, _, _)| std::cmp::Reverse(*c));
    hits_seen
}

fn find_self_update_loads_indexed(
    trace: &Trace,
    index: &Index,
    lo: usize,
    hi: usize,
    min_hits: u64,
    max_step: i64,
) -> Vec<(u64, u64, String, String)> {
    if hi < lo || trace.is_empty() {
        return Vec::new();
    }
    let cap = hi.min(trace.len() - 1);
    let mut sorted: Vec<(u64, u64, usize)> = Vec::new();
    for (&pc, idxs) in &index.pc_to_idxs {
        let start = idxs.partition_point(|&idx| idx < lo);
        let end = idxs.partition_point(|&idx| idx <= cap);
        if start >= end {
            continue;
        }
        sorted.push((pc, (end - start) as u64, idxs[start]));
    }
    sorted.sort_by_key(|(_, c, _)| std::cmp::Reverse(*c));
    sorted.truncate(200);

    let mut hits_seen: Vec<(u64, u64, String, String)> = Vec::new();
    for (pc, cnt, idx) in sorted {
        if cnt < min_hits {
            continue;
        }
        let d = decode(pc, trace.inst(idx));
        let m = d.mnemonic.as_str();
        if m != "ldrh" && m != "ldrb" && m != "ldr" {
            continue;
        }
        if !d.op_str.contains('!') {
            continue;
        }
        let Some(mem_op) = d.mem_op.first() else {
            continue;
        };
        if mem_op.disp.unsigned_abs() as i64 > max_step {
            continue;
        }
        let mnem_op = format!("{} {}", d.mnemonic, d.op_str);
        hits_seen.push((pc, cnt, mnem_op, mem_op.base.clone()));
    }
    hits_seen.sort_by_key(|(_, c, _, _)| std::cmp::Reverse(*c));
    hits_seen
}

/// Walk all hits of `reader_pc` in [lo, hi]; pull `base_reg` value at each hit;
/// return (min, max). Returns (0, 0) on parse failure / no hits / unknown reg.
/// Mirrors Python `_bytecode_range`.
fn bytecode_range(
    trace: &Trace,
    reader_pc: u64,
    base_reg: &str,
    lo: usize,
    hi: usize,
) -> (u64, u64) {
    if base_reg.is_empty() {
        return (0, 0);
    }
    let n = trace.len();
    if n == 0 || hi < lo {
        return (0, 0);
    }
    let mut vals: Vec<u64> = Vec::new();
    let cap = hi.min(n - 1);
    for i in lo..=cap {
        if trace.pc(i) != reader_pc {
            continue;
        }
        let rec = trace.record(i);
        let Some(v) = rec.reg(base_reg) else { continue };
        if v != 0 {
            vals.push(v);
        }
        if vals.len() >= 5000 {
            break;
        }
    }
    if vals.is_empty() {
        return (0, 0);
    }
    let mn = *vals.iter().min().unwrap();
    let mx = *vals.iter().max().unwrap();
    (mn, mx)
}

fn bytecode_range_indexed(
    trace: &Trace,
    index: &Index,
    reader_pc: u64,
    base_reg: &str,
    lo: usize,
    hi: usize,
) -> (u64, u64) {
    if base_reg.is_empty() {
        return (0, 0);
    }
    let n = trace.len();
    if n == 0 || hi < lo {
        return (0, 0);
    }
    let Some(idxs) = index.pc_to_idxs.get(&reader_pc) else {
        return (0, 0);
    };
    let cap = hi.min(n - 1);
    let start = idxs.partition_point(|&idx| idx < lo);
    let end = idxs.partition_point(|&idx| idx <= cap);
    let mut vals: Vec<u64> = Vec::new();
    for &i in &idxs[start..end] {
        let rec = trace.record(i);
        let Some(v) = rec.reg(base_reg) else {
            continue;
        };
        if v != 0 {
            vals.push(v);
        }
        if vals.len() >= 5000 {
            break;
        }
    }
    if vals.is_empty() {
        return (0, 0);
    }
    let mn = *vals.iter().min().unwrap();
    let mx = *vals.iter().max().unwrap();
    (mn, mx)
}

/// Main entry: detect VM dispatcher candidates and grab bytecode hex.
///
/// `mem`: optional MemShadow (built). When `None`, emits candidates without
/// hex_dump (`hex_dump: vec![]`).
/// `confidence_threshold`: passed to ollvm_detect_vm.
pub fn detect_vm_candidates(
    trace: &Trace,
    cfg: &CFG,
    mem: Option<&MemShadow>,
    confidence_threshold: f64,
) -> Vec<VmCandidateIR> {
    detect_vm_candidates_inner(
        trace,
        cfg,
        mem,
        confidence_threshold,
        ollvm_detect_vm(trace, 10, confidence_threshold),
        find_self_update_loads,
        bytecode_range,
    )
}

pub fn detect_vm_candidates_indexed(
    trace: &Trace,
    cfg: &CFG,
    index: &Index,
    mem: Option<&MemShadow>,
    confidence_threshold: f64,
) -> Vec<VmCandidateIR> {
    detect_vm_candidates_inner(
        trace,
        cfg,
        mem,
        confidence_threshold,
        ollvm_detect_vm_indexed(trace, index, 10, confidence_threshold),
        |trace, lo, hi, min_hits, max_step| {
            find_self_update_loads_indexed(trace, index, lo, hi, min_hits, max_step)
        },
        |trace, reader_pc, base_reg, lo, hi| {
            bytecode_range_indexed(trace, index, reader_pc, base_reg, lo, hi)
        },
    )
}

fn detect_vm_candidates_inner<F, G>(
    trace: &Trace,
    _cfg: &CFG,
    mem: Option<&MemShadow>,
    _confidence_threshold: f64,
    findings: Vec<OllvmFinding>,
    find_readers: F,
    find_range: G,
) -> Vec<VmCandidateIR>
where
    F: Fn(&Trace, usize, usize, u64, i64) -> Vec<(u64, u64, String, String)>,
    G: Fn(&Trace, u64, &str, usize, usize) -> (u64, u64),
{
    if findings.is_empty() {
        return Vec::new();
    }
    let n = trace.len();
    if n == 0 {
        return Vec::new();
    }
    let mut out: Vec<VmCandidateIR> = Vec::new();
    for f in findings {
        let mut cand = VmCandidateIR {
            dispatcher_pc: f.fn_pc,
            confidence: f.confidence,
            reasons: f.reasons,
            ..Default::default()
        };
        let readers = find_readers(trace, 0, n - 1, 8, 16);
        if let Some((pc, hits, ms, base)) = readers.into_iter().next() {
            cand.reader_pc = pc;
            cand.reader_inst = ms;
            cand.reader_hits = hits;
            cand.reader_base_reg = base.clone();
            let (lo, hi) = find_range(trace, pc, &base, 0, n - 1);
            if lo > 0 && hi > lo {
                cand.bytecode_addr = lo;
                cand.bytecode_len = hi - lo + 1;
                if let Some(m) = mem {
                    cand.hex_dump = m.hex_dump(lo, (n - 1) as u64, 16, 16);
                }
            }
        }
        out.push(cand);
    }
    out.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::build_cfg;
    use crate::index::Index;
    use crate::trace::REC_SIZE;

    fn synth_no_vm() -> tempfile::TempDir {
        // 12 nops — no indirect br → ollvm_detect_vm returns nothing.
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("run").join("calls").join("c");
        std::fs::create_dir_all(&cd).unwrap();
        let mut buf = vec![0u8; REC_SIZE * 12];
        for i in 0..12usize {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&(0x1000u64 + (i as u64) * 4).to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":12}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x1000","size":"0x10000"}}"#,
        )
        .unwrap();
        dir
    }

    fn load_trace(dir: &tempfile::TempDir) -> Trace {
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .read_dir()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        Trace::load(&cd).unwrap()
    }

    #[test]
    fn detect_vm_candidates_empty_when_no_ollvm_signal() {
        let dir = synth_no_vm();
        let t = load_trace(&dir);
        let cfg = build_cfg(&t);
        let cands = detect_vm_candidates(&t, &cfg, None, 0.4);
        assert!(cands.is_empty(), "no ollvm signal → no candidates");
    }

    #[test]
    fn detect_vm_candidates_indexed_empty_when_no_ollvm_signal() {
        let dir = synth_no_vm();
        let t = load_trace(&dir);
        let cfg = build_cfg(&t);
        let index = Index::build(&t);
        let cands = detect_vm_candidates_indexed(&t, &cfg, &index, None, 0.4);
        assert!(cands.is_empty(), "no ollvm signal → no candidates");
    }

    #[test]
    fn find_self_update_loads_empty_on_no_match() {
        let dir = synth_no_vm();
        let t = load_trace(&dir);
        let n = t.len();
        let res = find_self_update_loads(&t, 0, n - 1, 1, 16);
        assert!(res.is_empty(), "no ldrh/ldrb/ldr with `!` in nops");
    }

    #[test]
    fn bytecode_range_zero_when_unknown_reg() {
        let dir = synth_no_vm();
        let t = load_trace(&dir);
        let n = t.len();
        let (lo, hi) = bytecode_range(&t, 0x9999, "x0", 0, n - 1);
        assert_eq!((lo, hi), (0, 0));
        let (lo, hi) = bytecode_range(&t, 0x1000, "", 0, n - 1);
        assert_eq!((lo, hi), (0, 0), "empty base_reg → (0,0)");
    }
}
