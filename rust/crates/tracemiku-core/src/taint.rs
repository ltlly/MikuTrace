//! Forward + backward taint propagation on a trace.
//!
//! Direct port of `viewer/taint.py` minus the slow-path fallback,
//! `through_mem`, `data_only`, and `cross_fn_call` flags (those land in
//! M3-γ). MVP scope: index-accelerated forward + backward with optional
//! exclude-reg set.
//!
//! Algorithm (backward): BFS via VecDeque<(cur_idx, want_reg)>,
//! mirroring Python `pending.pop(0)` (head) / `pending.append(...)` (tail).
//! Walk order matters under max_count truncation.

use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet, VecDeque};

use crate::disasm::decode;
use crate::index::Index;
use crate::trace::Trace;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TaintHit {
    pub idx: usize,
    pub why: String,
}

pub fn build_frame_depth_map(trace: &Trace) -> Vec<u32> {
    let n = trace.len();
    let mut out = vec![0u32; n];
    let mut depth: u32 = 0;
    for (i, slot) in out.iter_mut().enumerate().take(n) {
        *slot = depth;
        let r = trace.record(i);
        let d = decode(r.pc, r.inst);
        if d.is_call {
            depth = depth.saturating_add(1);
        } else if d.is_ret && depth > 0 {
            depth -= 1;
        }
    }
    out
}

pub fn forward_taint(
    trace: &Trace,
    index: &Index,
    start_idx: usize,
    taint_reg: &str,
    max_count: usize,
    exclude_regs: &HashSet<String>,
) -> (Vec<TaintHit>, bool) {
    let mut tainted_regs: HashSet<String> = HashSet::new();
    tainted_regs.insert(taint_reg.to_string());
    let mut heap: BinaryHeap<Reverse<(usize, String, usize)>> = BinaryHeap::new();

    let push_reg = |heap: &mut BinaryHeap<Reverse<(usize, String, usize)>>,
                    reg: &str,
                    lo: usize| {
        if exclude_regs.contains(reg) {
            return;
        }
        let Some(uses) = index.reg_uses.get(reg) else {
            return;
        };
        let pos = uses.partition_point(|&u| u <= lo);
        if pos < uses.len() {
            heap.push(Reverse((uses[pos], reg.to_string(), pos)));
        }
    };
    push_reg(&mut heap, taint_reg, start_idx);

    let mut out: Vec<TaintHit> = Vec::new();
    let mut seen: HashSet<usize> = HashSet::new();
    let cap = if max_count == 0 { usize::MAX } else { max_count };
    let mut stopped = false;

    while let Some(Reverse((i, reg, pos))) = heap.pop() {
        if out.len() >= cap {
            stopped = true;
            break;
        }
        if let Some(uses) = index.reg_uses.get(&reg) {
            if pos + 1 < uses.len() {
                heap.push(Reverse((uses[pos + 1], reg.clone(), pos + 1)));
            }
        }
        if seen.contains(&i) {
            continue;
        }
        let r = trace.record(i);
        let d = decode(r.pc, r.inst);
        // Collect the tainted regs that this insn READS, sorted, no clones.
        let mut used: Vec<String> = Vec::new();
        for u in &d.regs_use {
            if tainted_regs.contains(u) {
                used.push(u.clone());
            }
        }
        if used.is_empty() {
            continue;
        }
        used.sort();
        used.dedup();
        let why = format!("regs:{}", used.join(","));
        out.push(TaintHit { idx: i, why });
        seen.insert(i);
        for nr in &d.regs_def {
            if exclude_regs.contains(nr) {
                continue;
            }
            if !tainted_regs.contains(nr) {
                tainted_regs.insert(nr.clone());
                push_reg(&mut heap, nr, i);
            }
        }
    }

    (out, stopped)
}

pub fn backward_taint(
    trace: &Trace,
    index: &Index,
    idx: usize,
    taint_reg: &str,
    max_count: usize,
    exclude_regs: &HashSet<String>,
) -> (Vec<TaintHit>, bool) {
    // Direct port of viewer/taint.py:300-370 (`_backward_taint_indexed`).
    //
    // Backward: BFS via VecDeque<(cur_idx, want_reg)> — matches Python
    // `pending.pop(0)` / `pending.append(...)` semantics. Walk order matters
    // under max_count truncation: priority-by-idx would diverge.
    let mut pending: VecDeque<(usize, String)> = VecDeque::new();
    if !exclude_regs.contains(taint_reg) {
        pending.push_back((idx, taint_reg.to_string()));
    }

    // visited: per-(cur_idx, want_reg) set so we don't re-walk the same query.
    let mut visited: HashSet<(usize, String)> = HashSet::new();

    // raw out: list of (def_idx, want_reg). May contain duplicates by idx;
    // dedup by sorted-idx happens after the loop (matches Python lines 358-361).
    let mut raw_out: Vec<(usize, String)> = Vec::new();
    let cap = if max_count == 0 { usize::MAX } else { max_count };
    let mut stopped = false;

    while let Some((cur_idx, want_reg)) = pending.pop_front() {
        if raw_out.len() >= cap {
            stopped = true;
            break;
        }
        if exclude_regs.contains(&want_reg) {
            continue;
        }
        if visited.contains(&(cur_idx, want_reg.clone())) {
            continue;
        }
        visited.insert((cur_idx, want_reg.clone()));

        let Some(defs) = index.reg_defs.get(&want_reg) else {
            continue;
        };
        // partition_point(|&d| d < cur_idx) - 1  ↔  bisect_left - 1
        let pos = defs.partition_point(|&d| d < cur_idx);
        if pos == 0 {
            continue;
        }
        let j = defs[pos - 1];
        raw_out.push((j, want_reg.clone()));

        // Push regs_use of j as new pending queries (chasing further back).
        let r = trace.record(j);
        let d = decode(r.pc, r.inst);
        for u in &d.regs_use {
            if exclude_regs.contains(u) {
                continue;
            }
            pending.push_back((j, u.clone()));
        }
    }

    // Dedup by idx, preserving the first reg seen at that idx (Python:
    // `for ix, reg in sorted(out): if ix in seen_idx: continue`).
    raw_out.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut seen_idx: HashSet<usize> = HashSet::new();
    let mut out: Vec<TaintHit> = Vec::new();
    for (i, reg) in raw_out {
        if seen_idx.contains(&i) {
            continue;
        }
        seen_idx.insert(i);
        out.push(TaintHit { idx: i, why: reg });
    }

    (out, stopped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::REC_SIZE;

    fn synth_two_callees() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_9r_1ms");
        std::fs::create_dir_all(&cd).unwrap();
        let pcs: [u64; 9] = [
            0x100000, 0x100004, 0x100100, 0x100104, 0x100008, 0x100200, 0x100204, 0x100208,
            0x10000c,
        ];
        let insts: [u32; 9] = [
            0xd503201f, 0x9400003f, 0xd503201f, 0xd65f03c0, 0x9400007e, 0xd503201f, 0xd503201f,
            0xd65f03c0, 0xd65f03c0,
        ];
        let mut buf = vec![0u8; REC_SIZE * 9];
        for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
            buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":9}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
        )
        .unwrap();
        dir
    }

    fn synth_x0_chain() -> tempfile::TempDir {
        // 5 records of `add x0, x0, #1` (opcode 0x91000400). If this opcode
        // does not produce regs_use=[x0] under your capstone wrapper, swap for
        // `add x0, x0, x1` (0x8b010000) and ensure the test still asserts x0.
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_5r_1ms");
        std::fs::create_dir_all(&cd).unwrap();
        let mut buf = vec![0u8; REC_SIZE * 5];
        for i in 0..5 {
            let off = i * REC_SIZE;
            let pc = 0x100000u64 + (i as u64) * 4;
            buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
            buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&0x91000400u32.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":5}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x100000","size":4096}}"#,
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
    fn frame_depth_map_root_only_then_one_call() {
        let dir = synth_two_callees();
        let t = load_trace(&dir);
        let depths = build_frame_depth_map(&t);
        assert_eq!(depths.len(), 9);
        assert_eq!(depths[0], 0);
        assert_eq!(depths[1], 0);
        assert_eq!(depths[2], 1);
        assert_eq!(depths[3], 1);
        assert_eq!(depths[4], 0);
        assert_eq!(depths[5], 1);
        assert_eq!(depths[8], 0);
    }

    #[test]
    fn forward_taint_empty_when_reg_unused() {
        let dir = synth_two_callees();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, stopped) = forward_taint(&t, &idx, 0, "x0", 100, &exclude);
        assert!(hits.is_empty());
        assert!(!stopped);
    }

    #[test]
    fn backward_taint_empty_when_reg_undefined() {
        let dir = synth_two_callees();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, stopped) = backward_taint(&t, &idx, 8, "x0", 100, &exclude);
        assert!(hits.is_empty());
        assert!(!stopped);
    }

    #[test]
    fn forward_taint_max_count_caps() {
        let dir = synth_x0_chain();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, stopped) = forward_taint(&t, &idx, 0, "x0", 3, &exclude);
        assert_eq!(hits.len(), 3, "should stop after 3 hits, got {hits:?}");
        assert!(stopped, "max_count truncation should set stopped=true");
        for h in &hits {
            assert!(h.why.contains("x0"), "hit row references x0: {h:?}");
        }
    }

    #[test]
    fn backward_taint_emits_bare_reg_name() {
        // 5-record `add x0, x0, #1` chain. Backward from idx=4, taint=x0.
        // Each `add x0, x0, #1` defines x0 AND uses x0, so chasing x0 backward
        // should yield idxs 3, 2, 1, 0 (latest def < cursor each step).
        let dir = synth_x0_chain();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, stopped) = backward_taint(&t, &idx, 4, "x0", 100, &exclude);
        assert!(!hits.is_empty(), "should chase x0 def chain backwards");
        assert!(!stopped);
        // Wire-shape pin: `why` is the bare reg name, NOT "via:x0".
        for h in &hits {
            assert_eq!(h.why, "x0", "expected bare reg name, got {:?}", h.why);
        }
        // Order: dedup'd by sorted idx, so smallest idx first.
        let idxs: Vec<usize> = hits.iter().map(|h| h.idx).collect();
        for w in idxs.windows(2) {
            assert!(w[0] < w[1], "hits sorted by ascending idx: {idxs:?}");
        }
    }
}
