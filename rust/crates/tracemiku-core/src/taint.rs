//! Forward + backward taint propagation on a trace.
//!
//! Direct port of `viewer/taint.py` minus the slow-path fallback,
//! `through_mem`, `data_only`, and `cross_fn_call` flags (those land in
//! M3-γ Tasks 2/3/4). MVP scope: index-accelerated forward + backward
//! with optional exclude-reg set.
//!
//! Algorithm (backward): BFS via VecDeque<BwdItem> where BwdItem is
//! either a (cur_idx, want_reg) reg-chase or a (before_idx, addr, size)
//! mem-chase. Mem items use index.mem_addr_to_writes for exact-addr
//! writer lookup (byte-overlap mode is M3-γ Task 2 via through_mem).
//! Mirrors viewer/taint.py:301-356 exactly.

use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet, VecDeque};

use crate::disasm::{addr_of, decode, MemOp};
use crate::index::Index;
use crate::trace::Trace;

/// Set of registers used purely as base/index of memory ops in this insn.
/// Mirrors `viewer/taint.py:83` `_addressing_regs(d)`.
#[allow(dead_code)] // M3-γ Task 3 consumer (data_only filter).
fn addressing_regs(mem_ops: &[MemOp]) -> HashSet<String> {
    let mut s = HashSet::new();
    for op in mem_ops {
        if !op.base.is_empty() {
            s.insert(op.base.clone());
        }
        if !op.idx.is_empty() {
            s.insert(op.idx.clone());
        }
    }
    s
}

/// Pending-queue item for backward taint BFS.
///
/// Mirrors Python `pending: list[tuple]` which holds either
/// `(cur_idx, want_reg)` reg-chases or `("MEM", before_idx, addr, sz)`
/// mem-chases. The Rust port uses a tagged enum.
#[derive(Debug)]
enum BwdItem {
    /// Chase the latest def of `want_reg` strictly before `cur_idx`.
    Reg(usize, String),
    /// Chase the writer of memory `[addr, addr+size)` strictly before
    /// `before_idx` (exact-addr fast path; M3-γ Task 2 adds byte-overlap).
    Mem(usize, u64, u32),
}

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
    let mut pending: VecDeque<BwdItem> = VecDeque::new();
    let mut visited: HashSet<(usize, String)> = HashSet::new();
    let mut raw_out: Vec<(usize, String)> = Vec::new();
    let cap = if max_count == 0 { usize::MAX } else { max_count };
    let mut stopped = false;

    // Initial seed branch (viewer/taint.py:306-318).
    let r0 = trace.record(idx);
    let d0 = decode(r0.pc, r0.inst);
    let starts_with_def = d0.regs_def.iter().any(|r| r == taint_reg);

    if starts_with_def && !exclude_regs.contains(taint_reg) {
        raw_out.push((idx, taint_reg.to_string()));
        visited.insert((idx, taint_reg.to_string()));
        for u in &d0.regs_use {
            if exclude_regs.contains(u) {
                continue;
            }
            pending.push_back(BwdItem::Reg(idx, u.clone()));
        }
        for op in &d0.mem_op {
            if op.is_write {
                continue;
            }
            let addr = addr_of(&r0, op);
            pending.push_back(BwdItem::Mem(idx, addr, op.size));
        }
    } else if !exclude_regs.contains(taint_reg) {
        pending.push_back(BwdItem::Reg(idx, taint_reg.to_string()));
    }

    while let Some(item) = pending.pop_front() {
        if raw_out.len() >= cap {
            stopped = true;
            break;
        }
        match item {
            BwdItem::Mem(before_idx, addr, _size) => {
                // Exact-addr mode (M3-γ Task 2 adds byte-overlap):
                // ONLY return the LATEST writer strictly before before_idx.
                // Python: `return [writes[pos]]` after `bisect_left - 1`.
                let Some(writer_idxs) = index.mem_addr_to_writes.get(&addr) else {
                    continue;
                };
                let pos = writer_idxs.partition_point(|&w| w < before_idx);
                if pos == 0 {
                    continue;
                }
                let j = writer_idxs[pos - 1];
                let r = trace.record(j);
                let d = decode(r.pc, r.inst);
                let (base_w, idx_w) = if let Some(op) = d.mem_op.first() {
                    (op.base.clone(), op.idx.clone())
                } else {
                    (String::new(), String::new())
                };
                if let Some(src) = d.regs_use.iter().find(|u| {
                    !exclude_regs.contains(*u) && **u != base_w && **u != idx_w
                }) {
                    pending.push_back(BwdItem::Reg(j, src.clone()));
                }
            }
            BwdItem::Reg(cur_idx, want_reg) => {
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
                let pos = defs.partition_point(|&d| d < cur_idx);
                if pos == 0 {
                    continue;
                }
                let j = defs[pos - 1];
                raw_out.push((j, want_reg.clone()));

                let r = trace.record(j);
                let d = decode(r.pc, r.inst);
                for u in &d.regs_use {
                    if exclude_regs.contains(u) {
                        continue;
                    }
                    pending.push_back(BwdItem::Reg(j, u.clone()));
                }
                for op in &d.mem_op {
                    if op.is_write {
                        continue;
                    }
                    let addr = addr_of(&r, op);
                    pending.push_back(BwdItem::Mem(j, addr, op.size));
                }
            }
        }
    }

    // Dedup by sorted idx (Python lines 358-361).
    raw_out.sort_by(|(ai, ar), (bi, br)| ai.cmp(bi).then_with(|| ar.cmp(br)));
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

    #[test]
    fn backward_taint_chases_mem_writer() {
        // 5-record trace:
        //   idx 0: mov x0, x2   (0xaa0203e0)  — defines x0 from x2
        //   idx 1: str x0, [sp] (0xf90003e0)  — store x0 to [sp]
        //   idx 2: nop          (0xd503201f)
        //   idx 3: ldr x1, [sp] (0xf94003e1)  — defs x1 from [sp]
        //   idx 4: nop          (0xd503201f)
        //
        // Backward from idx=3, taint=x1.
        //   d0 (idx=3) defines x1 → starts_with_def branch:
        //     pre-emit (3, "x1"); push regs_use of d0 (sp); push MEM(3, 0x7000, 8).
        //   pop Reg(3, sp): no defs of sp → continue.
        //   pop MEM(3, 0x7000, 8): writers of 0x7000 < 3 → idx 1.
        //     j=1; first non-addressing reg in d.regs_use → x0; push Reg(1, "x0").
        //   pop Reg(1, "x0"): defs of x0 before 1 → idx 0; emit (0, "x0").
        //
        // Expected: hits idxs include 0 AND 3.
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_5r_1ms");
        std::fs::create_dir_all(&cd).unwrap();
        let mut buf = vec![0u8; REC_SIZE * 5];
        let pcs: [u64; 5] = [0x100000, 0x100004, 0x100008, 0x10000c, 0x100010];
        let insts: [u32; 5] = [0xaa0203e0, 0xf90003e0, 0xd503201f, 0xf94003e1, 0xd503201f];
        for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
            // x0 = 0xdead so values are defined.
            buf[off + 8..off + 16].copy_from_slice(&0xdeadu64.to_le_bytes());
            // x2 = 0xbeef so x0 := x2 has a defined source.
            buf[off + 24..off + 32].copy_from_slice(&0xbeefu64.to_le_bytes());
            // sp = 0x7000.
            buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":5}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x100000","size":4096}}"#,
        )
        .unwrap();
        let cd_path = dir
            .path()
            .join("run")
            .join("calls")
            .read_dir()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let t = Trace::load(&cd_path).unwrap();
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, _stopped) = backward_taint(&t, &idx, 3, "x1", 100, &exclude);
        let idxs: Vec<usize> = hits.iter().map(|h| h.idx).collect();
        assert!(
            idxs.contains(&0),
            "MEM-chasing should reach idx 0 via mov→str→ldr at sp=0x7000; got {idxs:?}"
        );
        assert!(
            idxs.contains(&3),
            "should pre-emit (idx=3, want_reg=x1) when start defines x1; got {idxs:?}"
        );
    }
}
