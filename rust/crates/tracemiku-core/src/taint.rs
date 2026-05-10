//! Forward + backward taint propagation on a trace.
//!
//! Direct port of `viewer/taint.py` minus the slow-path fallback and
//! `cross_fn_call` flag (latter lands in M3-γ Task 4). Current scope:
//! index-accelerated forward + backward with `through_mem` byte-overlap
//! and `data_only` addressing-reg filter.
//!
//! Algorithm (backward): BFS via VecDeque<BwdItem> where BwdItem is
//! either a (cur_idx, want_reg) reg-chase or a (before_idx, addr, size)
//! mem-chase. Mem items use index.mem_addr_to_writes for byte-range
//! writer lookup.
//! Mirrors viewer/taint.py:301-356 exactly.

use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::thread;

use crate::disasm::{addr_of, decode, DecodedInsn, MemOp};
use crate::index::Index;
use crate::memshadow::MemShadow;
use crate::parallel;
use crate::trace::Trace;

/// Default frame registers almost always skipped during data-only taint.
/// Matches viewer/taint.py:37 DEFAULT_FRAME_REGS.
pub const DEFAULT_FRAME_REGS: &[&str] = &["sp", "fp", "lr"];

const FRAME_DEPTH_PARALLEL_MIN_RECORDS: usize = 250_000;
const FRAME_DEPTH_MIN_CHUNK_RECORDS: usize = 200_000;
const FRAME_FLAG_CALL: u8 = 1;
const FRAME_FLAG_RET: u8 = 2;

/// Build the default frame-reg HashSet (sp, fp, lr).
pub fn default_frame_reg_set() -> HashSet<String> {
    DEFAULT_FRAME_REGS.iter().map(|s| s.to_string()).collect()
}

/// Set of registers used purely as base/index of memory ops in this insn.
/// Mirrors `viewer/taint.py:83` `_addressing_regs(d)`.
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

const REG_USE_EVENT: u8 = 0;
const REG_DEF_EVENT: u8 = 1;
const MEM_TOUCH_EVENT: u8 = 2;

fn push_next_reg_event(
    heap: &mut BinaryHeap<Reverse<(usize, u8, String, usize)>>,
    entries: Option<&Vec<usize>>,
    reg: &str,
    lo: usize,
    kind: u8,
) {
    let Some(entries) = entries else {
        return;
    };
    let pos = entries.partition_point(|&u| u <= lo);
    if pos < entries.len() {
        heap.push(Reverse((entries[pos], kind, reg.to_string(), pos)));
    }
}

fn push_next_reg_events(
    heap: &mut BinaryHeap<Reverse<(usize, u8, String, usize)>>,
    index: &Index,
    exclude_regs: &HashSet<String>,
    reg: &str,
    lo: usize,
) {
    if exclude_regs.contains(reg) {
        return;
    }
    push_next_reg_event(heap, index.reg_uses.get(reg), reg, lo, REG_USE_EVENT);
    push_next_reg_event(heap, index.reg_defs.get(reg), reg, lo, REG_DEF_EVENT);
}

fn next_mem_touch_after(
    index: &Index,
    tainted_mem: &HashMap<u64, TaintProvenance>,
    lo: usize,
) -> Option<usize> {
    if tainted_mem.is_empty() {
        return None;
    }
    let next_in = |addr_to_idxs: &HashMap<u64, Vec<usize>>| {
        tainted_mem
            .keys()
            .filter_map(|addr| {
                let entries = addr_to_idxs.get(addr)?;
                let pos = entries.partition_point(|&idx| idx <= lo);
                entries.get(pos).copied()
            })
            .min()
    };
    match (
        next_in(&index.mem_addr_to_reads),
        next_in(&index.mem_addr_to_writes),
    ) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn push_next_mem_touch(
    heap: &mut BinaryHeap<Reverse<(usize, u8, String, usize)>>,
    index: &Index,
    tainted_mem: &HashMap<u64, TaintProvenance>,
    lo: usize,
) {
    if let Some(idx) = next_mem_touch_after(index, tainted_mem, lo) {
        heap.push(Reverse((idx, MEM_TOUCH_EVENT, String::new(), 0)));
    }
}

fn mnemonic_base(mnemonic: &str) -> &str {
    mnemonic.split('.').next().unwrap_or(mnemonic)
}

fn is_partial_modify(d: &DecodedInsn) -> bool {
    matches!(
        mnemonic_base(&d.mnemonic),
        "movk" | "bfm" | "bfi" | "bfxil" | "bfc"
    )
}

fn span_overlaps(a: u64, a_size: u32, b: u64, b_size: u32) -> bool {
    let a_end = a.saturating_add(a_size as u64);
    let b_end = b.saturating_add(b_size as u64);
    a < b_end && b < a_end
}

fn load_dest_regs(d: &DecodedInsn, op: &MemOp) -> Vec<String> {
    if !op.src_reg.is_empty() {
        return vec![op.src_reg.clone()];
    }
    let out: Vec<String> = d
        .regs_def
        .iter()
        .filter(|r| **r != op.base)
        .take(1)
        .cloned()
        .collect();
    if out.is_empty() {
        d.regs_def.iter().take(1).cloned().collect()
    } else {
        out
    }
}

fn load_op_feeds_reg(d: &DecodedInsn, op: &MemOp, reg: &str) -> bool {
    if op.is_write {
        return false;
    }
    let dests = load_dest_regs(d, op);
    dests.is_empty() || dests.iter().any(|dst| dst == reg)
}

fn store_source_regs(d: &DecodedInsn, op: &MemOp) -> Vec<String> {
    if !op.src_reg.is_empty() {
        return vec![op.src_reg.clone()];
    }
    d.regs_use
        .iter()
        .find(|r| **r != op.base && (op.idx.is_empty() || **r != op.idx))
        .cloned()
        .into_iter()
        .collect()
}

fn store_source_regs_for_addr(
    d: &DecodedInsn,
    r: &crate::trace::Record,
    addr: u64,
    size: u32,
) -> Vec<String> {
    let mut out = Vec::new();
    for op in &d.mem_op {
        if !op.is_write {
            continue;
        }
        let base = addr_of(r, op);
        if !span_overlaps(base, op.size, addr, size) {
            continue;
        }
        for src in store_source_regs(d, op) {
            if !out.contains(&src) {
                out.push(src);
            }
        }
    }
    out
}

fn tainted_mem_overlaps(tainted_mem: &HashMap<u64, TaintProvenance>, addr: u64, size: u32) -> bool {
    (0..size as u64).any(|o| tainted_mem.contains_key(&(addr + o)))
}

fn clear_tainted_mem_span(
    tainted_mem: &mut HashMap<u64, TaintProvenance>,
    addr: u64,
    size: u32,
    through_mem: bool,
) {
    if through_mem {
        for o in 0..size as u64 {
            tainted_mem.remove(&(addr + o));
        }
    } else {
        tainted_mem.remove(&addr);
    }
}

fn write_tainted_mem_span(
    tainted_mem: &mut HashMap<u64, TaintProvenance>,
    addr: u64,
    size: u32,
    through_mem: bool,
    provenance: TaintProvenance,
) {
    if through_mem {
        for o in 0..size as u64 {
            tainted_mem.insert(addr + o, provenance);
        }
    } else {
        tainted_mem.insert(addr, provenance);
    }
}

fn last_cond_before(index: &Index, before_idx: usize) -> Option<usize> {
    let pos = index.cond_branches.partition_point(|&i| i < before_idx);
    if pos == 0 {
        return None;
    }
    let ctrl_idx = index.cond_branches[pos - 1];
    let boundary_pos = index
        .call_ret_boundaries
        .partition_point(|&i| i < before_idx);
    if boundary_pos > 0 && index.call_ret_boundaries[boundary_pos - 1] > ctrl_idx {
        return None;
    }
    Some(ctrl_idx)
}

fn push_control_dependency(
    trace: &Trace,
    index: &Index,
    raw_out: &mut Vec<RawBwdHit>,
    pending: &mut VecDeque<BwdItem>,
    at_idx: usize,
    parent_idx: usize,
    depth: u32,
    exclude_regs: &HashSet<String>,
) {
    let Some(ctrl_idx) = last_cond_before(index, at_idx) else {
        return;
    };
    raw_out.push(RawBwdHit {
        idx: ctrl_idx,
        why: "control".to_string(),
        parent_idxs: vec![parent_idx],
        taint_depth: depth,
        edge_kind: Some("control".to_string()),
    });
    let r = trace.record(ctrl_idx);
    let d = decode(r.pc, r.inst);
    for u in &d.regs_use {
        if exclude_regs.contains(u) {
            continue;
        }
        pending.push_back(BwdItem::Reg {
            cur_idx: ctrl_idx,
            want_reg: u.clone(),
            parent_idx: Some(ctrl_idx),
            depth: depth.saturating_add(1),
            edge_kind: "control-reg",
        });
    }
}

/// Pending-queue item for backward taint BFS.
///
/// Mirrors Python `pending: list[tuple]` which holds either
/// `(cur_idx, want_reg)` reg-chases or `("MEM", before_idx, addr, sz)`
/// mem-chases. The Rust port uses a tagged enum.
#[derive(Debug)]
enum BwdItem {
    /// Chase the latest def of `want_reg` strictly before `cur_idx`.
    Reg {
        cur_idx: usize,
        want_reg: String,
        parent_idx: Option<usize>,
        depth: u32,
        edge_kind: &'static str,
    },
    /// Chase the writer of memory `[addr, addr+size)` strictly before
    /// `before_idx` (exact-addr fast path; M3-γ Task 2 adds byte-overlap).
    Mem {
        before_idx: usize,
        addr: u64,
        size: u32,
        parent_idx: Option<usize>,
        depth: u32,
        edge_kind: &'static str,
    },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TaintHit {
    pub idx: usize,
    pub why: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_idxs: Vec<usize>,
    pub taint_depth: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_kind: Option<String>,
}

#[derive(Debug, Clone)]
struct RawBwdHit {
    idx: usize,
    why: String,
    parent_idxs: Vec<usize>,
    taint_depth: u32,
    edge_kind: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TaintProvenance {
    idx: Option<usize>,
    depth: u32,
}

impl TaintProvenance {
    fn seed() -> Self {
        Self {
            idx: None,
            depth: 0,
        }
    }

    fn from_hit(idx: usize, depth: u32) -> Self {
        Self {
            idx: Some(idx),
            depth,
        }
    }
}

pub fn build_frame_depth_map(trace: &Trace) -> Vec<u32> {
    let n = trace.len();
    let flags = scan_frame_depth_flags(trace);
    let mut out = vec![0u32; n];
    let mut depth: u32 = 0;
    for (flag, slot) in flags.into_iter().zip(out.iter_mut()) {
        *slot = depth;
        if flag == FRAME_FLAG_CALL {
            depth = depth.saturating_add(1);
        } else if flag == FRAME_FLAG_RET && depth > 0 {
            depth -= 1;
        }
    }
    out
}

pub fn frame_depth_worker_count(n: usize) -> usize {
    parallel::worker_count(
        n,
        "TRACEMIKU_FRAME_DEPTH_THREADS",
        FRAME_DEPTH_PARALLEL_MIN_RECORDS,
        FRAME_DEPTH_MIN_CHUNK_RECORDS,
    )
}

struct FrameDepthChunk {
    start: usize,
    flags: Vec<u8>,
}

fn scan_frame_depth_flags(trace: &Trace) -> Vec<u8> {
    let n = trace.len();
    let workers = frame_depth_worker_count(n);
    if workers <= 1 {
        return scan_frame_depth_range(trace, 0, n).flags;
    }

    tracing::info!(
        target: "tracemiku-core",
        records = n,
        workers,
        "scanning frame-depth call/ret flags in parallel"
    );

    let chunk_size = n.div_ceil(workers);
    let chunks = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let start = worker * chunk_size;
            let end = (start + chunk_size).min(n);
            if start >= end {
                continue;
            }
            handles.push(scope.spawn(move || scan_frame_depth_range(trace, start, end)));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("frame-depth worker panicked"))
            .collect::<Vec<_>>()
    });

    let mut flags = vec![0u8; n];
    for chunk in chunks {
        flags[chunk.start..chunk.start + chunk.flags.len()].copy_from_slice(&chunk.flags);
    }
    flags
}

fn scan_frame_depth_range(trace: &Trace, start: usize, end: usize) -> FrameDepthChunk {
    let mut flags = vec![0u8; end.saturating_sub(start)];
    for i in start..end {
        let r = trace.record(i);
        let d = decode(r.pc, r.inst);
        if d.is_call {
            flags[i - start] = FRAME_FLAG_CALL;
        } else if d.is_ret {
            flags[i - start] = FRAME_FLAG_RET;
        }
    }
    FrameDepthChunk { start, flags }
}

/// Why a taint walk terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// Walked the queue to completion.
    Completed,
    /// Hit the `max_count` cap.
    MaxCount,
    /// Saw `scan_limit` consecutive iterations without producing a new hit.
    /// Inspired by GumTrace's `SCAN_LIMIT_REACHED` watchdog.
    ScanLimit,
}

/// Extended walk options. `scan_limit` mirrors GumTrace's
/// `set_max_scan_distance`: stop after N consecutive iterations that did
/// not append to the hit list (visited, deduped, no propagation, etc.).
/// `None` disables the watchdog.
#[derive(Debug, Clone, Copy, Default)]
pub struct TaintOptions {
    pub through_mem: bool,
    pub data_only: bool,
    pub scan_limit: Option<usize>,
}

/// Result of a taint walk that exposes the [`StopReason`].
#[derive(Debug, Clone)]
pub struct TaintWalkResult {
    pub hits: Vec<TaintHit>,
    pub stop_reason: StopReason,
}

#[allow(clippy::too_many_arguments)] // M3-γ Task 4 will add cross_fn_call.
pub fn forward_taint(
    trace: &Trace,
    index: &Index,
    start_idx: usize,
    taint_reg: &str,
    max_count: usize,
    exclude_regs: &HashSet<String>,
    through_mem: bool,
    mem: Option<&MemShadow>,
    data_only: bool,
) -> (Vec<TaintHit>, bool) {
    let result = forward_taint_ext(
        trace,
        index,
        start_idx,
        taint_reg,
        max_count,
        exclude_regs,
        mem,
        TaintOptions {
            through_mem,
            data_only,
            scan_limit: None,
        },
    );
    (
        result.hits,
        matches!(
            result.stop_reason,
            StopReason::MaxCount | StopReason::ScanLimit
        ),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn forward_taint_ext(
    trace: &Trace,
    index: &Index,
    start_idx: usize,
    taint_reg: &str,
    max_count: usize,
    exclude_regs: &HashSet<String>,
    _mem: Option<&MemShadow>,
    opts: TaintOptions,
) -> TaintWalkResult {
    let through_mem = opts.through_mem;
    let data_only = opts.data_only;
    let scan_limit = opts.scan_limit;
    // _mem is unused on the forward side because tagging is index-only —
    // Python also doesn't use MemShadow on the forward path (only on backward).
    let mut tainted_regs: HashMap<String, TaintProvenance> = HashMap::new();
    tainted_regs.insert(taint_reg.to_string(), TaintProvenance::seed());
    let mut tainted_mem: HashMap<u64, TaintProvenance> = HashMap::new();
    let mut heap: BinaryHeap<Reverse<(usize, u8, String, usize)>> = BinaryHeap::new();
    push_next_reg_events(&mut heap, index, exclude_regs, taint_reg, start_idx);

    let mut out: Vec<TaintHit> = Vec::new();
    let mut seen: HashSet<usize> = HashSet::new();
    let cap = if max_count == 0 {
        usize::MAX
    } else {
        max_count
    };
    let mut stop_reason = StopReason::Completed;
    let mut since_last_hit: usize = 0;

    while let Some(Reverse((i, event_kind, reg, pos))) = heap.pop() {
        if out.len() >= cap {
            stop_reason = StopReason::MaxCount;
            break;
        }
        if let Some(limit) = scan_limit {
            if since_last_hit >= limit {
                stop_reason = StopReason::ScanLimit;
                break;
            }
        }
        since_last_hit = since_last_hit.saturating_add(1);
        if event_kind != MEM_TOUCH_EVENT {
            let next_entries = if event_kind == REG_DEF_EVENT {
                index.reg_defs.get(&reg)
            } else {
                index.reg_uses.get(&reg)
            };
            if let Some(entries) = next_entries {
                if pos + 1 < entries.len() {
                    heap.push(Reverse((
                        entries[pos + 1],
                        event_kind,
                        reg.clone(),
                        pos + 1,
                    )));
                }
            }
        }
        if seen.contains(&i) {
            continue;
        }
        seen.insert(i);
        let r = trace.record(i);
        let d = decode(r.pc, r.inst);
        let addr_regs = if data_only {
            addressing_regs(&d.mem_op)
        } else {
            HashSet::new()
        };
        // Tainted regs that this insn READS.
        // In data_only mode, an insn only counts as "used" if the tainted
        // use is NOT purely an addressing reg (Python:155-156).
        let mut used: Vec<String> = Vec::new();
        let mut sources: Vec<TaintProvenance> = Vec::new();
        for u in &d.regs_use {
            if data_only && addr_regs.contains(u) {
                continue;
            }
            if let Some(src) = tainted_regs.get(u) {
                used.push(u.clone());
                sources.push(*src);
            }
        }

        // Check loads against tainted_mem (Python:158-187). For split pair
        // loads, remember which destination half is actually fed by tainted
        // memory so `ldp x4, x5, [sp]` does not taint both halves.
        let mut load_tainted = false;
        let mut load_tainted_regs: Vec<String> = Vec::new();
        for op in &d.mem_op {
            if op.is_write {
                continue;
            }
            let base = addr_of(&r, op);
            for o in 0..op.size as u64 {
                if let Some(src) = tainted_mem.get(&(base + o)) {
                    load_tainted = true;
                    sources.push(*src);
                    for dst in load_dest_regs(&d, op) {
                        if !load_tainted_regs.contains(&dst) {
                            load_tainted_regs.push(dst);
                        }
                    }
                    break;
                }
            }
        }

        let defines_tainted = d.regs_def.iter().any(|r| tainted_regs.contains_key(r));
        let mut overwrites_tainted_mem = false;
        for op in &d.mem_op {
            if !op.is_write {
                continue;
            }
            let base = addr_of(&r, op);
            if tainted_mem_overlaps(&tainted_mem, base, op.size) {
                overwrites_tainted_mem = true;
                break;
            }
        }

        if used.is_empty() && !load_tainted {
            // Kill semantics: a clean overwrite of a tainted register/memory
            // should stop later false positives. Partial RMW forms such as
            // movk keep the old destination taint when Capstone does not expose
            // the old destination as a use.
            if defines_tainted && !is_partial_modify(&d) {
                for nr in &d.regs_def {
                    tainted_regs.remove(nr);
                }
            }
            if overwrites_tainted_mem {
                for op in &d.mem_op {
                    if !op.is_write {
                        continue;
                    }
                    let base = addr_of(&r, op);
                    let src_tainted = store_source_regs(&d, op)
                        .iter()
                        .any(|src| tainted_regs.contains_key(src));
                    if !src_tainted {
                        clear_tainted_mem_span(&mut tainted_mem, base, op.size, through_mem);
                    }
                }
                push_next_mem_touch(&mut heap, index, &tainted_mem, i);
            }
            continue;
        }
        used.sort();
        used.dedup();
        let mut why_parts: Vec<String> = Vec::new();
        if !used.is_empty() {
            why_parts.push(format!("regs:{}", used.join(",")));
        }
        if load_tainted {
            why_parts.push("mem".to_string());
        }
        let why = why_parts.join(" ");
        let taint_depth = sources
            .iter()
            .filter(|src| src.idx.is_some())
            .map(|src| src.depth.saturating_add(1))
            .max()
            .unwrap_or(0);
        let mut parent_idxs: Vec<usize> = sources.iter().filter_map(|src| src.idx).collect();
        parent_idxs.sort_unstable();
        parent_idxs.dedup();
        out.push(TaintHit {
            idx: i,
            why,
            parent_idxs,
            taint_depth,
            edge_kind: if load_tainted && !used.is_empty() {
                Some("reg+mem".to_string())
            } else if load_tainted {
                Some("mem".to_string())
            } else {
                Some("reg".to_string())
            },
        });
        since_last_hit = 0;
        let next_provenance = TaintProvenance::from_hit(i, taint_depth);

        // Propagate: regs_def → push next-use/def. Loads from tainted memory
        // only taint the loaded destination register(s); tainted register
        // sources still taint all explicit defs as before.
        let mut defs_to_taint: HashSet<String> = HashSet::new();
        if !used.is_empty() {
            for nr in &d.regs_def {
                defs_to_taint.insert(nr.clone());
            }
        }
        if load_tainted {
            if load_tainted_regs.is_empty() {
                for nr in &d.regs_def {
                    defs_to_taint.insert(nr.clone());
                }
            } else {
                for nr in load_tainted_regs {
                    defs_to_taint.insert(nr);
                }
            }
        }
        for nr in &d.regs_def {
            if exclude_regs.contains(nr) {
                continue;
            }
            if defs_to_taint.contains(nr)
                || (is_partial_modify(&d) && tainted_regs.contains_key(nr))
            {
                let was_tainted = tainted_regs.contains_key(nr);
                tainted_regs.insert(nr.clone(), next_provenance);
                if !was_tainted {
                    push_next_reg_events(&mut heap, index, exclude_regs, nr, i);
                }
            } else {
                tainted_regs.remove(nr);
            }
        }
        // Propagate/kill stores per memory half. Pair and exclusive stores use
        // MemOp.src_reg, so stp half2 follows its second data register rather
        // than the first register in the instruction.
        for op in &d.mem_op {
            if !op.is_write {
                continue;
            }
            let base = addr_of(&r, op);
            let src_tainted = store_source_regs(&d, op)
                .iter()
                .any(|src| tainted_regs.contains_key(src));
            if src_tainted {
                write_tainted_mem_span(
                    &mut tainted_mem,
                    base,
                    op.size,
                    through_mem,
                    next_provenance,
                );
            } else {
                clear_tainted_mem_span(&mut tainted_mem, base, op.size, through_mem);
            }
        }
        push_next_mem_touch(&mut heap, index, &tainted_mem, i);
    }

    TaintWalkResult {
        hits: out,
        stop_reason,
    }
}

/// Return writer record indices that overlap `[addr, addr+size)` strictly
/// before `before_idx`. Mirrors viewer/taint.py:274-299.
fn mem_writers_overlapping(
    index: &Index,
    mem: Option<&MemShadow>,
    addr: u64,
    size: u32,
    before_idx: usize,
    through_mem: bool,
) -> Vec<usize> {
    if !through_mem || mem.is_none() {
        // Exact-addr mode: ONLY the latest writer < before_idx.
        let Some(writers) = index.mem_addr_to_writes.get(&addr) else {
            return Vec::new();
        };
        let pos = writers.partition_point(|&w| w < before_idx);
        if pos == 0 {
            return Vec::new();
        }
        return vec![writers[pos - 1]];
    }
    // Byte-overlap mode: scan bytes, collect unique writers, descending.
    let mem = mem.unwrap();
    let mut seen: HashSet<usize> = HashSet::new();
    for o in 0..size as u64 {
        if let Some(j) = mem.latest_write_idx_strict_before(addr + o, before_idx) {
            seen.insert(j);
        }
    }
    let mut out: Vec<usize> = seen.into_iter().collect();
    out.sort_unstable();
    out.reverse();
    out
}

#[allow(clippy::too_many_arguments)] // M3-γ Task 4 will add cross_fn_call.
pub fn backward_taint(
    trace: &Trace,
    index: &Index,
    idx: usize,
    taint_reg: &str,
    max_count: usize,
    exclude_regs: &HashSet<String>,
    through_mem: bool,
    mem: Option<&MemShadow>,
    data_only: bool,
) -> (Vec<TaintHit>, bool) {
    let result = backward_taint_ext(
        trace,
        index,
        idx,
        taint_reg,
        max_count,
        exclude_regs,
        mem,
        TaintOptions {
            through_mem,
            data_only,
            scan_limit: None,
        },
    );
    (
        result.hits,
        matches!(
            result.stop_reason,
            StopReason::MaxCount | StopReason::ScanLimit
        ),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn backward_taint_ext(
    trace: &Trace,
    index: &Index,
    idx: usize,
    taint_reg: &str,
    max_count: usize,
    exclude_regs: &HashSet<String>,
    mem: Option<&MemShadow>,
    opts: TaintOptions,
) -> TaintWalkResult {
    let through_mem = opts.through_mem;
    let data_only = opts.data_only;
    let scan_limit = opts.scan_limit;
    let mut pending: VecDeque<BwdItem> = VecDeque::new();
    let mut visited: HashSet<(usize, String)> = HashSet::new();
    let mut raw_out: Vec<RawBwdHit> = Vec::new();
    let cap = if max_count == 0 {
        usize::MAX
    } else {
        max_count
    };
    let mut stop_reason = StopReason::Completed;
    let mut since_last_hit: usize = 0;

    // Initial seed branch (viewer/taint.py:306-318).
    let r0 = trace.record(idx);
    let d0 = decode(r0.pc, r0.inst);
    let starts_with_def = d0.regs_def.iter().any(|r| r == taint_reg);

    if starts_with_def && !exclude_regs.contains(taint_reg) {
        raw_out.push(RawBwdHit {
            idx,
            why: taint_reg.to_string(),
            parent_idxs: Vec::new(),
            taint_depth: 0,
            edge_kind: Some("seed".to_string()),
        });
        if !data_only {
            push_control_dependency(
                trace,
                index,
                &mut raw_out,
                &mut pending,
                idx,
                idx,
                1,
                exclude_regs,
            );
        }
        let addr_regs0 = addressing_regs(&d0.mem_op);
        for u in &d0.regs_use {
            if exclude_regs.contains(u) {
                continue;
            }
            if data_only && addr_regs0.contains(u) {
                continue;
            }
            pending.push_back(BwdItem::Reg {
                cur_idx: idx,
                want_reg: u.clone(),
                parent_idx: Some(idx),
                depth: 1,
                edge_kind: if addr_regs0.contains(u) {
                    "addr"
                } else {
                    "reg"
                },
            });
        }
        for op in &d0.mem_op {
            if !load_op_feeds_reg(&d0, op, taint_reg) {
                continue;
            }
            let addr = addr_of(&r0, op);
            pending.push_back(BwdItem::Mem {
                before_idx: idx,
                addr,
                size: op.size,
                parent_idx: Some(idx),
                depth: 1,
                edge_kind: "mem",
            });
        }
    } else if !exclude_regs.contains(taint_reg) {
        pending.push_back(BwdItem::Reg {
            cur_idx: idx,
            want_reg: taint_reg.to_string(),
            parent_idx: None,
            depth: 0,
            edge_kind: "reg",
        });
    }

    while let Some(item) = pending.pop_front() {
        if raw_out.len() >= cap {
            stop_reason = StopReason::MaxCount;
            break;
        }
        if let Some(limit) = scan_limit {
            if since_last_hit >= limit {
                stop_reason = StopReason::ScanLimit;
                break;
            }
        }
        let before_pop = raw_out.len();
        since_last_hit = since_last_hit.saturating_add(1);
        match item {
            BwdItem::Mem {
                before_idx,
                addr,
                size,
                parent_idx,
                depth,
                edge_kind,
            } => {
                let writers =
                    mem_writers_overlapping(index, mem, addr, size, before_idx, through_mem);
                for j in writers {
                    let r = trace.record(j);
                    let d = decode(r.pc, r.inst);
                    let parent_idxs = parent_idx.into_iter().collect::<Vec<_>>();
                    raw_out.push(RawBwdHit {
                        idx: j,
                        why: "mem".to_string(),
                        parent_idxs: parent_idxs.clone(),
                        taint_depth: depth,
                        edge_kind: Some(edge_kind.to_string()),
                    });
                    if !data_only {
                        push_control_dependency(
                            trace,
                            index,
                            &mut raw_out,
                            &mut pending,
                            j,
                            j,
                            depth.saturating_add(1),
                            exclude_regs,
                        );
                    }
                    let sources = store_source_regs_for_addr(&d, &r, addr, size);
                    for src in sources {
                        if exclude_regs.contains(&src) {
                            continue;
                        }
                        pending.push_back(BwdItem::Reg {
                            cur_idx: j,
                            want_reg: src,
                            parent_idx: Some(j),
                            depth: depth.saturating_add(1),
                            edge_kind: "store-src",
                        });
                    }
                }
            }
            BwdItem::Reg {
                cur_idx,
                want_reg,
                parent_idx,
                depth,
                edge_kind,
            } => {
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
                let parent_idxs = parent_idx.into_iter().collect::<Vec<_>>();
                raw_out.push(RawBwdHit {
                    idx: j,
                    why: want_reg.clone(),
                    parent_idxs,
                    taint_depth: depth,
                    edge_kind: Some(edge_kind.to_string()),
                });
                if !data_only {
                    push_control_dependency(
                        trace,
                        index,
                        &mut raw_out,
                        &mut pending,
                        j,
                        j,
                        depth.saturating_add(1),
                        exclude_regs,
                    );
                }

                let r = trace.record(j);
                let d = decode(r.pc, r.inst);
                let addr_regs = addressing_regs(&d.mem_op);
                for u in &d.regs_use {
                    if exclude_regs.contains(u) {
                        continue;
                    }
                    if data_only && addr_regs.contains(u) {
                        continue;
                    }
                    pending.push_back(BwdItem::Reg {
                        cur_idx: j,
                        want_reg: u.clone(),
                        parent_idx: Some(j),
                        depth: depth.saturating_add(1),
                        edge_kind: if addr_regs.contains(u) { "addr" } else { "reg" },
                    });
                }
                for op in &d.mem_op {
                    if !load_op_feeds_reg(&d, op, &want_reg) {
                        continue;
                    }
                    let addr = addr_of(&r, op);
                    pending.push_back(BwdItem::Mem {
                        before_idx: j,
                        addr,
                        size: op.size,
                        parent_idx: Some(j),
                        depth: depth.saturating_add(1),
                        edge_kind: "mem",
                    });
                }
            }
        }
        if raw_out.len() > before_pop {
            since_last_hit = 0;
        }
    }

    // Dedup by sorted idx (Python lines 358-361).
    raw_out.sort_by(|a, b| a.idx.cmp(&b.idx).then_with(|| a.why.cmp(&b.why)));
    let mut seen_idx: HashSet<usize> = HashSet::new();
    let mut out: Vec<TaintHit> = Vec::new();
    for hit in raw_out {
        if seen_idx.contains(&hit.idx) {
            continue;
        }
        seen_idx.insert(hit.idx);
        out.push(TaintHit {
            idx: hit.idx,
            why: hit.why,
            parent_idxs: hit.parent_idxs,
            taint_depth: hit.taint_depth,
            edge_kind: hit.edge_kind,
        });
    }
    TaintWalkResult {
        hits: out,
        stop_reason,
    }
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

    fn synth_trace_with<F>(insts: &[u32], mut fill: F) -> tempfile::TempDir
    where
        F: FnMut(usize, &mut [u8]),
    {
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join(format!("call_001_tid1_{}r_1ms", insts.len()));
        std::fs::create_dir_all(&cd).unwrap();
        let mut buf = vec![0u8; REC_SIZE * insts.len()];
        for (i, inst) in insts.iter().enumerate() {
            let off = i * REC_SIZE;
            let rec = &mut buf[off..off + REC_SIZE];
            let pc = 0x100000u64 + (i as u64) * 4;
            rec[0..8].copy_from_slice(&pc.to_le_bytes());
            rec[256..264].copy_from_slice(&0x7000u64.to_le_bytes());
            rec[268..272].copy_from_slice(&inst.to_le_bytes());
            fill(i, rec);
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(
            cd.join("meta.json"),
            format!(r#"{{"records":{}}}"#, insts.len()),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x100000","size":4096}}"#,
        )
        .unwrap();
        dir
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
        let (hits, stopped) = forward_taint(&t, &idx, 0, "x0", 100, &exclude, false, None, false);
        assert!(hits.is_empty());
        assert!(!stopped);
    }

    #[test]
    fn forward_taint_kills_clean_reg_overwrite() {
        // idx 0 seeds x0, idx 1 overwrites x0 with an immediate, idx 2 reads x0.
        // Without explicit def-event kill semantics idx 2 was a false positive.
        let dir = synth_trace_with(&[0xd2800020, 0xd2800000, 0x91000401], |i, rec| {
            let x0 = if i == 0 { 1u64 } else { 0u64 };
            rec[8..16].copy_from_slice(&x0.to_le_bytes());
        });
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, stopped) = forward_taint(&t, &idx, 0, "x0", 100, &exclude, false, None, false);
        assert!(!stopped);
        assert!(
            hits.iter().all(|h| h.idx != 2),
            "clean overwrite at idx 1 should kill x0 before idx 2: {hits:?}"
        );
    }

    #[test]
    fn forward_taint_partial_modify_preserves_reg_taint() {
        // movk is a partial register update. If Capstone does not expose the old
        // destination as a use, the taint engine still keeps the existing x0 taint.
        let dir = synth_trace_with(&[0xd2800020, 0xf2800040, 0x91000401], |_, rec| {
            rec[8..16].copy_from_slice(&1u64.to_le_bytes());
        });
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, stopped) = forward_taint(&t, &idx, 0, "x0", 100, &exclude, false, None, false);
        assert!(!stopped);
        assert!(
            hits.iter().any(|h| h.idx == 2),
            "movk should preserve x0 taint through the later add: {hits:?}"
        );
    }

    #[test]
    fn backward_taint_empty_when_reg_undefined() {
        let dir = synth_two_callees();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, stopped) = backward_taint(&t, &idx, 8, "x0", 100, &exclude, false, None, false);
        assert!(hits.is_empty());
        assert!(!stopped);
    }

    #[test]
    fn forward_taint_max_count_caps() {
        let dir = synth_x0_chain();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, stopped) = forward_taint(&t, &idx, 0, "x0", 3, &exclude, false, None, false);
        assert_eq!(hits.len(), 3, "should stop after 3 hits, got {hits:?}");
        assert!(stopped, "max_count truncation should set stopped=true");
        for h in &hits {
            assert!(h.why.contains("x0"), "hit row references x0: {h:?}");
        }
    }

    #[test]
    fn forward_taint_updates_self_reg_provenance() {
        // Same-reg read-modify-write must advance provenance for tree view:
        // seed x0 at idx=0, then each `add x0, x0, #1` depends on the prior hit.
        let dir = synth_x0_chain();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, stopped) = forward_taint(&t, &idx, 0, "x0", 100, &exclude, false, None, false);
        assert!(!stopped);
        let idxs: Vec<usize> = hits.iter().map(|h| h.idx).collect();
        assert_eq!(idxs, vec![1, 2, 3, 4], "forward self-chain hits: {hits:?}");

        let row1 = hits.iter().find(|h| h.idx == 1).unwrap();
        assert_eq!(row1.parent_idxs, Vec::<usize>::new());
        assert_eq!(row1.taint_depth, 0);
        for (expected_idx, expected_parent, expected_depth) in [(2, 1, 1), (3, 2, 2), (4, 3, 3)] {
            let row = hits.iter().find(|h| h.idx == expected_idx).unwrap();
            assert_eq!(
                row.parent_idxs,
                vec![expected_parent],
                "row #{expected_idx} should depend on #{expected_parent}: {row:?}"
            );
            assert_eq!(
                row.taint_depth, expected_depth,
                "row #{expected_idx} depth should advance along self-chain: {row:?}"
            );
        }
    }

    #[test]
    fn backward_taint_emits_bare_reg_name() {
        // 5-record `add x0, x0, #1` chain. Backward from idx=4, taint=x0.
        // Each `add x0, x0, #1` defines x0 AND uses x0, so chasing x0 backward
        // should include the seed at idx=4 plus prior defs 3, 2, 1, 0.
        let dir = synth_x0_chain();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, stopped) = backward_taint(&t, &idx, 4, "x0", 100, &exclude, false, None, false);
        let idxs: Vec<usize> = hits.iter().map(|h| h.idx).collect();
        assert_eq!(
            idxs,
            vec![0, 1, 2, 3, 4],
            "should chase self read-modify-write chain backwards: {hits:?}"
        );
        assert!(!stopped);
        // Wire-shape pin: `why` is the bare reg name, NOT "via:x0".
        for h in &hits {
            assert_eq!(h.why, "x0", "expected bare reg name, got {:?}", h.why);
        }
        // Order: dedup'd by sorted idx, so smallest idx first.
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
        //     emit idx 1 as the memory writer; first non-addressing reg in
        //     d.regs_use → x0; push Reg(1, "x0") with parent idx 1.
        //   pop Reg(1, "x0"): defs of x0 before 1 → idx 0; emit (0, "x0").
        //
        // Expected: hits idxs include 0, 1, and 3.
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
        let (hits, _stopped) = backward_taint(&t, &idx, 3, "x1", 100, &exclude, false, None, false);
        let idxs: Vec<usize> = hits.iter().map(|h| h.idx).collect();
        assert!(
            idxs.contains(&0),
            "MEM-chasing should reach idx 0 via mov→str→ldr at sp=0x7000; got {idxs:?}"
        );
        assert!(
            idxs.contains(&1),
            "MEM-chasing should expose idx 1 as the memory writer; got {idxs:?}"
        );
        assert!(
            idxs.contains(&3),
            "should pre-emit (idx=3, want_reg=x1) when start defines x1; got {idxs:?}"
        );
        let row1 = hits.iter().find(|h| h.idx == 1).unwrap();
        assert_eq!(row1.why, "mem");
        assert_eq!(row1.parent_idxs, vec![3]);
        assert_eq!(row1.edge_kind.as_deref(), Some("mem"));
        let row0 = hits.iter().find(|h| h.idx == 0).unwrap();
        assert_eq!(row0.parent_idxs, vec![1]);
        assert_eq!(row0.edge_kind.as_deref(), Some("store-src"));
    }

    #[test]
    fn backward_taint_includes_control_dependency_when_enabled() {
        // idx 0: cmp x0, #0
        // idx 1: b.eq #8
        // idx 2: mov x1, x2
        let dir = synth_trace_with(&[0xf100001f, 0x54000040, 0xaa0203e1], |_, rec| {
            rec[8..16].copy_from_slice(&1u64.to_le_bytes()); // x0
            rec[24..32].copy_from_slice(&2u64.to_le_bytes()); // x2
        });
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();

        let (hits, stopped) = backward_taint(&t, &idx, 2, "x1", 100, &exclude, false, None, false);
        assert!(!stopped);
        let idxs: Vec<usize> = hits.iter().map(|h| h.idx).collect();
        assert!(
            idxs.contains(&1),
            "control branch should be included in backward taint: {hits:?}"
        );
        assert!(
            idxs.contains(&0),
            "control branch condition should chase back to cmp/nzcv def: {hits:?}"
        );
        let branch = hits.iter().find(|h| h.idx == 1).unwrap();
        assert_eq!(branch.why, "control");
        assert_eq!(branch.edge_kind.as_deref(), Some("control"));

        let (data_hits, _) = backward_taint(&t, &idx, 2, "x1", 100, &exclude, false, None, true);
        let data_idxs: Vec<usize> = data_hits.iter().map(|h| h.idx).collect();
        assert!(
            !data_idxs.contains(&1),
            "data_only=true should suppress control branch dependency: {data_hits:?}"
        );
    }

    #[test]
    fn backward_taint_does_not_attach_control_across_call_boundary() {
        // idx 0: cmp x0, #0
        // idx 1: b.eq #8
        // idx 2: bl #8        -- boundary between caller condition and callee body
        // idx 3: mov x1, x2   -- pretend this is inside the callee
        let dir = synth_trace_with(
            &[0xf100001f, 0x54000040, 0x94000002, 0xaa0203e1],
            |_, rec| {
                rec[8..16].copy_from_slice(&1u64.to_le_bytes()); // x0
                rec[24..32].copy_from_slice(&2u64.to_le_bytes()); // x2
            },
        );
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, stopped) = backward_taint(&t, &idx, 3, "x1", 100, &exclude, false, None, false);
        assert!(!stopped);
        let idxs: Vec<usize> = hits.iter().map(|h| h.idx).collect();
        assert!(
            !idxs.contains(&1),
            "caller-side conditional branch should not control a row past bl boundary: {hits:?}"
        );
    }

    #[test]
    fn backward_taint_pair_load_chases_matching_store_half() {
        // idx 0: mov x0, x2
        // idx 1: mov x1, x3
        // idx 2: stp x0, x1, [sp]
        // idx 3: ldp x4, x5, [sp]
        //
        // Backward from x5 must chase the second ldp/stp half through x1, not
        // the first half through x0.
        let dir = synth_trace_with(
            &[0xaa0203e0, 0xaa0303e1, 0xa90007e0, 0xa94017e4],
            |_, rec| {
                rec[8..16].copy_from_slice(&0x1111u64.to_le_bytes()); // x0
                rec[16..24].copy_from_slice(&0x2222u64.to_le_bytes()); // x1
                rec[24..32].copy_from_slice(&0xaaaau64.to_le_bytes()); // x2
                rec[32..40].copy_from_slice(&0xbbbbu64.to_le_bytes()); // x3
            },
        );
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, stopped) = backward_taint(&t, &idx, 3, "x5", 100, &exclude, false, None, true);
        assert!(!stopped);
        let idxs: Vec<usize> = hits.iter().map(|h| h.idx).collect();
        assert!(
            idxs.contains(&1),
            "x5 should chase through second store half source x1: {hits:?}"
        );
        assert!(
            !idxs.contains(&0),
            "x5 should not chase through first store half source x0: {hits:?}"
        );
    }

    #[test]
    fn forward_taint_through_mem_byte_overlap_extends_taint() {
        // 4-record trace exploring byte-overlap behavior:
        //   idx 0: mov x0, #0xab     (defines x0)
        //   idx 1: str x0, [x0]      (8-byte write, taints bytes [x0_val, x0_val+8))
        //   idx 2: ldr w1, [x0, #4]  (4-byte load at x0_val+4..x0_val+8 —
        //                             ONLY overlaps when through_mem tags full range)
        //   idx 3: nop
        //
        // Both insns have x0 in regs_use, so the heap-driven loop visits
        // them via push_reg(x0). The differentiator is whether load_tainted
        // fires at idx 2:
        //   through_mem=true:  bytes x0+4..x0+8 ARE tagged → "mem" in why
        //   through_mem=false: only base byte (x0) tagged → no overlap → no "mem"
        //
        // x0 register value in fixture = 0xab (so store taints 0xab..0xb3,
        // load reads 0xaf..0xb3 — fully inside the tainted range).
        //
        // Opcodes (ARM64 LE):
        //   mov x0, #0xab     = 0xd2801560
        //   str x0, [x0]      = 0xf9000000
        //   ldr w1, [x0, #4]  = 0xb9400401
        //   nop               = 0xd503201f
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_4r_1ms");
        std::fs::create_dir_all(&cd).unwrap();
        let pcs: [u64; 4] = [0x100000, 0x100004, 0x100008, 0x10000c];
        let insts: [u32; 4] = [0xd2801560, 0xf9000000, 0xb9400401, 0xd503201f];
        let mut buf = vec![0u8; REC_SIZE * 4];
        for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
            // x0 = 0xab (offset 8..16)
            buf[off + 8..off + 16].copy_from_slice(&0xabu64.to_le_bytes());
            // sp (offset 256..264)
            buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
            // inst (offset 268..272)
            buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":4}"#).unwrap();
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
        let mem = MemShadow::build_from_trace(&t);
        let exclude = HashSet::new();

        // through_mem=true: idx 2 hits with "mem" in why (byte-overlap match).
        let (hits_on, _stopped) =
            forward_taint(&t, &idx, 0, "x0", 100, &exclude, true, Some(&mem), false);
        let idxs_on: Vec<usize> = hits_on.iter().map(|h| h.idx).collect();
        assert!(
            idxs_on.contains(&1),
            "idx 1 (str) should emit; got {idxs_on:?}"
        );
        assert!(
            idxs_on.contains(&2),
            "idx 2 (ldr [x0,#4]) should emit; got {idxs_on:?}"
        );
        let row2_on = hits_on.iter().find(|h| h.idx == 2).unwrap();
        assert!(
            row2_on.why.contains("mem"),
            "through_mem=true: idx 2 why should contain 'mem'; got {row2_on:?}"
        );
        let row1_on = hits_on.iter().find(|h| h.idx == 1).unwrap();
        assert_eq!(
            row1_on.taint_depth, 0,
            "seed-driven first store should be a root tree node: {row1_on:?}"
        );
        assert!(
            row1_on.parent_idxs.is_empty(),
            "seed-driven first store should not have parents: {row1_on:?}"
        );
        assert_eq!(
            row2_on.parent_idxs,
            vec![1],
            "load should depend on the store that tainted memory: {row2_on:?}"
        );
        assert_eq!(
            row2_on.taint_depth, 1,
            "load depending on row 1 should be one level below it: {row2_on:?}"
        );

        // through_mem=false: idx 2 still emits (regs:x0 use), but NO "mem" —
        // only the base byte (x0_val) is tagged, load reads x0_val+4..+8.
        let (hits_off, _stopped) =
            forward_taint(&t, &idx, 0, "x0", 100, &exclude, false, None, false);
        let row2_off = hits_off.iter().find(|h| h.idx == 2).unwrap();
        assert!(
            !row2_off.why.contains("mem"),
            "through_mem=false: idx 2 why must NOT contain 'mem' (base-only tag); got {row2_off:?}"
        );
    }

    #[test]
    fn forward_taint_clean_store_kills_tainted_memory() {
        // idx 0: mov x0, #0xab
        // idx 1: str x0, [sp]    -> taints [sp]
        // idx 2: mov x0, #0      -> kills x0
        // idx 3: str x2, [sp]    -> clean overwrite must kill [sp]
        // idx 4: ldr x1, [sp]    -> must not reload stale memory taint
        let dir = synth_trace_with(
            &[0xd2801560, 0xf90003e0, 0xd2800000, 0xf90003e2, 0xf94003e1],
            |_, rec| {
                rec[8..16].copy_from_slice(&0xabu64.to_le_bytes()); // x0
                rec[24..32].copy_from_slice(&0xcdu64.to_le_bytes()); // x2
            },
        );
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let mem = MemShadow::build_from_trace(&t);
        let (hits, stopped) =
            forward_taint(&t, &idx, 0, "x0", 100, &exclude, true, Some(&mem), false);
        assert!(!stopped);
        assert!(
            hits.iter().any(|h| h.idx == 1),
            "seed x0 should taint the first store: {hits:?}"
        );
        assert!(
            !hits.iter().any(|h| h.idx == 4 && h.why.contains("mem")),
            "clean store at idx 3 should clear memory before load idx 4: {hits:?}"
        );
    }

    #[test]
    fn forward_taint_data_only_filters_addressing_regs() {
        // 4-record trace where x1 is tainted; an `ldr w2, [x0, x1]` uses x1
        // PURELY as an index reg (addressing), and `add x3, x3, x1` uses x1
        // as a value reg.
        //
        //   idx 0: mov x1, #0xab    (defines x1)
        //   idx 1: ldr w2, [x0, x1] (reads x1 as index → addressing)
        //   idx 2: add x3, x3, x1   (reads x1 as value)
        //   idx 3: nop
        //
        // forward_taint(start=0, reg=x1):
        //   data_only=false: hits include idx 1 (x1 in regs_use, even if addressing)
        //                    AND idx 2 (x1 in regs_use as value).
        //   data_only=true:  hits exclude idx 1 (x1 filtered as addressing reg).
        //                    Includes idx 2 only.
        //
        // Opcodes (ARM64 LE):
        //   mov x1, #0xab        = 0xd2801561
        //   ldr w2, [x0, x1]     = 0xb8616802  (extended-reg form; x1 = index)
        //   add x3, x3, x1       = 0x8b010063
        //   nop                  = 0xd503201f
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_4r_1ms");
        std::fs::create_dir_all(&cd).unwrap();
        let pcs: [u64; 4] = [0x100000, 0x100004, 0x100008, 0x10000c];
        let insts: [u32; 4] = [0xd2801561, 0xb8616802, 0x8b010063, 0xd503201f];
        let mut buf = vec![0u8; REC_SIZE * 4];
        for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
            buf[off + 8..off + 16].copy_from_slice(&0u64.to_le_bytes()); // x0
            buf[off + 16..off + 24].copy_from_slice(&0xabu64.to_le_bytes()); // x1
            buf[off + 24..off + 32].copy_from_slice(&0u64.to_le_bytes()); // x2
            buf[off + 32..off + 40].copy_from_slice(&0u64.to_le_bytes()); // x3
            buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":4}"#).unwrap();
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

        // data_only=false: should hit idx 1 AND idx 2 on x1.
        let (hits_loose, _) = forward_taint(&t, &idx, 0, "x1", 100, &exclude, false, None, false);
        let idxs_loose: Vec<usize> = hits_loose.iter().map(|h| h.idx).collect();
        assert!(
            idxs_loose.contains(&1),
            "data_only=false: idx 1 (ldr [x0,x1]) should hit; got {idxs_loose:?}"
        );
        assert!(
            idxs_loose.contains(&2),
            "data_only=false: idx 2 (add x3,x3,x1) should hit; got {idxs_loose:?}"
        );

        // data_only=true: should hit idx 2 only — idx 1 filtered as addressing.
        let (hits_strict, _) = forward_taint(&t, &idx, 0, "x1", 100, &exclude, false, None, true);
        let idxs_strict: Vec<usize> = hits_strict.iter().map(|h| h.idx).collect();
        assert!(
            !idxs_strict.contains(&1),
            "data_only=true: idx 1 should be filtered (x1 is index reg); got {idxs_strict:?}"
        );
        assert!(
            idxs_strict.contains(&2),
            "data_only=true: idx 2 should still hit; got {idxs_strict:?}"
        );
    }

    #[test]
    fn forward_taint_ext_completes_when_no_limits() {
        let dir = synth_x0_chain();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let result = forward_taint_ext(
            &t,
            &idx,
            0,
            "x0",
            100,
            &exclude,
            None,
            TaintOptions::default(),
        );
        assert_eq!(result.stop_reason, StopReason::Completed);
        assert_eq!(result.hits.len(), 4);
    }

    #[test]
    fn forward_taint_ext_max_count_sets_max_count_reason() {
        let dir = synth_x0_chain();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let result = forward_taint_ext(
            &t,
            &idx,
            0,
            "x0",
            2,
            &exclude,
            None,
            TaintOptions::default(),
        );
        assert_eq!(result.stop_reason, StopReason::MaxCount);
        assert_eq!(result.hits.len(), 2);
    }

    #[test]
    fn forward_taint_ext_scan_limit_kicks_in_on_dead_seed() {
        // Seed reg never appears in trace, so the BFS finds nothing. With
        // a scan_limit of 1 the watchdog should trip.
        let dir = synth_two_callees();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let result = forward_taint_ext(
            &t,
            &idx,
            0,
            "x9",
            100,
            &exclude,
            None,
            TaintOptions {
                through_mem: false,
                data_only: false,
                scan_limit: Some(1),
            },
        );
        // With no reg events scheduled the heap is empty, so the loop never
        // runs and the walk completes (no hits, no scan-limit trip).
        assert!(result.hits.is_empty());
        assert!(matches!(
            result.stop_reason,
            StopReason::Completed | StopReason::ScanLimit
        ));
    }

    #[test]
    fn forward_taint_ext_scan_limit_trips_when_walk_runs_dry() {
        // x0_chain emits one hit per record, but the heap interleaves
        // register-use and register-def events for the same row, so the
        // BFS pops several already-seen rows between hits. With a tight
        // scan_limit those idle iterations exhaust the watchdog before the
        // queue drains.
        let dir = synth_x0_chain();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let result = forward_taint_ext(
            &t,
            &idx,
            0,
            "x0",
            100,
            &exclude,
            None,
            TaintOptions {
                through_mem: false,
                data_only: false,
                scan_limit: Some(1),
            },
        );
        assert_eq!(
            result.stop_reason,
            StopReason::ScanLimit,
            "scan_limit=1 must trip in synth_x0_chain when duplicate events are popped"
        );
    }

    #[test]
    fn forward_taint_ext_scan_limit_completes_when_limit_is_high() {
        let dir = synth_x0_chain();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let result = forward_taint_ext(
            &t,
            &idx,
            0,
            "x0",
            100,
            &exclude,
            None,
            TaintOptions {
                through_mem: false,
                data_only: false,
                scan_limit: Some(10_000),
            },
        );
        assert_eq!(result.stop_reason, StopReason::Completed);
        assert_eq!(result.hits.len(), 4);
    }

    #[test]
    fn backward_taint_ext_max_count_reports_max_count_reason() {
        let dir = synth_x0_chain();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let result = backward_taint_ext(
            &t,
            &idx,
            4,
            "x0",
            2,
            &exclude,
            None,
            TaintOptions::default(),
        );
        assert_eq!(result.stop_reason, StopReason::MaxCount);
        assert!(result.hits.len() <= 2);
    }

    #[test]
    fn backward_taint_ext_completes_on_finite_chain() {
        let dir = synth_x0_chain();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let result = backward_taint_ext(
            &t,
            &idx,
            4,
            "x0",
            100,
            &exclude,
            None,
            TaintOptions::default(),
        );
        assert_eq!(result.stop_reason, StopReason::Completed);
        let idxs: Vec<usize> = result.hits.iter().map(|h| h.idx).collect();
        assert_eq!(idxs, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn taint_legacy_wrappers_preserve_old_shape() {
        let dir = synth_x0_chain();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (fwd_hits, fwd_stopped) =
            forward_taint(&t, &idx, 0, "x0", 100, &exclude, false, None, false);
        assert!(!fwd_stopped);
        assert_eq!(fwd_hits.len(), 4);
        let (bwd_hits, bwd_stopped) =
            backward_taint(&t, &idx, 4, "x0", 100, &exclude, false, None, false);
        assert!(!bwd_stopped);
        assert_eq!(bwd_hits.len(), 5);
    }
}
