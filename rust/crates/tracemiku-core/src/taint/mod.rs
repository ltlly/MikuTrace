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

/// 前向污点的内存触碰事件游标（事件驱动）。
///
/// 旧实现对每条处理过的指令都全量扫描 `tainted_mem` 的每个污染地址并取
/// 最小"下一次触碰"，复杂度 O(指令数 × 污染字节数 × log n)，`through_mem`
/// 扫大缓冲区时灾难性变慢。本结构改为按地址维护候选事件：
/// `(下一次触碰 idx, 地址)` 存入小顶堆，堆顶即全局最小。正确性依赖：
/// 1. 候选项的 idx 一定是该地址在 reads/writes 倒排表中的真实记录下标，
///    且插入/推进时是"当时游标之后的第一个下标"；游标单调不减，因此
///    任何 idx > 游标的候选项恰好是该地址当前的下一次触碰；
/// 2. 失活（地址已去污）或过期（idx <= 游标）的候选项只在堆顶暴露时被
///    惰性丢弃/推进；字节重新污染时总是插入新候选项。
///
/// 单次查询均摊 O(log n)，每个倒排表项至多被游标消费一次。
struct MemTouchTracker<'a> {
    reads: &'a HashMap<u64, Vec<usize>>,
    writes: &'a HashMap<u64, Vec<usize>>,
    /// 候选事件堆：`(下一次触碰 idx, 污染地址)`，按 idx 取最小。
    heap: BinaryHeap<Reverse<(usize, u64)>>,
    /// 已处理到的记录下标（单调不减）。
    cursor: usize,
}

impl<'a> MemTouchTracker<'a> {
    fn new(index: &'a Index) -> Self {
        Self {
            reads: &index.mem_addr_to_reads,
            writes: &index.mem_addr_to_writes,
            heap: BinaryHeap::new(),
            cursor: 0,
        }
    }

    /// 地址 `addr` 在 `lo` 之后（不含）的第一次读取/写入记录下标。
    fn next_posting(&self, addr: u64, lo: usize) -> Option<usize> {
        let next_in = |entries: Option<&Vec<usize>>| {
            let entries = entries?;
            let pos = entries.partition_point(|&idx| idx <= lo);
            entries.get(pos).copied()
        };
        match (
            next_in(self.reads.get(&addr)),
            next_in(self.writes.get(&addr)),
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// 字节地址新被污染时登记候选事件。
    fn taint(&mut self, addr: u64) {
        if let Some(idx) = self.next_posting(addr, self.cursor) {
            self.heap.push(Reverse((idx, addr)));
        }
    }

    fn advance_to(&mut self, idx: usize) {
        self.cursor = self.cursor.max(idx);
    }

    /// 当前全部污染字节的下一次触碰（读取或写入）的最小记录下标。
    fn next_touch(&mut self, tainted_mem: &HashMap<u64, TaintProvenance>) -> Option<usize> {
        while let Some(&Reverse((idx, addr))) = self.heap.peek() {
            if !tainted_mem.contains_key(&addr) {
                // 失活候选项：地址已去污，惰性丢弃。
                self.heap.pop();
                continue;
            }
            if idx > self.cursor {
                return Some(idx);
            }
            // 过期候选项：推进到游标之后的下一次触碰（没有则丢弃）。
            self.heap.pop();
            if let Some(next) = self.next_posting(addr, self.cursor) {
                self.heap.push(Reverse((next, addr)));
            }
        }
        None
    }

    /// 污染 `[addr, addr+size)`（`through_mem=false` 时只污染 `addr`）。
    /// 仅在新污染的字节上登记候选事件；已污染字节只刷新 provenance。
    fn write_span(
        &mut self,
        tainted_mem: &mut HashMap<u64, TaintProvenance>,
        addr: u64,
        size: u32,
        through_mem: bool,
        provenance: TaintProvenance,
    ) {
        if through_mem {
            for o in 0..size as u64 {
                if tainted_mem.insert(addr + o, provenance).is_none() {
                    self.taint(addr + o);
                }
            }
        } else if tainted_mem.insert(addr, provenance).is_none() {
            self.taint(addr);
        }
    }

    /// 去污 `[addr, addr+size)`。候选事件无需同步清理：失活项会在
    /// `next_touch` 堆顶暴露时被惰性丢弃。
    fn clear_span(
        &mut self,
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
}

fn push_next_mem_touch(
    heap: &mut BinaryHeap<Reverse<(usize, u8, String, usize)>>,
    mem_touch: &mut MemTouchTracker<'_>,
    tainted_mem: &HashMap<u64, TaintProvenance>,
    lo: usize,
) {
    mem_touch.advance_to(lo);
    if let Some(idx) = mem_touch.next_touch(tainted_mem) {
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

#[allow(clippy::too_many_arguments)] // BFS pipeline passes data dependencies; refactor is separate work.
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
    /// `before_idx`. Exact-addr fast path when `through_mem` is off;
    /// byte-overlap resolution when on (see `mem_writers_overlapping`).
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

mod backward;
mod forward;
#[cfg(test)]
mod tests;

pub use backward::{backward_taint, backward_taint_ext};
pub use forward::{forward_taint, forward_taint_ext};
