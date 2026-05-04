//! Sparse byte-level memory shadow built from a trace.
//!
//! Direct port of `viewer/memshadow.py:58-339`. Sidecar serialization is
//! intentionally **deferred** — eager build only.
//!
//! Each instruction has full register state captured BEFORE its execution.
//! Memory state is reconstructed by walking through stores (the source register
//! supplies the bytes, taken from the storing record's pre-state) AND loads
//! (the destination register in the NEXT record gives us the loaded value).
//!
//! Indexes:
//!  - `writes`: trace-ordered list of (insn_idx, addr, size, value) bytes written
//!  - `reads`:  trace-ordered list of (insn_idx, addr, size, value) bytes read
//!  - `bytes`:  BTreeMap<addr_byte, Vec<ByteEvent>> with idx-sorted events
//!
//! Query: [`MemShadow::byte_at(addr, t)`](MemShadow::byte_at) → `(value, kind,
//! source_idx)` returns the latest event with `idx <= t`, or `(None, "??",
//! None)` if no event yet.

use std::collections::BTreeMap;

use crate::disasm::{addr_of, decode, DecodedInsn, MemOp};
use crate::trace::Trace;

/// One byte-level memory event: which trace-record idx touched this byte,
/// the byte value, and the kind ("r" = load, "w" = store, "x" = external/
/// boundary-diff write — the latter is only populated when external writes
/// are loaded; this Rust port doesn't load them yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteEvent {
    pub idx: usize,
    pub byte: u8,
    pub kind: &'static str,
}

/// One memory-side index entry where the source/dest register WAS observable.
///
/// Note: this collides with [`crate::index::MemRec`]. The prelude re-exports
/// this one as `ShadowMemRec` to disambiguate. The `index::MemRec` has an
/// `Option<u64>` value; this one's value is always known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemRec {
    pub idx: usize,
    pub addr: u64,
    pub size: u32,
    pub value: u64,
}

/// Sparse byte-level memory shadow over a trace.
///
/// Built once from a [`Trace`]; immutable thereafter. Lookup APIs are
/// `byte_at` (point query), `hex_dump` (rectangular region), and
/// `find_strings` (printable-ASCII run scan).
pub struct MemShadow {
    pub writes: Vec<MemRec>,
    pub reads: Vec<MemRec>,
    pub bytes: BTreeMap<u64, Vec<ByteEvent>>,
}

impl MemShadow {
    /// Walk every record once; for each store, record the source-reg pre-state
    /// bytes; for each load, record the dest-reg post-state (next record's
    /// value) bytes. Mirrors `viewer/memshadow.py:74-110` minus the sidecar
    /// load/save and the external_writes.bin handling.
    pub fn build_from_trace(trace: &Trace) -> Self {
        let n = trace.len();
        let mut writes: Vec<MemRec> = Vec::new();
        let mut reads: Vec<MemRec> = Vec::new();
        let mut bytes: BTreeMap<u64, Vec<ByteEvent>> = BTreeMap::new();
        for i in 0..n {
            let rec = trace.record(i);
            let d = decode(rec.pc, rec.inst);
            for op in &d.mem_op {
                if op.base.is_empty() {
                    continue;
                }
                let addr = addr_of(&rec, op);
                if op.is_write {
                    if let Some(v) = value_of_write(trace, i, op, &d) {
                        writes.push(MemRec {
                            idx: i,
                            addr,
                            size: op.size,
                            value: v,
                        });
                        splat_bytes(&mut bytes, addr, op.size, v, i, "w");
                    }
                } else if let Some(v) = value_of_read(trace, i, op, &d) {
                    reads.push(MemRec {
                        idx: i,
                        addr,
                        size: op.size,
                        value: v,
                    });
                    splat_bytes(&mut bytes, addr, op.size, v, i, "r");
                }
            }
        }
        Self {
            writes,
            reads,
            bytes,
        }
    }

    /// Return `(byte_value, kind, source_idx)` for the latest event at `addr`
    /// with `idx <= t`. Binary-searches the per-addr event list (events are
    /// pushed in trace order so naturally sorted by idx).
    ///
    /// `(None, "??", None)` if no event exists at `addr` or if the earliest
    /// event has `idx > t`.
    pub fn byte_at(&self, addr: u64, t: u64) -> (Option<u8>, &'static str, Option<usize>) {
        let evs = match self.bytes.get(&addr) {
            Some(e) => e,
            None => return (None, "??", None),
        };
        let mut lo = 0usize;
        let mut hi = evs.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if (evs[mid].idx as u64) <= t {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return (None, "??", None);
        }
        let ev = &evs[lo - 1];
        (Some(ev.byte), ev.kind, Some(ev.idx))
    }

    /// Return the idx of the latest WRITE event at `byte_addr` strictly
    /// before `before_idx`. Returns None if no such write exists.
    ///
    /// Mirrors the inner loop of viewer/taint.py:282-299 for one byte:
    /// fetch `bytes.get(addr+o)`, find the partition point where ev.idx
    /// crosses `before_idx`, then walk back to the first write.
    ///
    /// "kind" semantics: "w" = store, "x" = external/JNI write.
    /// "r" events are skipped — only writes count for taint.
    pub fn latest_write_idx_strict_before(
        &self,
        byte_addr: u64,
        before_idx: usize,
    ) -> Option<usize> {
        let evs = self.bytes.get(&byte_addr)?;
        // partition_point: first index where ev.idx >= before_idx
        let pos = evs.partition_point(|ev| ev.idx < before_idx);
        for j in (0..pos).rev() {
            let ev = &evs[j];
            if ev.kind == "w" || ev.kind == "x" {
                return Some(ev.idx);
            }
        }
        None
    }

    /// Scan known bytes (latest event at each addr) for printable-ASCII runs
    /// of length ≥ `min_len`. Gap-aware: a non-contiguous addr cuts the run.
    /// Returns `(start_addr, ascii_string)` pairs.
    pub fn find_strings(&self, min_len: usize) -> Vec<(u64, String)> {
        if self.bytes.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut run_start: Option<u64> = None;
        let mut run_chars: Vec<u8> = Vec::new();
        let mut prev_addr: Option<u64> = None;
        for (&a, evs) in &self.bytes {
            if let Some(prev) = prev_addr {
                if a != prev + 1 {
                    flush_run(&mut out, &mut run_start, &mut run_chars, min_len);
                }
            }
            let byte = evs.last().map(|e| e.byte).unwrap_or(0);
            if (32..127).contains(&byte) {
                if run_start.is_none() {
                    run_start = Some(a);
                }
                run_chars.push(byte);
            } else {
                flush_run(&mut out, &mut run_start, &mut run_chars, min_len);
            }
            prev_addr = Some(a);
        }
        flush_run(&mut out, &mut run_start, &mut run_chars, min_len);
        out
    }

    /// Render `rows` × `cols` bytes starting at `base` as pwndbg-style hex+
    /// ASCII lines, using `byte_at(addr, t)` for each cell. Bytes never
    /// observed appear as `??` and `.` in the ASCII column.
    pub fn hex_dump(&self, base: u64, t: u64, rows: usize, cols: usize) -> Vec<String> {
        let mut out = Vec::with_capacity(rows);
        for r in 0..rows {
            let row_addr = base + (r * cols) as u64;
            let mut byte_strs: Vec<String> = Vec::with_capacity(cols);
            let mut ascii_strs = String::with_capacity(cols);
            for c in 0..cols {
                let a = row_addr + c as u64;
                let (b, _kind, _) = self.byte_at(a, t);
                match b {
                    Some(v) => {
                        byte_strs.push(format!("{v:02x}"));
                        ascii_strs.push(if (32..127).contains(&v) {
                            v as char
                        } else {
                            '.'
                        });
                    }
                    None => {
                        byte_strs.push("??".to_string());
                        ascii_strs.push('.');
                    }
                }
            }
            let half = cols / 2;
            let line = format!(
                "{row_addr:016x}  {}  {}  |{ascii_strs}|",
                byte_strs[..half].join(" "),
                byte_strs[half..].join(" "),
            );
            out.push(line);
        }
        out
    }
}

/// Flush a pending printable-ASCII run into `out` if it meets `min_len`,
/// then reset the run state. Always resets, even if the run was too short.
fn flush_run(
    out: &mut Vec<(u64, String)>,
    run_start: &mut Option<u64>,
    run_chars: &mut Vec<u8>,
    min_len: usize,
) {
    if let Some(start) = *run_start {
        if run_chars.len() >= min_len {
            out.push((start, String::from_utf8_lossy(run_chars).into_owned()));
        }
    }
    *run_start = None;
    run_chars.clear();
}

/// Splat the LE bytes of `value` (size `size` bytes) into the per-addr event
/// map starting at `addr`.
fn splat_bytes(
    bytes: &mut BTreeMap<u64, Vec<ByteEvent>>,
    addr: u64,
    size: u32,
    value: u64,
    idx: usize,
    kind: &'static str,
) {
    for o in 0..size as u64 {
        let b = ((value >> (o * 8)) & 0xff) as u8;
        bytes
            .entry(addr + o)
            .or_default()
            .push(ByteEvent { idx, byte: b, kind });
    }
}

/// Pick the source register that supplied a store's bytes, taken from the
/// storing record's pre-state. For stp/ldp pair-split entries, capstone fills
/// `op.src_reg` directly; otherwise fall back to the first non-base/non-idx
/// reg in `regs_use`.
fn value_of_write(trace: &Trace, i: usize, op: &MemOp, decoded: &DecodedInsn) -> Option<u64> {
    let src = if !op.src_reg.is_empty() {
        op.src_reg.clone()
    } else {
        decoded
            .regs_use
            .iter()
            .find(|r| **r != op.base && **r != op.idx)
            .cloned()?
    };
    let rec = trace.record(i);
    rec.reg_by_name(&src)
}

/// Pick the dest register that received a load's bytes, taken from the NEXT
/// record's post-state. For ldp pair-split entries, capstone fills
/// `op.src_reg`; otherwise fall back to `regs_def[0]`.
fn value_of_read(trace: &Trace, i: usize, op: &MemOp, decoded: &DecodedInsn) -> Option<u64> {
    if i + 1 >= trace.len() {
        return None;
    }
    let dest = if !op.src_reg.is_empty() {
        op.src_reg.clone()
    } else {
        decoded.regs_def.first().cloned()?
    };
    trace.record(i + 1).reg_by_name(&dest)
}
