//! Sparse byte-level memory shadow built from a trace.
//!
//! Direct port of `viewer/memshadow.py:58-339`, with a Rust-native v3 binary
//! sidecar for fast reloads on large traces.
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
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::thread;

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

const SIDECAR_MAGIC: &[u8; 8] = b"TMMSV3\0\0";
const SIDECAR_VERSION: u32 = 3;
pub const SIDECAR_SUFFIX: &str = ".memshadow.v3.bin";
const PARALLEL_MIN_RECORDS: usize = 250_000;
const MIN_CHUNK_RECORDS: usize = 200_000;

/// Sparse byte-level memory shadow over a trace.
///
/// Built once from a [`Trace`]; immutable thereafter. Lookup APIs are
/// `byte_at` (point query), `hex_dump` (rectangular region), and
/// `find_strings` (printable-ASCII run scan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemShadow {
    pub writes: Vec<MemRec>,
    pub reads: Vec<MemRec>,
    pub bytes: BTreeMap<u64, Vec<ByteEvent>>,
}

impl MemShadow {
    /// Sidecar path for this trace: `<call_dir>/trace.bin.memshadow.v3.bin`.
    pub fn sidecar_path(trace: &Trace) -> PathBuf {
        trace.call_dir().join(format!("trace.bin{SIDECAR_SUFFIX}"))
    }

    /// Load from a valid v3 sidecar when possible; otherwise cold-build and
    /// best-effort save. Corrupt/stale sidecars are ignored.
    pub fn load_or_build(trace: &Trace) -> Self {
        if let Some(mem) = Self::try_load_sidecar(trace) {
            return mem;
        }
        let mem = Self::build_from_trace(trace);
        let _ = mem.save_sidecar(trace);
        mem
    }

    /// Walk every record once; for each store, record the source-reg pre-state
    /// bytes; for each load, record the dest-reg post-state (next record's
    /// value) bytes. Mirrors `viewer/memshadow.py:74-110` minus the sidecar
    /// load/save and the external_writes.bin handling.
    pub fn build_from_trace(trace: &Trace) -> Self {
        let n = trace.len();
        let workers = memshadow_worker_count(n);
        if workers <= 1 {
            return build_range(trace, 0, n);
        }
        tracing::info!(
            target: "tracemiku-core",
            records = n,
            workers,
            "building MemShadow in parallel"
        );

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
                .map(|handle| handle.join().expect("memshadow worker panicked"))
                .collect::<Vec<_>>()
        });

        merge_partials(partials)
    }

    /// Try to load `<call_dir>/trace.bin.memshadow.v3.bin`.
    ///
    /// Returns `None` for miss, stale trace size, schema mismatch, or corrupt
    /// content. Callers that want a ready MemShadow should use
    /// [`MemShadow::load_or_build`].
    pub fn try_load_sidecar(trace: &Trace) -> Option<Self> {
        Self::read_sidecar(trace).ok()
    }

    /// Save this shadow as v3 binary sidecar. Writes to a temp file in the
    /// call directory and then atomically renames it over the final path.
    pub fn save_sidecar(&self, trace: &Trace) -> std::io::Result<()> {
        let path = Self::sidecar_path(trace);
        let tmp_name = format!(
            "{}.tmp.{}",
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("trace.bin.memshadow.v3.bin"),
            std::process::id()
        );
        let tmp_path = path.with_file_name(tmp_name);
        let write_result = (|| {
            let raw = std::fs::File::create(&tmp_path)?;
            let mut f = BufWriter::with_capacity(1024 * 1024, raw);
            f.write_all(SIDECAR_MAGIC)?;
            write_u32(&mut f, SIDECAR_VERSION)?;
            write_u64(&mut f, trace.raw().len() as u64)?;
            write_u64(&mut f, self.writes.len() as u64)?;
            write_u64(&mut f, self.reads.len() as u64)?;
            write_u64(&mut f, self.bytes.len() as u64)?;

            for rec in &self.writes {
                write_memrec(&mut f, rec)?;
            }
            for rec in &self.reads {
                write_memrec(&mut f, rec)?;
            }
            for (addr, evs) in &self.bytes {
                write_u64(&mut f, *addr)?;
                write_u64(&mut f, evs.len() as u64)?;
                for ev in evs {
                    write_u64(&mut f, ev.idx as u64)?;
                    f.write_all(&[ev.byte, kind_to_code(ev.kind)?])?;
                }
            }
            f.flush()?;
            f.get_ref().sync_all()?;
            std::fs::rename(&tmp_path, &path)
        })();
        if write_result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        write_result
    }

    fn read_sidecar(trace: &Trace) -> std::io::Result<Self> {
        let path = Self::sidecar_path(trace);
        let raw = std::fs::File::open(path)?;
        let mut f = BufReader::with_capacity(1024 * 1024, raw);
        let mut magic = [0u8; 8];
        f.read_exact(&mut magic)?;
        if &magic != SIDECAR_MAGIC {
            return Err(invalid_data("bad memshadow sidecar magic"));
        }
        let version = read_u32(&mut f)?;
        if version != SIDECAR_VERSION {
            return Err(invalid_data("bad memshadow sidecar version"));
        }
        let trace_size = read_u64(&mut f)?;
        if trace_size != trace.raw().len() as u64 {
            return Err(invalid_data("stale memshadow sidecar trace size"));
        }
        let writes_len = read_len(&mut f)?;
        let reads_len = read_len(&mut f)?;
        let addr_len = read_len(&mut f)?;

        let mut writes = Vec::with_capacity(writes_len);
        for _ in 0..writes_len {
            writes.push(read_memrec(&mut f)?);
        }
        let mut reads = Vec::with_capacity(reads_len);
        for _ in 0..reads_len {
            reads.push(read_memrec(&mut f)?);
        }
        let mut bytes = BTreeMap::new();
        for _ in 0..addr_len {
            let addr = read_u64(&mut f)?;
            let event_len = read_len(&mut f)?;
            let mut evs = Vec::with_capacity(event_len);
            for _ in 0..event_len {
                let idx = read_usize_u64(&mut f)?;
                let mut bb = [0u8; 2];
                f.read_exact(&mut bb)?;
                let kind = code_to_kind(bb[1])?;
                evs.push(ByteEvent {
                    idx,
                    byte: bb[0],
                    kind,
                });
            }
            evs.sort_by_key(|ev| ev.idx);
            bytes.insert(addr, evs);
        }
        Ok(Self {
            writes,
            reads,
            bytes,
        })
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

fn memshadow_worker_count(n: usize) -> usize {
    let requested = std::env::var("TRACEMIKU_MEMSHADOW_THREADS")
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

fn build_range(trace: &Trace, start: usize, end: usize) -> MemShadow {
    let mut writes: Vec<MemRec> = Vec::new();
    let mut reads: Vec<MemRec> = Vec::new();
    let mut bytes: BTreeMap<u64, Vec<ByteEvent>> = BTreeMap::new();
    for i in start..end {
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
    MemShadow {
        writes,
        reads,
        bytes,
    }
}

fn merge_partials(partials: Vec<MemShadow>) -> MemShadow {
    let mut out = MemShadow {
        writes: Vec::new(),
        reads: Vec::new(),
        bytes: BTreeMap::new(),
    };
    for mut partial in partials {
        out.writes.append(&mut partial.writes);
        out.reads.append(&mut partial.reads);
        for (addr, mut events) in partial.bytes {
            out.bytes.entry(addr).or_default().append(&mut events);
        }
    }
    out
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

fn write_memrec(w: &mut impl Write, rec: &MemRec) -> std::io::Result<()> {
    write_u64(w, rec.idx as u64)?;
    write_u64(w, rec.addr)?;
    write_u32(w, rec.size)?;
    write_u64(w, rec.value)
}

fn read_memrec(r: &mut impl Read) -> std::io::Result<MemRec> {
    Ok(MemRec {
        idx: read_usize_u64(r)?,
        addr: read_u64(r)?,
        size: read_u32(r)?,
        value: read_u64(r)?,
    })
}

fn write_u32(w: &mut impl Write, v: u32) -> std::io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn write_u64(w: &mut impl Write, v: u64) -> std::io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn read_u32(r: &mut impl Read) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64(r: &mut impl Read) -> std::io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn read_len(r: &mut impl Read) -> std::io::Result<usize> {
    read_usize_u64(r)
}

fn read_usize_u64(r: &mut impl Read) -> std::io::Result<usize> {
    let v = read_u64(r)?;
    usize::try_from(v).map_err(|_| invalid_data("memshadow sidecar usize overflow"))
}

fn kind_to_code(kind: &str) -> std::io::Result<u8> {
    match kind {
        "r" => Ok(0),
        "w" => Ok(1),
        "x" => Ok(2),
        _ => Err(invalid_data("bad memshadow event kind")),
    }
}

fn code_to_kind(code: u8) -> std::io::Result<&'static str> {
    match code {
        0 => Ok("r"),
        1 => Ok("w"),
        2 => Ok("x"),
        _ => Err(invalid_data("bad memshadow event kind code")),
    }
}

fn invalid_data(msg: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_partials_keeps_trace_order_for_same_address() {
        let partial_a = MemShadow {
            writes: vec![MemRec {
                idx: 1,
                addr: 0x7000,
                size: 1,
                value: 0x41,
            }],
            reads: Vec::new(),
            bytes: BTreeMap::from([(
                0x7000,
                vec![ByteEvent {
                    idx: 1,
                    byte: 0x41,
                    kind: "w",
                }],
            )]),
        };
        let partial_b = MemShadow {
            writes: vec![MemRec {
                idx: 3,
                addr: 0x7000,
                size: 1,
                value: 0x42,
            }],
            reads: Vec::new(),
            bytes: BTreeMap::from([(
                0x7000,
                vec![ByteEvent {
                    idx: 3,
                    byte: 0x42,
                    kind: "w",
                }],
            )]),
        };

        let merged = merge_partials(vec![partial_a, partial_b]);

        assert_eq!(
            merged
                .bytes
                .get(&0x7000)
                .unwrap()
                .iter()
                .map(|ev| ev.idx)
                .collect::<Vec<_>>(),
            vec![1, 3]
        );
        assert_eq!(
            merged.writes.iter().map(|rec| rec.idx).collect::<Vec<_>>(),
            vec![1, 3]
        );
    }
}
