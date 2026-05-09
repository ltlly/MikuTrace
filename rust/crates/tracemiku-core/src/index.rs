//! Per-register def-use indices over a Trace. Used by taint and the
//! `last-write-of-reg` family of endpoints.
//!
//! M2-ζ: also populates `mem_writes` / `mem_reads` / memory addr indexes
//! in the same single trace-walk that drives the reg side. Mirrors
//! `viewer/index.py:41-54`.

use std::collections::HashMap;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::thread;

use crate::disasm::classify::is_conditional_branch_mnem;
use crate::disasm::{addr_of, decode};
use crate::parallel;
use crate::trace::Trace;

const PARALLEL_MIN_RECORDS: usize = 250_000;
const MIN_CHUNK_RECORDS: usize = 200_000;
const SIDECAR_MAGIC: &[u8; 8] = b"TMIDX2\0\0";
const SIDECAR_VERSION: u32 = 2;
pub const SIDECAR_SUFFIX: &str = ".analysis-index.v2.bin";

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
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Index {
    /// `reg_defs[r]` = sorted record indices that WRITE to `r`.
    pub reg_defs: HashMap<String, Vec<usize>>,
    /// `reg_uses[r]` = sorted record indices that READ from `r`.
    pub reg_uses: HashMap<String, Vec<usize>>,
    /// All memory-write entries in trace order.
    pub mem_writes: Vec<MemRec>,
    /// All memory-read entries in trace order.
    pub mem_reads: Vec<MemRec>,
    /// `pc → sorted record indices`. Used by hot UI navigation paths such as
    /// CFG/HLIL clicks, hash deep-links, and Trace-for-PC.
    pub pc_to_idxs: HashMap<u64, Vec<usize>>,
    /// `addr → trace indices of writes whose byte range covers addr`. Fast
    /// "who wrote here?" lookup for backward taint and the
    /// `last-write-of-addr` endpoint family.
    pub mem_addr_to_writes: HashMap<u64, Vec<usize>>,
    /// `addr → trace indices of reads whose byte range covers addr`. Used by
    /// forward taint to jump to the next memory touch without scanning every
    /// memory op in large traces.
    pub mem_addr_to_reads: HashMap<u64, Vec<usize>>,
    /// Sorted record indices of conditional branches. Used by backward taint
    /// to expose optional control dependencies without a full dependency graph.
    pub cond_branches: Vec<usize>,
    /// Sorted record indices of calls and returns. Control dependencies are
    /// intentionally not attributed across these boundaries.
    pub call_ret_boundaries: Vec<usize>,
}

impl Index {
    /// Sidecar path for this trace: `<call_dir>/trace.bin.analysis-index.v2.bin`.
    pub fn sidecar_path(trace: &Trace) -> PathBuf {
        trace.call_dir().join(format!("trace.bin{SIDECAR_SUFFIX}"))
    }

    /// Load a valid persisted index when possible, otherwise build it and
    /// best-effort save it. Corrupt, stale, or older-version sidecars are
    /// ignored so callers can treat this as a drop-in replacement for
    /// [`Index::build`].
    pub fn load_or_build(trace: &Trace) -> Self {
        if let Some(index) = Self::try_load_sidecar(trace) {
            return index;
        }
        let index = Self::build(trace);
        let _ = index.save_sidecar(trace);
        index
    }

    /// Try to load the index sidecar. Returns `None` for miss, stale trace
    /// size, schema mismatch, or corrupt content.
    pub fn try_load_sidecar(trace: &Trace) -> Option<Self> {
        Self::read_sidecar(trace).ok()
    }

    /// Save this index as a compact binary sidecar. Writes to a temp file in
    /// the call directory and atomically renames it over the final path.
    pub fn save_sidecar(&self, trace: &Trace) -> std::io::Result<()> {
        let path = Self::sidecar_path(trace);
        let tmp_name = format!(
            "{}.tmp.{}",
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("trace.bin.analysis-index.v2.bin"),
            std::process::id()
        );
        let tmp_path = path.with_file_name(tmp_name);
        let write_result = (|| {
            let raw = std::fs::File::create(&tmp_path)?;
            let mut f = BufWriter::with_capacity(1024 * 1024, raw);
            f.write_all(SIDECAR_MAGIC)?;
            write_u32(&mut f, SIDECAR_VERSION)?;
            write_u64(&mut f, trace.raw().len() as u64)?;
            write_u64(&mut f, trace_fingerprint(trace))?;
            write_string_vec_map(&mut f, &self.reg_defs)?;
            write_string_vec_map(&mut f, &self.reg_uses)?;
            write_memrec_vec(&mut f, &self.mem_writes)?;
            write_memrec_vec(&mut f, &self.mem_reads)?;
            write_u64_vec_map(&mut f, &self.pc_to_idxs)?;
            write_u64_vec_map(&mut f, &self.mem_addr_to_writes)?;
            write_u64_vec_map(&mut f, &self.mem_addr_to_reads)?;
            write_usize_vec(&mut f, &self.cond_branches)?;
            write_usize_vec(&mut f, &self.call_ret_boundaries)?;
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
            return Err(invalid_data("bad index sidecar magic"));
        }
        let version = read_u32(&mut f)?;
        if version != SIDECAR_VERSION {
            return Err(invalid_data("bad index sidecar version"));
        }
        let trace_size = read_u64(&mut f)?;
        if trace_size != trace.raw().len() as u64 {
            return Err(invalid_data("stale index sidecar trace size"));
        }
        let fingerprint = read_u64(&mut f)?;
        if fingerprint != trace_fingerprint(trace) {
            return Err(invalid_data("stale index sidecar trace fingerprint"));
        }
        let index = Self {
            reg_defs: read_string_vec_map(&mut f)?,
            reg_uses: read_string_vec_map(&mut f)?,
            mem_writes: read_memrec_vec(&mut f)?,
            mem_reads: read_memrec_vec(&mut f)?,
            pc_to_idxs: read_u64_vec_map(&mut f)?,
            mem_addr_to_writes: read_u64_vec_map(&mut f)?,
            mem_addr_to_reads: read_u64_vec_map(&mut f)?,
            cond_branches: read_usize_vec(&mut f)?,
            call_ret_boundaries: read_usize_vec(&mut f)?,
        };
        Ok(index)
    }

    /// Walk every record in `trace`, decode the instruction, and accumulate
    /// def/use entries by register name plus memory-op entries by addr.
    /// Large traces are split across worker threads; each worker builds a
    /// local index over a contiguous record range, then the main thread merges
    /// chunks in range order so all `Vec<idx>` outputs stay sorted.
    pub fn build(trace: &Trace) -> Self {
        let n = trace.len();
        let workers = index_worker_count(n);
        if workers <= 1 {
            return build_range(trace, 0, n);
        }

        tracing::info!(
            target: "tracemiku-core",
            records = n,
            workers,
            "building trace index in parallel"
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
                .map(|handle| handle.join().expect("index worker panicked"))
                .collect::<Vec<_>>()
        });

        merge_partials(partials)
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

/// Planned worker count for [`Index::build`] at `n` records.
pub fn index_worker_count(n: usize) -> usize {
    parallel::worker_count(
        n,
        "TRACEMIKU_INDEX_THREADS",
        PARALLEL_MIN_RECORDS,
        MIN_CHUNK_RECORDS,
    )
}

fn build_range(trace: &Trace, start: usize, end: usize) -> Index {
    let mut idx = Index::default();
    for i in start..end {
        let pc = trace.pc(i);
        idx.pc_to_idxs.entry(pc).or_default().push(i);
        let inst = trace.inst(i);
        let d = decode(pc, inst);
        if is_conditional_branch_mnem(&d.mnemonic) {
            idx.cond_branches.push(i);
        }
        if d.is_call || d.is_ret {
            idx.call_ret_boundaries.push(i);
        }
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
                    idx.mem_writes.push(mr);
                    push_mem_addr_idx(&mut idx.mem_addr_to_writes, addr, op.size, i);
                } else {
                    idx.mem_reads.push(mr);
                    push_mem_addr_idx(&mut idx.mem_addr_to_reads, addr, op.size, i);
                }
            }
        }
    }
    idx
}

fn merge_partials(partials: Vec<Index>) -> Index {
    let mut out = Index::default();
    for partial in partials {
        for (reg, mut values) in partial.reg_defs {
            out.reg_defs.entry(reg).or_default().append(&mut values);
        }
        for (reg, mut values) in partial.reg_uses {
            out.reg_uses.entry(reg).or_default().append(&mut values);
        }
        out.mem_writes.extend(partial.mem_writes);
        out.mem_reads.extend(partial.mem_reads);
        out.cond_branches.extend(partial.cond_branches);
        out.call_ret_boundaries.extend(partial.call_ret_boundaries);
        for (pc, mut values) in partial.pc_to_idxs {
            out.pc_to_idxs.entry(pc).or_default().append(&mut values);
        }
        for (addr, mut values) in partial.mem_addr_to_writes {
            out.mem_addr_to_writes
                .entry(addr)
                .or_default()
                .append(&mut values);
        }
        for (addr, mut values) in partial.mem_addr_to_reads {
            out.mem_addr_to_reads
                .entry(addr)
                .or_default()
                .append(&mut values);
        }
    }
    debug_assert!(out.cond_branches.windows(2).all(|w| w[0] < w[1]));
    debug_assert!(out.call_ret_boundaries.windows(2).all(|w| w[0] < w[1]));
    out
}

fn push_mem_addr_idx(map: &mut HashMap<u64, Vec<usize>>, addr: u64, size: u32, idx: usize) {
    for offset in 0..size as u64 {
        map.entry(addr.saturating_add(offset))
            .or_default()
            .push(idx);
    }
}

fn trace_fingerprint(trace: &Trace) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    const SAMPLE: usize = 4096;

    fn mix(mut h: u64, bytes: &[u8]) -> u64 {
        for byte in bytes {
            h ^= u64::from(*byte);
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }

    fn mix_u64(h: u64, value: u64) -> u64 {
        mix(h, &value.to_le_bytes())
    }

    let raw = trace.raw();
    let len = raw.len();
    let mut h = mix_u64(FNV_OFFSET, len as u64);
    if len == 0 {
        return h;
    }

    let mid = len.saturating_sub(SAMPLE) / 2;
    let ranges = [
        (0usize, len.min(SAMPLE)),
        (mid, (mid + SAMPLE).min(len)),
        (len.saturating_sub(SAMPLE), len),
    ];
    for (start, end) in ranges {
        h = mix_u64(h, start as u64);
        h = mix(h, &raw[start..end]);
    }
    h
}

fn write_string_vec_map(
    w: &mut impl Write,
    map: &HashMap<String, Vec<usize>>,
) -> std::io::Result<()> {
    write_u64(w, map.len() as u64)?;
    for (key, values) in map {
        write_string(w, key)?;
        write_usize_vec(w, values)?;
    }
    Ok(())
}

fn read_string_vec_map(r: &mut impl Read) -> std::io::Result<HashMap<String, Vec<usize>>> {
    let len = read_len(r)?;
    let mut map = HashMap::with_capacity(len);
    for _ in 0..len {
        let key = read_string(r)?;
        let values = read_usize_vec(r)?;
        map.insert(key, values);
    }
    Ok(map)
}

fn write_u64_vec_map(w: &mut impl Write, map: &HashMap<u64, Vec<usize>>) -> std::io::Result<()> {
    write_u64(w, map.len() as u64)?;
    for (key, values) in map {
        write_u64(w, *key)?;
        write_usize_vec(w, values)?;
    }
    Ok(())
}

fn read_u64_vec_map(r: &mut impl Read) -> std::io::Result<HashMap<u64, Vec<usize>>> {
    let len = read_len(r)?;
    let mut map = HashMap::with_capacity(len);
    for _ in 0..len {
        let key = read_u64(r)?;
        let values = read_usize_vec(r)?;
        map.insert(key, values);
    }
    Ok(map)
}

fn write_memrec_vec(w: &mut impl Write, recs: &[MemRec]) -> std::io::Result<()> {
    write_u64(w, recs.len() as u64)?;
    for rec in recs {
        write_u64(w, rec.idx as u64)?;
        write_u64(w, rec.addr)?;
        write_u32(w, rec.size)?;
        match rec.value {
            Some(value) => {
                w.write_all(&[1])?;
                write_u64(w, value)?;
            }
            None => w.write_all(&[0])?,
        }
    }
    Ok(())
}

fn read_memrec_vec(r: &mut impl Read) -> std::io::Result<Vec<MemRec>> {
    let len = read_len(r)?;
    let mut recs = Vec::with_capacity(len);
    for _ in 0..len {
        let idx = read_usize_u64(r)?;
        let addr = read_u64(r)?;
        let size = read_u32(r)?;
        let mut tag = [0u8; 1];
        r.read_exact(&mut tag)?;
        let value = match tag[0] {
            0 => None,
            1 => Some(read_u64(r)?),
            _ => return Err(invalid_data("bad index sidecar option tag")),
        };
        recs.push(MemRec {
            idx,
            addr,
            size,
            value,
        });
    }
    Ok(recs)
}

fn write_usize_vec(w: &mut impl Write, values: &[usize]) -> std::io::Result<()> {
    write_u64(w, values.len() as u64)?;
    for value in values {
        write_u64(w, *value as u64)?;
    }
    Ok(())
}

fn read_usize_vec(r: &mut impl Read) -> std::io::Result<Vec<usize>> {
    let len = read_len(r)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(read_usize_u64(r)?);
    }
    Ok(values)
}

fn write_string(w: &mut impl Write, s: &str) -> std::io::Result<()> {
    write_u64(w, s.len() as u64)?;
    w.write_all(s.as_bytes())
}

fn read_string(r: &mut impl Read) -> std::io::Result<String> {
    const MAX_STRING_BYTES: usize = 4096;
    let len = read_len(r)?;
    if len > MAX_STRING_BYTES {
        return Err(invalid_data("index sidecar string too large"));
    }
    let mut bytes = vec![0u8; len];
    r.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| invalid_data("index sidecar string is not utf-8"))
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
    usize::try_from(v).map_err(|_| invalid_data("index sidecar usize overflow"))
}

fn invalid_data(msg: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}
