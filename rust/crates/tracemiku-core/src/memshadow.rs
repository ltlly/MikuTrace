//! Sparse byte-level memory shadow built from a trace.
//!
//! Direct port of `viewer/memshadow.py:58-339`, with a Rust-native v7 binary
//! sidecar (`TMMSV8`) with fixed-layout sections for mmap reloads on large traces.
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

#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use crate::disasm::{addr_of, decode, DecodedInsn, MemOp};
pub use crate::memshadow_store::{
    ByteEvent, ByteEventKind, ByteEvents, CopySources, EventList, MemRec, MemRecords,
};
use crate::sidecar_io::{invalid_data, write_atomic, write_u32, write_u64};
use crate::trace::Trace;
use memmap2::Mmap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnloggedWriteGap {
    pub prev_write_idx: Option<usize>,
    pub prev_write_byte: Option<u8>,
    pub first_observing_read_idx: usize,
    pub observed_byte: u8,
}

/// Errors surfaced when MemShadow is not ready to serve a query.
///
/// Replaces the previous `Result<&MemShadow, &'static str>` so callers get
/// exhaustiveness checking while the wire `status` string stays stable
/// (contract test `memshadow_error_contract_tests`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemShadowError {
    /// Shadow is still being built (previous wire value "loading").
    Building,
    /// Shadow build failed or is otherwise unavailable (wire value "error").
    Failed,
}

impl MemShadowError {
    /// Stable wire string used in route response `status` fields.
    pub fn status_str(&self) -> &'static str {
        match self {
            MemShadowError::Building => "loading",
            MemShadowError::Failed => "error",
        }
    }
}

impl std::fmt::Display for MemShadowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.status_str())
    }
}

impl std::error::Error for MemShadowError {}

/// One memory-side index entry where the source/dest register WAS observable.
///
/// Note: this collides with [`crate::index::MemRec`]. The prelude re-exports
/// this one as `ShadowMemRec` to disambiguate. The `index::MemRec` has an
/// `Option<u64>` value; this one's value is always known.
const SIDECAR_MAGIC: &[u8; 8] = b"TMMSV8\0\0";
const SIDECAR_VERSION: u32 = 8;
const SIDECAR_HEADER_SIZE: usize = 136;
const MEMREC_DISK_SIZE: usize = 32;
const ADDRESS_DISK_SIZE: usize = 24;
const EVENT_DISK_SIZE: usize = 8;
const COPY_DISK_SIZE: usize = 24;
pub const SIDECAR_SUFFIX: &str = ".memshadow.v8.bin";
const EXTERNAL_WRITES_FILE: &str = "external_writes.bin";
const EXTERNAL_WRITE_RECORD_SIZE: usize = 17;
const PARALLEL_MIN_RECORDS: usize = 250_000;
const MIN_CHUNK_RECORDS: usize = 200_000;

/// Initial-memory-snapshot sidecar (captured on-device at trace start).
const SNAPSHOT_FILE: &str = "memory_snapshot.bin";
const SNAPSHOT_MAGIC: &[u8; 8] = b"TMSNAP\0\0";

/// One contiguous region of real device memory captured at trace start (t=0).
/// Kept as a compact sorted blob rather than splatted per-byte into the event
/// map, so a multi-hundred-MB snapshot stays cheap. See
/// `docs/memory-completeness-design.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapRegion {
    pub base: u64,
    pub perms: u32,
    pub data: Vec<u8>,
}

/// Initial memory snapshot: the baseline `i` layer of the byte oracle. Provides
/// real bytes for any address that was initialized before the trace window
/// (pre-trace `.rodata` constants, decrypted runtime tables, etc.) and is never
/// overwritten by a traced store. Regions are sorted by `base` for binary
/// search.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemSnapshot {
    /// Sorted by `base`, non-overlapping.
    pub regions: Vec<SnapRegion>,
}

impl MemSnapshot {
    /// Parse a `memory_snapshot.bin` blob. Returns `None` on bad magic, short
    /// header, or truncated region data (best-effort: a corrupt tail is dropped
    /// but already-parsed regions are kept).
    pub fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < 16 || &raw[0..8] != SNAPSHOT_MAGIC {
            return None;
        }
        let version = u32::from_le_bytes(raw[8..12].try_into().ok()?);
        if version != 1 {
            return None;
        }
        let count = u32::from_le_bytes(raw[12..16].try_into().ok()?) as usize;
        if count > (raw.len() - 16) / 24 {
            return None;
        }
        let mut regions = Vec::with_capacity(count);
        let mut off = 16usize;
        for _ in 0..count {
            // base u64, size u64, perms u32, flags u32 = 24-byte region header
            if off + 24 > raw.len() {
                break;
            }
            let base = u64::from_le_bytes(raw[off..off + 8].try_into().ok()?);
            let size = u64::from_le_bytes(raw[off + 8..off + 16].try_into().ok()?) as usize;
            let perms = u32::from_le_bytes(raw[off + 16..off + 20].try_into().ok()?);
            off += 24;
            if size > raw.len().saturating_sub(off) || base.checked_add(size as u64).is_none() {
                break;
            }
            regions.push(SnapRegion {
                base,
                perms,
                data: raw[off..off + size].to_vec(),
            });
            off += size;
        }
        if regions.is_empty() {
            return None;
        }
        regions.sort_by_key(|r| r.base);
        Some(MemSnapshot { regions })
    }

    /// Load `<call_dir>/memory_snapshot.bin` if present and valid.
    pub fn load(trace: &Trace) -> Option<Self> {
        let file = std::fs::File::open(trace.call_dir().join(SNAPSHOT_FILE)).ok()?;
        // SAFETY: the snapshot is immutable for this read; parsing copies only
        // validated regions and does not retain a second whole-file heap blob.
        let raw = unsafe { Mmap::map(&file) }.ok()?;
        Self::parse(&raw)
    }

    /// Return the captured byte at `addr`, or `None` if no region covers it.
    pub fn byte_at(&self, addr: u64) -> Option<u8> {
        // Binary search for the region whose base <= addr.
        let pos = self.regions.partition_point(|r| r.base <= addr);
        if pos == 0 {
            return None;
        }
        let r = &self.regions[pos - 1];
        let off = addr.checked_sub(r.base)? as usize;
        r.data.get(off).copied()
    }

    /// Total captured bytes across all regions.
    pub fn total_bytes(&self) -> usize {
        self.regions.iter().map(|r| r.data.len()).sum()
    }
}

/// Sparse byte-level memory shadow over a trace.
///
/// Built once from a [`Trace`]; immutable thereafter. Lookup APIs are
/// `byte_at` (point query), `hex_dump` (rectangular region), and
/// `find_strings` (printable-ASCII run scan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemShadow {
    pub writes: MemRecords,
    pub reads: MemRecords,
    pub bytes: ByteEvents,
    /// Mapping `(dst_addr, write_idx) -> src_addr` for uninstrumented external
    /// memory copy boundaries (`memcpy` / `memmove`).
    pub copy_sources: CopySources,
    /// Initial-memory-snapshot fallback layer (kind `i`). `None` when no
    /// `memory_snapshot.bin` was captured for this trace.
    pub snapshot: Option<MemSnapshot>,
}

impl MemShadow {
    /// Sidecar path for this trace: `<call_dir>/trace.bin.memshadow.v8.bin`.
    pub fn sidecar_path(trace: &Trace) -> PathBuf {
        trace.call_dir().join(format!("trace.bin{SIDECAR_SUFFIX}"))
    }

    /// Return the source byte address if `(addr, idx)` was synthesized from an
    /// uninstrumented `memcpy` / `memmove` call boundary.
    pub fn copy_source_at(&self, addr: u64, idx: usize) -> Option<u64> {
        self.copy_sources.get(&(addr, idx)).copied()
    }

    /// Load from a valid v8 sidecar when possible; otherwise cold-build and
    /// best-effort save. Corrupt/stale sidecars are ignored.
    pub fn load_or_build(trace: &Trace) -> Self {
        Self::load_or_build_with_budget(trace, usize::MAX)
            .expect("unbounded MemShadow build cannot exceed its budget")
    }

    pub fn load_sidecar_with_budget(
        trace: &Trace,
        budget_bytes: usize,
    ) -> Result<Option<Self>, crate::parallel::BuildLimit> {
        let Some(mut mem) = Self::try_load_sidecar(trace) else {
            return Ok(None);
        };
        mem.snapshot = load_snapshot_with_budget(trace, mem.estimated_heap_bytes(), budget_bytes)?;
        Ok(Some(mem))
    }

    pub fn load_or_build_with_budget(
        trace: &Trace,
        budget_bytes: usize,
    ) -> Result<Self, crate::parallel::BuildLimit> {
        if let Some(mem) = Self::load_sidecar_with_budget(trace, budget_bytes)? {
            return Ok(mem);
        }
        let before = memory_input_digest(trace).ok();
        let mut mem = Self::build_from_trace_with_budget(trace, budget_bytes)?;
        // A live append/change during reconstruction must not create a cache
        // that claims to represent the new inputs.
        if before.is_some() && before == memory_input_digest(trace).ok() {
            let _ = mem.save_sidecar(trace);
        }
        mem.snapshot = load_snapshot_with_budget(trace, mem.estimated_heap_bytes(), budget_bytes)?;
        Ok(mem)
    }

    /// Walk every record once; for each store, record the source-reg pre-state
    /// bytes; for each load, record the dest-reg post-state (next record's
    /// value) bytes. Also merges boundary-diff events from
    /// `<call_dir>/external_writes.bin` as kind `"x"` writes and reconstructs
    /// uninstrumented external `memcpy`/`memmove`/`memset` boundaries.
    pub fn build_from_trace(trace: &Trace) -> Self {
        Self::build_from_trace_with_budget(trace, usize::MAX)
            .expect("unbounded MemShadow build cannot exceed its budget")
    }

    pub fn build_from_trace_with_budget(
        trace: &Trace,
        budget_bytes: usize,
    ) -> Result<Self, crate::parallel::BuildLimit> {
        let n = trace.len();
        if n > u32::MAX as usize + 1 {
            return Err(crate::parallel::BuildLimit {
                component: "memshadow_record_index",
                estimated_bytes: n,
                budget_bytes: u32::MAX as usize + 1,
            });
        }
        let workers = memshadow_worker_count(n);
        let worker_budget = budget_bytes / workers.max(1) / 2;
        let mut mem = if workers <= 1 {
            build_range(trace, 0, n, worker_budget)?
        } else {
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
                    handles
                        .push(scope.spawn(move || build_range(trace, start, end, worker_budget)));
                }
                handles
                    .into_iter()
                    .map(|handle| handle.join().expect("memshadow worker panicked"))
                    .collect::<Vec<_>>()
            });
            let mut completed = Vec::with_capacity(partials.len());
            for partial in partials {
                completed.push(partial?);
            }
            merge_partials(completed)
        };
        let mut event_count = mem.bytes.event_count();
        mem.ensure_budget(budget_bytes)?;
        merge_worker_traces(trace, &mut mem, &mut event_count, budget_bytes)?;
        merge_external_writes(trace, &mut mem, &mut event_count, budget_bytes)?;
        let snap = load_snapshot_with_budget(trace, mem.estimated_heap_bytes(), budget_bytes)?;
        crate::memshadow_ext::merge_uninstrumented_mem_calls(trace, &mut mem, snap.as_ref());
        mem.ensure_budget(budget_bytes)?;
        let finalize_extra = mem
            .bytes
            .event_count()
            .saturating_mul(EVENT_DISK_SIZE)
            .saturating_add(mem.bytes.len().saturating_mul(ADDRESS_DISK_SIZE));
        crate::parallel::check_memory_budget(
            "memshadow",
            mem.estimated_heap_bytes().saturating_add(finalize_extra),
            budget_bytes,
        )?;
        mem.bytes.finalize();
        mem.copy_sources.finalize();
        mem.ensure_budget(budget_bytes)?;
        Ok(mem)
    }

    fn estimated_heap_bytes(&self) -> usize {
        self.writes
            .heap_bytes()
            .saturating_add(self.reads.heap_bytes())
            .saturating_add(self.bytes.estimated_heap_bytes())
            .saturating_add(self.copy_sources.heap_bytes())
            .saturating_add(self.snapshot.as_ref().map_or(0, MemSnapshot::total_bytes))
    }

    fn estimated_heap_bytes_with_event_count(&self, event_count: usize) -> usize {
        self.writes
            .heap_bytes()
            .saturating_add(self.reads.heap_bytes())
            .saturating_add(
                self.bytes
                    .estimated_heap_bytes_with_event_count(event_count),
            )
            .saturating_add(self.copy_sources.heap_bytes())
    }

    fn ensure_budget(&self, budget_bytes: usize) -> Result<(), crate::parallel::BuildLimit> {
        crate::parallel::check_memory_budget("memshadow", self.estimated_heap_bytes(), budget_bytes)
    }

    fn ensure_budget_with_event_count(
        &self,
        event_count: usize,
        budget_bytes: usize,
    ) -> Result<(), crate::parallel::BuildLimit> {
        crate::parallel::check_memory_budget(
            "memshadow",
            self.estimated_heap_bytes_with_event_count(event_count),
            budget_bytes,
        )
    }

    /// Try to load `<call_dir>/trace.bin.memshadow.v8.bin`.
    ///
    /// Returns `None` for miss, stale trace size, schema mismatch, or corrupt
    /// content. Callers that want a ready MemShadow should use
    /// [`MemShadow::load_or_build`].
    pub fn try_load_sidecar(trace: &Trace) -> Option<Self> {
        Self::read_sidecar(trace).ok()
    }

    /// Save this shadow as v8 fixed-layout binary sidecar. Writes to a temp file in the
    /// call directory and then atomically renames it over the final path.
    pub fn save_sidecar(&self, trace: &Trace) -> std::io::Result<()> {
        let (addresses, events) = self.bytes.finalized_parts().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "memshadow byte index must be finalized before saving",
            )
        })?;
        if !self.copy_sources.is_finalized() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "memshadow copy sources must be finalized before saving",
            ));
        }
        let writes_len = self.writes.len();
        let reads_len = self.reads.len();
        let addresses_len = addresses.len();
        let events_len = events.len();
        let copy_len = self.copy_sources.len();
        let writes_offset = SIDECAR_HEADER_SIZE;
        let reads_offset = section_end(writes_offset, writes_len, MEMREC_DISK_SIZE)?;
        let addresses_offset = section_end(reads_offset, reads_len, MEMREC_DISK_SIZE)?;
        let events_offset = section_end(addresses_offset, addresses_len, ADDRESS_DISK_SIZE)?;
        let copy_offset = section_end(events_offset, events_len, EVENT_DISK_SIZE)?;
        let _ = section_end(copy_offset, copy_len, COPY_DISK_SIZE)?;

        write_atomic(
            &Self::sidecar_path(trace),
            "trace.bin.memshadow.v8.bin",
            |f| {
                f.write_all(SIDECAR_MAGIC)?;
                write_u32(f, SIDECAR_VERSION)?;
                write_u32(f, SIDECAR_HEADER_SIZE as u32)?;
                write_u64(f, trace.raw().len() as u64)?;
                f.write_all(&memory_input_digest(trace)?)?;
                for len in [writes_len, reads_len, addresses_len, events_len, copy_len] {
                    write_u64(f, len as u64)?;
                }
                for offset in [
                    writes_offset,
                    reads_offset,
                    addresses_offset,
                    events_offset,
                    copy_offset,
                ] {
                    write_u64(f, offset as u64)?;
                }
                f.write_all(bytemuck::cast_slice(&self.writes[..]))?;
                f.write_all(bytemuck::cast_slice(&self.reads[..]))?;
                f.write_all(bytemuck::cast_slice(addresses))?;
                f.write_all(byte_events_as_bytes(events))?;
                for (dst, idx, src) in self.copy_sources.iter() {
                    write_u64(f, dst)?;
                    write_u64(f, idx as u64)?;
                    write_u64(f, src)?;
                }
                Ok(())
            },
        )
    }

    fn read_sidecar(trace: &Trace) -> std::io::Result<Self> {
        let path = Self::sidecar_path(trace);
        let raw = std::fs::File::open(path)?;
        let file_len = usize::try_from(raw.metadata()?.len())
            .map_err(|_| invalid_data("memshadow sidecar is too large for this host"))?;
        // SAFETY: the sidecar is mapped read-only and all sections are validated
        // before any typed slice is exposed.
        let mmap = unsafe { Mmap::map(&raw) }?;
        if file_len < SIDECAR_HEADER_SIZE || mmap.get(..8) != Some(SIDECAR_MAGIC) {
            return Err(invalid_data("bad memshadow sidecar magic"));
        }
        if u32_at(&mmap, 8)? != SIDECAR_VERSION {
            return Err(invalid_data("bad memshadow sidecar version"));
        }
        if u32_at(&mmap, 12)? as usize != SIDECAR_HEADER_SIZE {
            return Err(invalid_data("bad memshadow sidecar header size"));
        }
        if u64_at(&mmap, 16)? != trace.raw().len() as u64 {
            return Err(invalid_data("stale memshadow sidecar trace size"));
        }
        if mmap.get(24..56) != Some(memory_input_digest(trace)?.as_slice()) {
            return Err(invalid_data("stale memshadow sidecar inputs"));
        }
        let writes_len = read_sidecar_len(&mmap, 56, file_len, MEMREC_DISK_SIZE)?;
        let reads_len = read_sidecar_len(&mmap, 64, file_len, MEMREC_DISK_SIZE)?;
        let addresses_len = read_sidecar_len(&mmap, 72, file_len, ADDRESS_DISK_SIZE)?;
        let events_len = read_sidecar_len(&mmap, 80, file_len, EVENT_DISK_SIZE)?;
        let copy_len = read_sidecar_len(&mmap, 88, file_len, COPY_DISK_SIZE)?;
        let writes_offset = sidecar_usize(&mmap, 96)?;
        let reads_offset = sidecar_usize(&mmap, 104)?;
        let addresses_offset = sidecar_usize(&mmap, 112)?;
        let events_offset = sidecar_usize(&mmap, 120)?;
        let copy_offset = sidecar_usize(&mmap, 128)?;

        let expected_writes_end = section_end(writes_offset, writes_len, MEMREC_DISK_SIZE)?;
        let expected_reads_end = section_end(reads_offset, reads_len, MEMREC_DISK_SIZE)?;
        let expected_addresses_end =
            section_end(addresses_offset, addresses_len, ADDRESS_DISK_SIZE)?;
        let expected_events_end = section_end(events_offset, events_len, EVENT_DISK_SIZE)?;
        let expected_copy_end = section_end(copy_offset, copy_len, COPY_DISK_SIZE)?;
        if writes_offset != SIDECAR_HEADER_SIZE
            || reads_offset != expected_writes_end
            || addresses_offset != expected_reads_end
            || events_offset != expected_addresses_end
            || copy_offset != expected_events_end
            || expected_copy_end != file_len
        {
            return Err(invalid_data("inconsistent memshadow sidecar sections"));
        }

        let map = Arc::new(mmap);
        let n_records = trace.len();
        let writes = MemRecords::from_mapped(map.clone(), writes_offset, writes_len, n_records)?;
        let reads = MemRecords::from_mapped(map.clone(), reads_offset, reads_len, n_records)?;
        let bytes = ByteEvents::from_mapped(
            map.clone(),
            addresses_offset,
            addresses_len,
            events_offset,
            events_len,
            n_records,
        )?;
        let copy_sources = CopySources::from_mapped(map, copy_offset, copy_len, n_records)?;
        Ok(Self {
            writes,
            reads,
            bytes,
            copy_sources,
            snapshot: None,
        })
    }

    /// Return `(byte_value, kind, source_idx)` for the latest event at `addr`
    /// with `idx <= t`. Binary-searches the per-addr event list (events are
    /// pushed in trace order so naturally sorted by idx).
    ///
    /// `(None, "??", None)` if no event exists at `addr` or if the earliest
    /// event has `idx > t`.
    pub fn byte_at(&self, addr: u64, t: u64) -> (Option<u8>, &'static str, Option<usize>) {
        if let Some(evs) = self.bytes.get(&addr) {
            let mut lo = 0usize;
            let mut hi = evs.len();
            while lo < hi {
                let mid = (lo + hi) / 2;
                if (evs[mid].idx() as u64) <= t {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            if lo != 0 {
                let ev = &evs[lo - 1];
                return (Some(ev.byte), ev.kind.as_str(), Some(ev.idx()));
            }
        }
        // No traced event at-or-before `t`: fall back to the initial-snapshot
        // (`i`, idx 0) layer. Correct for any `t` before the first traced write,
        // which is exactly when the event map has no qualifying entry. See
        // docs/memory-completeness-design.md.
        if let Some(snap) = &self.snapshot {
            if let Some(b) = snap.byte_at(addr) {
                return (Some(b), "i", Some(0));
            }
        }
        (None, "??", None)
    }

    /// Return the idx of the latest WRITE event at `byte_addr` strictly
    /// before `before_idx`. Returns None if no such write exists.
    ///
    /// Mirrors the inner loop of viewer/taint.py:282-299 for one byte:
    /// fetch `bytes.get(addr+o)`, find the partition point where ev.idx()
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
        // partition_point: first index where ev.idx() >= before_idx
        let pos = evs.partition_point(|ev| ev.idx() < before_idx);
        for j in (0..pos).rev() {
            let ev = &evs[j];
            if ev.kind == "w" || ev.kind == "x" {
                return Some(ev.idx());
            }
        }
        None
    }

    /// Detect when a load (`"r"`) at `byte_addr` strictly before `before_idx`
    /// observed a byte value that disagrees with the latest preceding store /
    /// external write (`"w"` / `"x"`), or when a load was observed with no
    /// preceding store (or disagrees with the initial snapshot byte).
    pub fn unlogged_write_gap_before(
        &self,
        byte_addr: u64,
        before_idx: usize,
    ) -> Option<UnloggedWriteGap> {
        let evs = self.bytes.get(&byte_addr)?;
        let pos = evs.partition_point(|ev| ev.idx() < before_idx);
        let mut last_w: Option<(usize, &ByteEvent)> = None;
        for (j, ev) in evs[..pos].iter().enumerate().rev() {
            if ev.kind == "w" || ev.kind == "x" {
                last_w = Some((j, ev));
                break;
            }
        }
        if let Some((w_pos, w_ev)) = last_w {
            for r_ev in &evs[w_pos + 1..pos] {
                if r_ev.kind == "r" && r_ev.byte != w_ev.byte {
                    return Some(UnloggedWriteGap {
                        prev_write_idx: Some(w_ev.idx()),
                        prev_write_byte: Some(w_ev.byte),
                        first_observing_read_idx: r_ev.idx(),
                        observed_byte: r_ev.byte,
                    });
                }
            }
            None
        } else {
            let snap_byte = self.snapshot.as_ref().and_then(|s| s.byte_at(byte_addr));
            for r_ev in &evs[..pos] {
                if r_ev.kind != "r" {
                    continue;
                }
                if let Some(sb) = snap_byte {
                    if r_ev.byte != sb {
                        return Some(UnloggedWriteGap {
                            prev_write_idx: Some(0),
                            prev_write_byte: Some(sb),
                            first_observing_read_idx: r_ev.idx(),
                            observed_byte: r_ev.byte,
                        });
                    }
                } else {
                    return Some(UnloggedWriteGap {
                        prev_write_idx: None,
                        prev_write_byte: None,
                        first_observing_read_idx: r_ev.idx(),
                        observed_byte: r_ev.byte,
                    });
                }
            }
            None
        }
    }

    /// Independent input oracle for replay within `[evidence_start, before_idx)`.
    /// Only preceding stores/external writes count. The initial snapshot is
    /// usable only when evidence_start is zero; load outputs never validate inputs.
    pub fn input_byte(
        &self,
        addr: u64,
        before_idx: usize,
        evidence_start: usize,
    ) -> (Option<u8>, &'static str, Option<usize>) {
        if let Some(events) = self.bytes.get(&addr) {
            let end = events.partition_point(|e| e.idx() < before_idx);
            if let Some(e) = events[..end]
                .iter()
                .rev()
                .take_while(|e| e.idx() >= evidence_start)
                .find(|e| e.kind == "w" || e.kind == "x")
            {
                return (Some(e.byte), e.kind.as_str(), Some(e.idx()));
            }
        }
        if evidence_start == 0 {
            if let Some(byte) = self.snapshot.as_ref().and_then(|s| s.byte_at(addr)) {
                return (Some(byte), "i", None);
            }
        }
        (None, "??", None)
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

/// Planned worker count for [`MemShadow::build_from_trace`] at `n` records.
pub fn memshadow_worker_count(n: usize) -> usize {
    crate::parallel::worker_count(
        n,
        "TRACEMIKU_MEMSHADOW_THREADS",
        PARALLEL_MIN_RECORDS,
        MIN_CHUNK_RECORDS,
    )
}

fn build_range(
    trace: &Trace,
    start: usize,
    end: usize,
    budget_bytes: usize,
) -> Result<MemShadow, crate::parallel::BuildLimit> {
    let mut writes: Vec<MemRec> = Vec::new();
    let mut reads: Vec<MemRec> = Vec::new();
    let mut bytes = ByteEvents::default();
    let mut event_count = 0usize;
    for i in start..end {
        let rec = trace.record(i);
        let d = decode(rec.pc, rec.inst);
        for op in &d.mem_op {
            if op.base.is_empty() {
                continue;
            }
            let addr = addr_of(&rec, op);
            if op.is_write {
                if let Some(raw_bytes) = bytes_of_write(trace, i, op, &d) {
                    let v = low_u64_from_le(&raw_bytes);
                    writes.push(MemRec {
                        idx: i,
                        addr,
                        size: op.size,
                        value: v,
                        reserved: 0,
                    });
                    event_count +=
                        splat_byte_slice(&mut bytes, addr, &raw_bytes, i, ByteEventKind::Write);
                }
            } else if let Some(raw_bytes) = bytes_of_read(trace, i, op, &d) {
                let v = low_u64_from_le(&raw_bytes);
                reads.push(MemRec {
                    idx: i,
                    addr,
                    size: op.size,
                    value: v,
                    reserved: 0,
                });
                event_count +=
                    splat_byte_slice(&mut bytes, addr, &raw_bytes, i, ByteEventKind::Read);
            }
        }
        let estimated = (writes.capacity().saturating_add(reads.capacity()))
            .saturating_mul(32)
            .saturating_add(bytes.estimated_heap_bytes_with_event_count(event_count));
        crate::parallel::check_memory_budget("memshadow", estimated, budget_bytes)?;
    }
    Ok(MemShadow {
        writes: writes.into(),
        reads: reads.into(),
        bytes,
        copy_sources: CopySources::default(),
        snapshot: None,
    })
}

fn merge_partials(partials: Vec<MemShadow>) -> MemShadow {
    let mut out = MemShadow {
        writes: MemRecords::default(),
        reads: MemRecords::default(),
        bytes: ByteEvents::default(),
        copy_sources: CopySources::default(),
        snapshot: None,
    };
    for mut partial in partials {
        out.writes.append(&mut partial.writes);
        out.reads.append(&mut partial.reads);
        for (addr, mut events) in partial.bytes.into_building() {
            out.bytes.entry(addr).or_default().append(&mut events);
        }
    }
    out
}

fn worker_trace_files(call_dir: &std::path::Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(call_dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("worker_trace_tid") && n.ends_with(".bin"))
        })
        .collect();
    files.sort();
    files
}

fn merge_worker_traces(
    trace: &Trace,
    mem: &mut MemShadow,
    event_count: &mut usize,
    budget_bytes: usize,
) -> Result<(), crate::parallel::BuildLimit> {
    let files = worker_trace_files(trace.call_dir());
    if files.is_empty() {
        return Ok(());
    }
    let default_anchor = trace.len().saturating_sub(1);
    let anchor_windows =
        crate::memshadow_ext::load_worker_anchor_windows(trace.call_dir(), default_anchor);
    let mut added = false;
    for path in files {
        let Ok(file) = std::fs::File::open(&path) else {
            tracing::warn!(path = %path.display(), "cannot open worker trace");
            continue;
        };
        // SAFETY: worker records are read through a read-only mapping; an
        // incomplete trailing record is excluded by integer division below.
        let raw = match unsafe { Mmap::map(&file) } {
            Ok(raw) => raw,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "cannot mmap worker trace");
                continue;
            }
        };
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let n = raw.len() / crate::trace::REC_SIZE;
        for i in 0..n {
            let anchor_idx = crate::memshadow_ext::worker_record_anchor_idx(
                &anchor_windows,
                file_name,
                i,
                n,
                default_anchor,
            );
            let off = i * crate::trace::REC_SIZE;
            let rec = *bytemuck::from_bytes::<crate::trace::Record>(
                &raw[off..off + crate::trace::REC_SIZE],
            );
            let d = decode(rec.pc, rec.inst);
            for op in &d.mem_op {
                if op.base.is_empty() || !op.is_write {
                    continue;
                }
                if matches!(
                    d.mnemonic.as_str(),
                    "stxr" | "stxrb" | "stxrh" | "stxp" | "stlxr" | "stlxrb" | "stlxrh" | "stlxp"
                ) {
                    if i + 1 >= n {
                        continue;
                    }
                    let next_off = (i + 1) * crate::trace::REC_SIZE;
                    let next_rec = *bytemuck::from_bytes::<crate::trace::Record>(
                        &raw[next_off..next_off + crate::trace::REC_SIZE],
                    );
                    let Some(status) = d.op_str.split(',').next().map(str::trim) else {
                        continue;
                    };
                    if next_rec.reg_by_name(status) != Some(0) {
                        continue;
                    }
                }
                let src = if !op.src_reg.is_empty() {
                    op.src_reg.clone()
                } else {
                    let Some(s) = d.regs_use.iter().find(|r| **r != op.base && **r != op.idx)
                    else {
                        continue;
                    };
                    s.clone()
                };
                let Some(v) = rec.reg_by_name(&src) else {
                    continue;
                };
                let addr = addr_of(&rec, op);
                let sz = (op.size as usize).min(8);
                let raw_bytes = &v.to_le_bytes()[..sz];
                mem.writes.push(MemRec {
                    idx: anchor_idx,
                    addr,
                    size: op.size,
                    value: v,
                    reserved: 0,
                });
                *event_count += splat_byte_slice(
                    &mut mem.bytes,
                    addr,
                    raw_bytes,
                    anchor_idx,
                    ByteEventKind::External,
                );
                added = true;
            }
            mem.ensure_budget_with_event_count(*event_count, budget_bytes)?;
        }
    }
    if added {
        mem.writes.sort_by_key(|rec| (rec.idx, rec.addr));
        for events in mem.bytes.values_mut() {
            events.sort_by_key(|ev| ev.idx());
        }
    }
    Ok(())
}

fn merge_external_writes(
    trace: &Trace,
    mem: &mut MemShadow,
    event_count: &mut usize,
    budget_bytes: usize,
) -> Result<(), crate::parallel::BuildLimit> {
    let path = trace.call_dir().join(EXTERNAL_WRITES_FILE);
    let Ok(file) = std::fs::File::open(path) else {
        return Ok(());
    };
    // SAFETY: external write records are read through a read-only mapping;
    // chunks_exact deliberately ignores an incomplete trailing record.
    let Ok(raw) = (unsafe { Mmap::map(&file) }) else {
        return Ok(());
    };
    let mut seen: BTreeSet<(usize, u64, u8)> = BTreeSet::new();
    for chunk in raw.as_chunks::<EXTERNAL_WRITE_RECORD_SIZE>().0 {
        let idx_u64 = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let Ok(idx) = usize::try_from(idx_u64) else {
            continue;
        };
        if idx >= trace.len() {
            continue;
        }
        let addr = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        let byte = chunk[16];
        if !seen.insert((idx, addr, byte)) {
            continue;
        }
        mem.writes.push(MemRec {
            idx,
            addr,
            size: 1,
            value: byte as u64,
            reserved: 0,
        });
        mem.bytes
            .entry(addr)
            .or_default()
            .push(ByteEvent::new(idx, byte, ByteEventKind::External));
        *event_count = event_count.saturating_add(1);
        mem.ensure_budget_with_event_count(*event_count, budget_bytes)?;
    }
    mem.writes.sort_by_key(|rec| (rec.idx, rec.addr));
    for events in mem.bytes.values_mut() {
        events.sort_by_key(|ev| ev.idx());
    }
    Ok(())
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

/// Splat a slice of LE bytes into the per-addr event map starting at `addr`.
fn splat_byte_slice(
    bytes: &mut ByteEvents,
    addr: u64,
    raw: &[u8],
    idx: usize,
    kind: ByteEventKind,
) -> usize {
    for (o, &b) in raw.iter().enumerate() {
        bytes
            .entry(addr.wrapping_add(o as u64))
            .or_default()
            .push(ByteEvent::new(idx, b, kind));
    }
    raw.len()
}

fn low_u64_from_le(raw: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let take = raw.len().min(8);
    buf[..take].copy_from_slice(&raw[..take]);
    u64::from_le_bytes(buf)
}

fn element_width_from_arrangement(token: &str) -> usize {
    if let Some((_, suffix)) = token.split_once('.') {
        let base = suffix.split('[').next().unwrap_or(suffix);
        return match base {
            "16b" | "8b" | "b" => 1,
            "8h" | "4h" | "h" => 2,
            "4s" | "2s" | "s" => 4,
            "2d" | "1d" | "d" => 8,
            _ => 1,
        };
    }
    1
}

/// Reconstruct interleaved or multi-register vector structure bytes at `simd_idx`.
fn vector_structure_bytes(
    trace: &Trace,
    simd_idx: usize,
    decoded: &DecodedInsn,
    expected_size: usize,
) -> Option<Vec<u8>> {
    let simd = trace.simd()?;
    let mnem_base = decoded
        .mnemonic
        .split('.')
        .next()
        .unwrap_or(&decoded.mnemonic);
    let (vec_regs, vec_sz) = crate::disasm::mem_op::parse_vector_list_from_op_str(&decoded.op_str)?;
    let n_regs = vec_regs.len();
    if n_regs == 0 {
        return None;
    }
    // Extract raw bytes for each vector register in the list.
    let mut reg_bufs = Vec::with_capacity(n_regs);
    for r in &vec_regs {
        let (reg_idx, _) = crate::trace::parse_simd_reg_name(r)?;
        let q = simd.q_bytes(simd_idx, reg_idx)?;
        reg_bufs.push(q[..(vec_sz as usize).min(16)].to_vec());
    }
    if matches!(mnem_base, "ld1r" | "st1" | "ld1") {
        let mut out = Vec::with_capacity(expected_size);
        for buf in &reg_bufs {
            out.extend_from_slice(buf);
        }
        out.truncate(expected_size);
        return Some(out);
    }
    // Interleaved st2..st4 / ld2..ld4: interleave elements of width `elem_bytes` across `n_regs`.
    let first_tok = decoded
        .op_str
        .find('{')
        .and_then(|open| {
            let close = decoded.op_str[open..].find('}')? + open;
            decoded.op_str[open + 1..close].split(',').next()
        })
        .unwrap_or("");
    let elem_bytes = element_width_from_arrangement(first_tok.trim()).max(1);
    let lane_count = (vec_sz as usize) / elem_bytes;
    let mut out = Vec::with_capacity(n_regs * (vec_sz as usize));
    for lane in 0..lane_count {
        let start = lane * elem_bytes;
        let end = start + elem_bytes;
        for buf in &reg_bufs {
            if end <= buf.len() {
                out.extend_from_slice(&buf[start..end]);
            }
        }
    }
    out.truncate(expected_size);
    (out.len() == expected_size).then_some(out)
}

/// Extract exact little-endian bytes written by a store operation at record `i`.
/// Supports scalar GPRs (`trace.bin`) and NEON/SIMD registers (`simd_trace.bin`).
pub(crate) fn bytes_of_write(
    trace: &Trace,
    i: usize,
    op: &MemOp,
    decoded: &DecodedInsn,
) -> Option<Vec<u8>> {
    if matches!(
        decoded.mnemonic.as_str(),
        "stxr" | "stxrb" | "stxrh" | "stxp" | "stlxr" | "stlxrb" | "stlxrh" | "stlxp"
    ) {
        let status = decoded.op_str.split(',').next()?.trim();
        if trace.post_record(i)?.reg_by_name(status)? != 0 {
            return None;
        }
    }
    let mnem_base = decoded
        .mnemonic
        .split('.')
        .next()
        .unwrap_or(&decoded.mnemonic);
    if matches!(mnem_base, "st2" | "st3" | "st4") {
        return vector_structure_bytes(trace, i, decoded, op.size as usize);
    }
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
    if let Some(v) = rec.reg_by_name(&src) {
        let sz = (op.size as usize).min(8);
        return Some(v.to_le_bytes()[..sz].to_vec());
    }
    if let Some((reg_idx, _)) = crate::trace::parse_simd_reg_name(&src) {
        let q = trace.simd()?.q_bytes(i, reg_idx)?;
        let sz = (op.size as usize).min(16);
        return Some(q[..sz].to_vec());
    }
    None
}

/// Extract exact little-endian bytes loaded by a load operation at record `i`,
/// taken from the next record's post-state (`trace.bin` or `simd_trace.bin`).
pub(crate) fn bytes_of_read(
    trace: &Trace,
    i: usize,
    op: &MemOp,
    decoded: &DecodedInsn,
) -> Option<Vec<u8>> {
    let post = trace.post_record(i)?;
    let post_idx = i + 1;
    let mnem_base = decoded
        .mnemonic
        .split('.')
        .next()
        .unwrap_or(&decoded.mnemonic);
    if matches!(
        mnem_base,
        "ld2" | "ld3" | "ld4" | "ld1r" | "ld2r" | "ld3r" | "ld4r"
    ) {
        return vector_structure_bytes(trace, post_idx, decoded, op.size as usize);
    }
    let dest = if !op.src_reg.is_empty() {
        op.src_reg.clone()
    } else {
        decoded.regs_def.first().cloned()?
    };
    if let Some(v) = post.reg_by_name(&dest) {
        let sz = (op.size as usize).min(8);
        return Some(v.to_le_bytes()[..sz].to_vec());
    }
    if let Some((reg_idx, _)) = crate::trace::parse_simd_reg_name(&dest) {
        let q = trace.simd()?.q_bytes(post_idx, reg_idx)?;
        let sz = (op.size as usize).min(16);
        return Some(q[..sz].to_vec());
    }
    None
}

/// Pick the source register that supplied a store's bytes, taken from the
/// storing record's pre-state. For stp/ldp pair-split entries, capstone fills
/// `op.src_reg` directly; otherwise fall back to the first non-base/non-idx
/// reg in `regs_use`. For 16-byte SIMD writes, returns the low 64 bits.
pub(crate) fn value_of_write(
    trace: &Trace,
    i: usize,
    op: &MemOp,
    decoded: &DecodedInsn,
) -> Option<u64> {
    bytes_of_write(trace, i, op, decoded).map(|b| low_u64_from_le(&b))
}

/// Bind reconstructed events to all inputs that affect them. Snapshots are
/// loaded fresh and are not serialized in the event cache.
fn load_snapshot_with_budget(
    trace: &Trace,
    current_bytes: usize,
    budget_bytes: usize,
) -> Result<Option<MemSnapshot>, crate::parallel::BuildLimit> {
    let path = trace.call_dir().join(SNAPSHOT_FILE);
    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(None);
    };
    let snapshot_bytes = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    crate::parallel::check_memory_budget(
        "memshadow_snapshot",
        current_bytes.saturating_add(snapshot_bytes),
        budget_bytes,
    )?;
    Ok(MemSnapshot::load(trace))
}

fn memory_input_digest(trace: &Trace) -> std::io::Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(trace.digest());
    hash.update(trace.quality().dropped.to_le_bytes());
    hash.update([
        trace.quality().truncated as u8,
        trace.quality().metadata_valid as u8,
        trace.quality().metadata_present as u8,
    ]);
    for name in [
        EXTERNAL_WRITES_FILE,
        "simd_trace.bin",
        "meta.json",
        SNAPSHOT_FILE,
    ] {
        hash.update(name.as_bytes());
        match std::fs::File::open(trace.call_dir().join(name)) {
            Ok(mut file) => {
                hash.update([1]);
                let mut buf = [0; 64 * 1024];
                loop {
                    let n = file.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hash.update(&buf[..n]);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => hash.update([0]),
            Err(e) => return Err(e),
        }
    }
    for worker_path in worker_trace_files(trace.call_dir()) {
        if let Some(name) = worker_path.file_name().and_then(|n| n.to_str()) {
            hash.update(name.as_bytes());
        }
        if let Ok(file) = std::fs::File::open(&worker_path) {
            hash.update([1]);
            let metadata = file.metadata()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                // ctime cannot be reset by userspace after rewriting a worker;
                // unlike hashing GiBs on every hot query, this keeps reload I/O bounded.
                for value in [
                    metadata.dev(),
                    metadata.ino(),
                    metadata.size(),
                    metadata.mtime() as u64,
                    metadata.mtime_nsec() as u64,
                    metadata.ctime() as u64,
                    metadata.ctime_nsec() as u64,
                ] {
                    hash.update(value.to_le_bytes());
                }
            }
            #[cfg(not(unix))]
            {
                hash.update(metadata.len().to_le_bytes());
                if let Ok(modified) = metadata.modified() {
                    if let Ok(elapsed) = modified.duration_since(std::time::SystemTime::UNIX_EPOCH)
                    {
                        hash.update(elapsed.as_nanos().to_le_bytes());
                    }
                }
            }
        }
    }
    Ok(hash.finalize().into())
}

fn section_end(offset: usize, len: usize, width: usize) -> std::io::Result<usize> {
    len.checked_mul(width)
        .and_then(|bytes| offset.checked_add(bytes))
        .ok_or_else(|| invalid_data("memshadow sidecar section offset overflow"))
}

fn read_sidecar_len(
    raw: &[u8],
    offset: usize,
    file_len: usize,
    width: usize,
) -> std::io::Result<usize> {
    let len = sidecar_usize(raw, offset)?;
    if len > file_len / width {
        return Err(invalid_data("sidecar length exceeds size limit"));
    }
    Ok(len)
}

fn sidecar_usize(raw: &[u8], offset: usize) -> std::io::Result<usize> {
    usize::try_from(u64_at(raw, offset)?).map_err(|_| invalid_data("sidecar usize overflow"))
}

fn u32_at(raw: &[u8], offset: usize) -> std::io::Result<u32> {
    let bytes = raw
        .get(offset..offset + 4)
        .ok_or_else(|| invalid_data("truncated memshadow sidecar u32"))?;
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
        invalid_data("truncated memshadow sidecar u32")
    })?))
}

fn u64_at(raw: &[u8], offset: usize) -> std::io::Result<u64> {
    let bytes = raw
        .get(offset..offset + 8)
        .ok_or_else(|| invalid_data("truncated memshadow sidecar u64"))?;
    Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| {
        invalid_data("truncated memshadow sidecar u64")
    })?))
}

fn byte_events_as_bytes(events: &[ByteEvent]) -> &[u8] {
    // SAFETY: ByteEvent implements NoUninit with explicit reserved bytes, so
    // every byte in the slice is initialized and valid to serialize.
    unsafe {
        std::slice::from_raw_parts(events.as_ptr().cast::<u8>(), std::mem::size_of_val(events))
    }
}

/// One byte's provenance in a Tenet-style export.
#[derive(Debug, Clone, Serialize)]
pub struct TenetByte {
    pub offset: u64,
    pub value: u8,
    pub source: TenetSource,
}

/// Where a dumped byte came from: a concrete writer, the initial snapshot,
/// or explicitly unknown. Never fabricated.
#[derive(Debug, Clone, Serialize)]
pub struct TenetSource {
    /// "store", "external", "initial", or "unknown".
    pub kind: String,
    /// Trace record idx of the writer (None for initial/unknown).
    pub idx: Option<usize>,
}

/// Tenet-style export of a contiguous byte range.
#[derive(Debug, Clone, Serialize)]
pub struct TenetDump {
    pub addr: u64,
    pub len: usize,
    pub bytes: Vec<TenetByte>,
}

impl MemShadow {
    /// Export `len` bytes starting at `addr` with per-byte provenance. Each
    /// byte is tagged with its latest writer (store/external), the initial
    /// snapshot value, or `unknown` when no evidence exists — missing memory
    /// is never fabricated. `t` is the trace index at which to evaluate the
    /// memory state (default: all events). Capped at 1 MiB to bound output.
    pub fn tenet_export(&self, addr: u64, len: usize) -> Result<TenetDump, String> {
        const MAX_TENET_LEN: usize = 1 << 20;
        if len == 0 || len > MAX_TENET_LEN {
            return Err(format!(
                "tenet export len {len} out of range (1..{MAX_TENET_LEN})"
            ));
        }
        let t = u64::MAX;
        let mut bytes = Vec::with_capacity(len);
        for off in 0..len as u64 {
            let (value, kind, idx) = self.byte_at(addr.wrapping_add(off), t);
            let source = match (kind, idx) {
                ("w", Some(i)) => TenetSource {
                    kind: "store".into(),
                    idx: Some(i),
                },
                ("x", Some(i)) => TenetSource {
                    kind: "external".into(),
                    idx: Some(i),
                },
                ("i", _) => TenetSource {
                    kind: "initial".into(),
                    idx: None,
                },
                _ => TenetSource {
                    kind: "unknown".into(),
                    idx: None,
                },
            };
            bytes.push(TenetByte {
                offset: off,
                value: value.unwrap_or(0),
                source,
            });
        }
        Ok(TenetDump { addr, len, bytes })
    }
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
                reserved: 0,
            }]
            .into(),
            reads: MemRecords::default(),
            bytes: BTreeMap::from([(0x7000, vec![ByteEvent::new(1, 0x41, ByteEventKind::Write)])])
                .into(),
            copy_sources: CopySources::default(),
            snapshot: None,
        };
        let partial_b = MemShadow {
            writes: vec![MemRec {
                idx: 3,
                addr: 0x7000,
                size: 1,
                value: 0x42,
                reserved: 0,
            }]
            .into(),
            reads: MemRecords::default(),
            bytes: BTreeMap::from([(0x7000, vec![ByteEvent::new(3, 0x42, ByteEventKind::Write)])])
                .into(),
            copy_sources: CopySources::default(),
            snapshot: None,
        };

        let merged = merge_partials(vec![partial_a, partial_b]);

        assert_eq!(
            merged
                .bytes
                .get(&0x7000)
                .unwrap()
                .iter()
                .map(|ev| ev.idx())
                .collect::<Vec<_>>(),
            vec![1, 3]
        );
        assert_eq!(
            merged.writes.iter().map(|rec| rec.idx).collect::<Vec<_>>(),
            vec![1, 3]
        );
    }

    /// Build a `memory_snapshot.bin` blob with one region.
    fn snap_blob(base: u64, perms: u32, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(SNAPSHOT_MAGIC);
        v.extend_from_slice(&1u32.to_le_bytes()); // version
        v.extend_from_slice(&1u32.to_le_bytes()); // count
        v.extend_from_slice(&base.to_le_bytes());
        v.extend_from_slice(&(data.len() as u64).to_le_bytes());
        v.extend_from_slice(&perms.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // flags
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn snapshot_parse_and_byte_lookup() {
        let blob = snap_blob(0x1000, 0b101, &[0xaa, 0xbb, 0xcc, 0xdd]);
        let snap = MemSnapshot::parse(&blob).expect("valid snapshot");
        assert_eq!(snap.total_bytes(), 4);
        assert_eq!(snap.byte_at(0x1000), Some(0xaa));
        assert_eq!(snap.byte_at(0x1003), Some(0xdd));
        assert_eq!(snap.byte_at(0x1004), None); // past region
        assert_eq!(snap.byte_at(0x0fff), None); // before region
    }

    #[test]
    fn snapshot_rejects_bad_magic() {
        assert!(MemSnapshot::parse(b"NOTMAGIC........").is_none());
        assert!(MemSnapshot::parse(b"short").is_none());
    }

    #[test]
    fn byte_at_falls_back_to_snapshot_then_traced_store_overrides() {
        // Pre-trace byte 0x42 at 0x2000 in the snapshot; a traced store writes
        // 0x99 there at idx=5.
        let snap = MemSnapshot::parse(&snap_blob(0x2000, 0b011, &[0x42])).unwrap();
        let mut bytes = BTreeMap::new();
        bytes.insert(
            0x2000u64,
            vec![ByteEvent::new(5, 0x99, ByteEventKind::Write)],
        );
        let mem = MemShadow {
            writes: MemRecords::default(),
            reads: MemRecords::default(),
            bytes: bytes.into(),
            copy_sources: CopySources::default(),
            snapshot: Some(snap),
        };

        // t before the store → snapshot value, kind "i", source idx 0.
        assert_eq!(mem.byte_at(0x2000, 3), (Some(0x42), "i", Some(0)));
        // t at/after the store → traced store wins, kind "w".
        assert_eq!(mem.byte_at(0x2000, 5), (Some(0x99), "w", Some(5)));
        // An address only in the snapshot, with no traced events at all.
        assert_eq!(mem.byte_at(0x9999, 100), (None, "??", None));
    }

    #[test]
    fn byte_at_no_snapshot_is_unknown() {
        let mem = MemShadow {
            writes: MemRecords::default(),
            reads: MemRecords::default(),
            bytes: ByteEvents::default(),
            copy_sources: CopySources::default(),
            snapshot: None,
        };
        assert_eq!(mem.byte_at(0x1000, 10), (None, "??", None));
    }
}
