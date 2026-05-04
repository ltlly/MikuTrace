//! Memory query endpoints backed by Index + MemShadow.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::*;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LastWriteOfAddrQuery {
    pub addr: String,
    #[serde(default = "default_before_idx")]
    pub before_idx: isize,
}

fn default_before_idx() -> isize {
    -1
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LastWriteOfAddrResponse {
    Found {
        status: &'static str,
        addr: String,
        before_idx: usize,
        writer_idx: usize,
        writer_pc: String,
        rel: Option<String>,
        func: Option<String>,
        asm: String,
        src_reg: Option<String>,
        src_value: Option<String>,
        writes_before: usize,
        writes_after: usize,
    },
    NotFound {
        status: &'static str,
        addr: String,
        before_idx: usize,
        writes_total: usize,
    },
}

pub async fn last_write_of_addr_handler(
    State(state): State<AppState>,
    Query(q): Query<LastWriteOfAddrQuery>,
) -> Json<LastWriteOfAddrResponse> {
    let Some(addr) = parse_int(&q.addr) else {
        return Json(LastWriteOfAddrResponse::NotFound {
            status: "not-found",
            addr: q.addr,
            before_idx: 0,
            writes_total: 0,
        });
    };
    let inner = &state.inner;
    let before = if q.before_idx >= 0 {
        (q.before_idx as usize).min(inner.trace.len())
    } else {
        inner.trace.len()
    };
    let mut writes: Vec<usize> = inner
        .index
        .mem_writes
        .iter()
        .filter(|w| touches_addr(w.addr, w.size, addr))
        .map(|w| w.idx)
        .collect();
    writes.sort_unstable();
    writes.dedup();
    let cut = writes.partition_point(|&idx| idx < before);
    let Some(&writer_idx) = cut.checked_sub(1).and_then(|i| writes.get(i)) else {
        return Json(LastWriteOfAddrResponse::NotFound {
            status: "not-found",
            addr: q.addr,
            before_idx: before,
            writes_total: writes.len(),
        });
    };
    let record = inner.trace.record(writer_idx);
    let decoded = decode(record.pc, record.inst);
    let (func_name, _) = inner.symbols.lookup(record.pc);
    let func = (func_name != "?").then_some(func_name);
    let base = primary_base(&inner.meta);
    let src_reg = source_reg_for_write(&decoded);
    let src_value = src_reg
        .as_deref()
        .and_then(|reg| record.reg_by_name(reg))
        .map(|v| format!("{v:#x}"));

    Json(LastWriteOfAddrResponse::Found {
        status: "found",
        addr: q.addr,
        before_idx: before,
        writer_idx,
        writer_pc: format!("{:#x}", record.pc),
        rel: base.map(|b| format!("{:#x}", record.pc.wrapping_sub(b))),
        func,
        asm: format!("{} {}", decoded.mnemonic, decoded.op_str)
            .trim()
            .to_string(),
        src_reg,
        src_value,
        writes_before: cut,
        writes_after: writes.len().saturating_sub(cut),
    })
}

#[derive(Debug, Deserialize)]
pub struct TouchingRangeQuery {
    pub addr: String,
    #[serde(default = "default_size")]
    pub size: u64,
    #[serde(default)]
    pub cursor: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_size() -> u64 {
    1
}

fn default_limit() -> usize {
    50
}

#[derive(Debug, Serialize)]
pub struct TouchingRangeResponse {
    pub status: &'static str,
    pub addr: String,
    pub size: u64,
    pub cursor: usize,
    pub writers_before: Vec<usize>,
    pub writers_after: Vec<usize>,
    pub writers_total: usize,
    pub readers_before: Vec<usize>,
    pub readers_after: Vec<usize>,
    pub readers_total: usize,
}

pub async fn idxs_touching_range_handler(
    State(state): State<AppState>,
    Query(q): Query<TouchingRangeQuery>,
) -> Json<TouchingRangeResponse> {
    let start = parse_int(&q.addr).unwrap_or(0);
    let size = q.size.max(1);
    let inner = &state.inner;
    let writers = touching_range_idxs(
        inner
            .index
            .mem_writes
            .iter()
            .map(|m| (m.idx, m.addr, m.size)),
        start,
        size,
    );
    let readers = touching_range_idxs(
        inner
            .index
            .mem_reads
            .iter()
            .map(|m| (m.idx, m.addr, m.size)),
        start,
        size,
    );
    let (writers_before, writers_after) = split_around_cursor(&writers, q.cursor, q.limit);
    let (readers_before, readers_after) = split_around_cursor(&readers, q.cursor, q.limit);
    Json(TouchingRangeResponse {
        status: "ready",
        addr: q.addr,
        size,
        cursor: q.cursor,
        writers_before,
        writers_after,
        writers_total: writers.len(),
        readers_before,
        readers_after,
        readers_total: readers.len(),
    })
}

#[derive(Debug, Deserialize)]
pub struct TouchingAddrQuery {
    pub addr: String,
    #[serde(default)]
    pub cursor: usize,
    #[serde(default = "default_addr_limit")]
    pub limit: usize,
}

fn default_addr_limit() -> usize {
    30
}

#[derive(Debug, Serialize, Clone)]
pub struct TouchingAddrEntry {
    pub idx: usize,
    pub kind: &'static str,
}

#[derive(Debug, Serialize)]
pub struct TouchingAddrResponse {
    pub status: &'static str,
    pub addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<usize>,
    pub before: Vec<TouchingAddrEntry>,
    pub after: Vec<TouchingAddrEntry>,
    pub total_before: usize,
    pub total_after: usize,
}

pub async fn idxs_touching_addr_handler(
    State(state): State<AppState>,
    Query(q): Query<TouchingAddrQuery>,
) -> Json<TouchingAddrResponse> {
    let addr = parse_int(&q.addr).unwrap_or(0);
    let inner = &state.inner;
    let mut entries: Vec<TouchingAddrEntry> = inner
        .index
        .mem_writes
        .iter()
        .filter(|m| touches_addr(m.addr, m.size, addr))
        .map(|m| TouchingAddrEntry {
            idx: m.idx,
            kind: "w",
        })
        .chain(
            inner
                .index
                .mem_reads
                .iter()
                .filter(|m| touches_addr(m.addr, m.size, addr))
                .map(|m| TouchingAddrEntry {
                    idx: m.idx,
                    kind: "r",
                }),
        )
        .collect();
    entries.sort_by_key(|e| e.idx);
    let cut = entries.partition_point(|e| e.idx < q.cursor);
    let before_start = cut.saturating_sub(q.limit);
    let mut before = entries[before_start..cut].to_vec();
    before.reverse();
    let after = entries[cut..entries.len().min(cut + q.limit)].to_vec();
    Json(TouchingAddrResponse {
        status: "ready",
        addr: q.addr,
        cursor: Some(q.cursor),
        before,
        after,
        total_before: cut,
        total_after: entries.len().saturating_sub(cut),
    })
}

#[derive(Debug, Deserialize)]
pub struct FindMemPatternQuery {
    pub bytes_hex: String,
    #[serde(default = "default_since")]
    pub since: isize,
    #[serde(default = "default_pattern_max")]
    pub max: usize,
    pub idx_lo: Option<usize>,
    pub idx_hi: Option<usize>,
}

fn default_since() -> isize {
    -1
}

fn default_pattern_max() -> usize {
    100
}

#[derive(Debug, Serialize)]
pub struct MemPatternHit {
    pub addr: String,
    pub first_idx: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct FindMemPatternResponse {
    pub pattern: String,
    pub since_idx: isize,
    pub count: usize,
    pub hits: Vec<MemPatternHit>,
}

pub async fn find_mem_pattern_handler(
    State(state): State<AppState>,
    Query(q): Query<FindMemPatternQuery>,
) -> Json<FindMemPatternResponse> {
    let pattern = parse_hex_bytes(&q.bytes_hex).unwrap_or_default();
    let cursor = if q.since >= 0 {
        q.since as u64
    } else {
        u64::MAX
    };
    let mut hits = Vec::new();
    if !pattern.is_empty() {
        for &addr in state.inner.memshadow.bytes.keys() {
            let mut first_idx: Option<usize> = None;
            let mut matched = true;
            for (offset, want) in pattern.iter().enumerate() {
                let (byte, _kind, idx) =
                    state.inner.memshadow.byte_at(addr + offset as u64, cursor);
                if byte != Some(*want) {
                    matched = false;
                    break;
                }
                if let Some(idx) = idx {
                    first_idx = Some(first_idx.map_or(idx, |old| old.min(idx)));
                }
            }
            if !matched {
                continue;
            }
            if q.idx_lo
                .is_some_and(|lo| first_idx.is_none_or(|idx| idx < lo))
            {
                continue;
            }
            if q.idx_hi
                .is_some_and(|hi| first_idx.is_none_or(|idx| idx >= hi))
            {
                continue;
            }
            hits.push(MemPatternHit {
                addr: format!("{addr:#x}"),
                first_idx,
            });
            if q.max > 0 && hits.len() >= q.max {
                break;
            }
        }
    }
    Json(FindMemPatternResponse {
        pattern: pattern.iter().map(|b| format!("{b:02x}")).collect(),
        since_idx: q.since,
        count: hits.len(),
        hits,
    })
}

fn parse_int(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let cleaned = s.replace("0x", "").replace("0X", "").replace(' ', "");
    if !cleaned.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        out.push(u8::from_str_radix(&cleaned[i..i + 2], 16).ok()?);
    }
    Some(out)
}

fn touches_addr(start: u64, size: u32, target: u64) -> bool {
    target >= start && target < start.saturating_add(size as u64)
}

fn overlaps(start: u64, size: u32, range_start: u64, range_size: u64) -> bool {
    let end = start.saturating_add(size as u64);
    let range_end = range_start.saturating_add(range_size);
    start < range_end && end > range_start
}

fn touching_range_idxs<I>(iter: I, start: u64, size: u64) -> Vec<usize>
where
    I: IntoIterator<Item = (usize, u64, u32)>,
{
    let mut out: Vec<usize> = iter
        .into_iter()
        .filter(|(_, addr, rec_size)| overlaps(*addr, *rec_size, start, size))
        .map(|(idx, _, _)| idx)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn split_around_cursor(idxs: &[usize], cursor: usize, limit: usize) -> (Vec<usize>, Vec<usize>) {
    let cut = idxs.partition_point(|&idx| idx < cursor);
    let before_start = cut.saturating_sub(limit);
    let mut before = idxs[before_start..cut].to_vec();
    before.reverse();
    let after = idxs[cut..idxs.len().min(cut + limit)].to_vec();
    (before, after)
}

fn source_reg_for_write(decoded: &DecodedInsn) -> Option<String> {
    let (base, idx) = decoded
        .mem_op
        .iter()
        .find(|op| op.is_write)
        .map(|op| (op.base.as_str(), op.idx.as_str()))
        .unwrap_or(("", ""));
    decoded
        .regs_use
        .iter()
        .find(|reg| reg.as_str() != base && reg.as_str() != idx)
        .cloned()
}

fn primary_base(meta: &TraceMeta) -> Option<u64> {
    meta.module.as_ref().and_then(|m| parse_int(&m.base))
}
