//! Memory query endpoints backed by Index + MemShadow.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::disasm::addr_of;
use tracemiku_core::prelude::*;

use crate::state::AppState;

const MAX_MEM_WRITES_RETURNED: usize = 5_000;
const MAX_PATTERN_HITS: usize = 5_000;
const MAX_TOUCHING_IDXS_RETURNED: usize = 5_000;

#[derive(Debug, Deserialize)]
pub struct LastWriteOfAddrQuery {
    pub addr: String,
    #[serde(default = "default_before_idx")]
    pub before_idx: isize,
    #[serde(default)]
    pub with_external: bool,
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
        write_kind: &'static str,
        writer_pc: String,
        rel: Option<String>,
        func: Option<String>,
        asm: String,
        dst_addr: String,
        size: u32,
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
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || last_write_of_addr_response(&inner, q, addr))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "last write of addr worker failed: {err}");
                LastWriteOfAddrResponse::NotFound {
                    status: "error",
                    addr: String::new(),
                    before_idx: 0,
                    writes_total: 0,
                }
            }),
    )
}

fn last_write_of_addr_response(
    inner: &crate::state::AppStateInner,
    q: LastWriteOfAddrQuery,
    addr: u64,
) -> LastWriteOfAddrResponse {
    let before = if q.before_idx >= 0 {
        (q.before_idx as usize).min(inner.trace.len())
    } else {
        inner.trace.len()
    };
    if q.with_external {
        return last_write_of_addr_response_from_memshadow(inner, q, addr, before);
    }
    let mut last_seen_idx: Option<usize> = None;
    let mut writes_before = 0usize;
    let mut writes_after = 0usize;
    let mut writer_idx: Option<usize> = None;
    let mut writer_addr: Option<u64> = None;
    let mut writer_size: Option<u32> = None;
    for write in &inner.index.mem_writes {
        if !touches_addr(write.addr, write.size, addr) {
            continue;
        }
        if last_seen_idx == Some(write.idx) {
            continue;
        }
        last_seen_idx = Some(write.idx);
        if write.idx < before {
            writes_before += 1;
            writer_idx = Some(write.idx);
            writer_addr = Some(write.addr);
            writer_size = Some(write.size);
        } else {
            writes_after += 1;
        }
    }
    let Some(writer_idx) = writer_idx else {
        return LastWriteOfAddrResponse::NotFound {
            status: "not-found",
            addr: q.addr,
            before_idx: before,
            writes_total: writes_before + writes_after,
        };
    };
    let record = inner.trace.record(writer_idx);
    let decoded = decode(record.pc, record.inst);
    let (func_name, _) = inner.symbols.lookup(record.pc);
    let func = (func_name != "?").then_some(func_name);
    let base = primary_base(&inner.meta);
    let src_reg = source_reg_for_write_at(&decoded, &record, addr);
    let src_value = src_reg
        .as_deref()
        .and_then(|reg| record.reg_by_name(reg))
        .map(|v| format!("{v:#x}"));

    LastWriteOfAddrResponse::Found {
        status: "found",
        addr: q.addr.clone(),
        before_idx: before,
        writer_idx,
        write_kind: "w",
        writer_pc: format!("{:#x}", record.pc),
        rel: base.map(|b| format!("{:#x}", record.pc.wrapping_sub(b))),
        func,
        asm: format!("{} {}", decoded.mnemonic, decoded.op_str)
            .trim()
            .to_string(),
        dst_addr: writer_addr
            .map(|addr| format!("{addr:#x}"))
            .unwrap_or_else(|| q.addr.clone()),
        size: writer_size.unwrap_or(1),
        src_reg,
        src_value,
        writes_before,
        writes_after,
    }
}

fn last_write_of_addr_response_from_memshadow(
    inner: &crate::state::AppStateInner,
    q: LastWriteOfAddrQuery,
    addr: u64,
    before: usize,
) -> LastWriteOfAddrResponse {
    let mem = inner.memshadow();
    let mut writes_before = 0usize;
    let mut writes_after = 0usize;
    let mut writer: Option<&tracemiku_core::prelude::ShadowMemRec> = None;
    let mut writer_kind = "w";
    for write in &mem.writes {
        if !touches_addr(write.addr, write.size, addr) {
            continue;
        }
        if write.idx < before {
            writes_before += 1;
            writer = Some(write);
            writer_kind = mem_write_kind_at(mem, addr, write.idx).unwrap_or("w");
        } else {
            writes_after += 1;
        }
    }
    let Some(write) = writer else {
        return LastWriteOfAddrResponse::NotFound {
            status: "not-found",
            addr: q.addr,
            before_idx: before,
            writes_total: writes_before + writes_after,
        };
    };
    let record = inner.trace.record(write.idx);
    let decoded = decode(record.pc, record.inst);
    let (func_name, _) = inner.symbols.lookup(record.pc);
    let func = (func_name != "?").then_some(func_name);
    let base = primary_base(&inner.meta);
    let src_reg = (writer_kind != "x")
        .then(|| source_reg_for_write_at(&decoded, &record, addr))
        .flatten();
    let src_value = src_reg
        .as_deref()
        .and_then(|reg| record.reg_by_name(reg))
        .unwrap_or(write.value);

    LastWriteOfAddrResponse::Found {
        status: "found",
        addr: q.addr,
        before_idx: before,
        writer_idx: write.idx,
        write_kind: writer_kind,
        writer_pc: format!("{:#x}", record.pc),
        rel: base.map(|b| format!("{:#x}", record.pc.wrapping_sub(b))),
        func,
        asm: format!("{} {}", decoded.mnemonic, decoded.op_str)
            .trim()
            .to_string(),
        dst_addr: format!("{:#x}", write.addr),
        size: write.size,
        src_reg,
        src_value: Some(format!("{src_value:#x}")),
        writes_before,
        writes_after,
    }
}

fn mem_write_kind_at(
    mem: &tracemiku_core::prelude::MemShadow,
    addr: u64,
    idx: usize,
) -> Option<&'static str> {
    mem.bytes
        .get(&addr)?
        .iter()
        .find(|ev| ev.idx == idx && (ev.kind == "w" || ev.kind == "x"))
        .map(|ev| ev.kind)
}

#[derive(Debug, Deserialize)]
pub struct MemWritesInRangeQuery {
    pub idx_lo: usize,
    #[serde(default = "default_idx_hi")]
    pub idx_hi: isize,
    pub src_byte: Option<String>,
    pub addr_lo: Option<String>,
    pub addr_hi: Option<String>,
    #[serde(default = "default_writes_max")]
    pub max: usize,
}

fn default_idx_hi() -> isize {
    -1
}

fn default_writes_max() -> usize {
    200
}

#[derive(Debug, Serialize)]
pub struct MemWriteRow {
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub func: Option<String>,
    pub asm: String,
    pub dst_addr: String,
    pub size: u32,
    pub src_reg: Option<String>,
    pub src_value: String,
    pub byte0: u8,
}

#[derive(Debug, Serialize)]
pub struct MemWritesInRangeResponse {
    pub idx_range: Vec<usize>,
    pub matched: usize,
    pub returned: usize,
    pub truncated: bool,
    pub writes: Vec<MemWriteRow>,
}

pub async fn mem_writes_in_range_handler(
    State(state): State<AppState>,
    Query(q): Query<MemWritesInRangeQuery>,
) -> Result<Json<MemWritesInRangeResponse>, (StatusCode, String)> {
    let inner = state.inner.clone();
    tokio::task::spawn_blocking(move || mem_writes_in_range_response(&inner, q))
        .await
        .unwrap_or_else(|err| {
            tracing::warn!(target: "tracemiku-server", "mem writes in range worker failed: {err}");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "mem writes worker failed".to_string(),
            ))
        })
        .map(Json)
}

fn mem_writes_in_range_response(
    inner: &crate::state::AppStateInner,
    q: MemWritesInRangeQuery,
) -> Result<MemWritesInRangeResponse, (StatusCode, String)> {
    let lo = q.idx_lo.min(inner.trace.len());
    let hi = if q.idx_hi >= 0 {
        (q.idx_hi as usize).min(inner.trace.len())
    } else {
        inner.trace.len()
    };
    let addr_lo = parse_optional_int("addr_lo", &q.addr_lo)?;
    let addr_hi = parse_optional_int("addr_hi", &q.addr_hi)?;
    let src_byte = parse_optional_int("src_byte", &q.src_byte)?.map(|v| (v & 0xff) as u8);
    let max = effective_writes_max(q.max);
    let base = primary_base(&inner.meta);
    if let (Some(src_byte), Some(memshadow)) = (src_byte, inner.memshadow_if_ready()) {
        return Ok(mem_writes_in_range_from_memshadow(
            inner, max, lo, hi, addr_lo, addr_hi, src_byte, base, memshadow,
        ));
    }

    let mut matched = 0usize;
    let mut rows = Vec::new();
    let writes_start = inner.index.mem_writes.partition_point(|w| w.idx < lo);
    let writes_end = inner.index.mem_writes.partition_point(|w| w.idx < hi);
    for write in &inner.index.mem_writes[writes_start..writes_end] {
        if !matches_addr_filter(write.addr, write.size, addr_lo, addr_hi) {
            continue;
        }
        if src_byte.is_none() {
            matched += 1;
            if rows.len() >= max {
                continue;
            }
        }
        let record = inner.trace.record(write.idx);
        let decoded = decode(record.pc, record.inst);
        let src_reg = source_reg_for_write_at(&decoded, &record, write.addr);
        let src_value = src_reg
            .as_deref()
            .and_then(|reg| record.reg_by_name(reg))
            .unwrap_or(0);
        if src_byte.is_some_and(|b| (src_value & 0xff) as u8 != b) {
            continue;
        }
        if src_byte.is_some() {
            matched += 1;
        }
        if rows.len() >= max {
            continue;
        }

        let (func_name, _) = inner.symbols.lookup(record.pc);
        rows.push(MemWriteRow {
            idx: write.idx,
            pc: format!("{:#x}", record.pc),
            rel: base.map(|b| format!("{:#x}", record.pc.wrapping_sub(b))),
            func: (func_name != "?").then_some(func_name),
            asm: format!("{} {}", decoded.mnemonic, decoded.op_str)
                .trim()
                .to_string(),
            dst_addr: format!("{:#x}", write.addr),
            size: write.size,
            src_reg,
            src_value: format!("{src_value:#x}"),
            byte0: (src_value & 0xff) as u8,
        });
    }

    Ok(MemWritesInRangeResponse {
        idx_range: vec![lo, hi],
        matched,
        returned: rows.len(),
        truncated: rows.len() < matched,
        writes: rows,
    })
}

#[allow(clippy::too_many_arguments)]
fn mem_writes_in_range_from_memshadow(
    inner: &crate::state::AppStateInner,
    max: usize,
    lo: usize,
    hi: usize,
    addr_lo: Option<u64>,
    addr_hi: Option<u64>,
    src_byte: u8,
    base: Option<u64>,
    memshadow: &tracemiku_core::prelude::MemShadow,
) -> MemWritesInRangeResponse {
    let mut matched = 0usize;
    let mut rows = Vec::new();
    let writes_start = memshadow.writes.partition_point(|w| w.idx < lo);
    let writes_end = memshadow.writes.partition_point(|w| w.idx < hi);
    for write in &memshadow.writes[writes_start..writes_end] {
        if !matches_addr_filter(write.addr, write.size, addr_lo, addr_hi) {
            continue;
        }
        if (write.value & 0xff) as u8 != src_byte {
            continue;
        }
        matched += 1;
        if rows.len() >= max {
            continue;
        }

        let record = inner.trace.record(write.idx);
        let decoded = decode(record.pc, record.inst);
        let src_reg = source_reg_for_write_at(&decoded, &record, write.addr);
        let (func_name, _) = inner.symbols.lookup(record.pc);
        rows.push(MemWriteRow {
            idx: write.idx,
            pc: format!("{:#x}", record.pc),
            rel: base.map(|b| format!("{:#x}", record.pc.wrapping_sub(b))),
            func: (func_name != "?").then_some(func_name),
            asm: format!("{} {}", decoded.mnemonic, decoded.op_str)
                .trim()
                .to_string(),
            dst_addr: format!("{:#x}", write.addr),
            size: write.size,
            src_reg,
            src_value: format!("{:#x}", write.value),
            byte0: (write.value & 0xff) as u8,
        });
    }

    MemWritesInRangeResponse {
        idx_range: vec![lo, hi],
        matched,
        returned: rows.len(),
        truncated: rows.len() < matched,
        writes: rows,
    }
}

fn effective_writes_max(raw: usize) -> usize {
    if raw == 0 {
        MAX_MEM_WRITES_RETURNED
    } else {
        raw.min(MAX_MEM_WRITES_RETURNED)
    }
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

fn effective_touch_limit(raw: usize) -> usize {
    raw.min(MAX_TOUCHING_IDXS_RETURNED)
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
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || idxs_touching_range_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "idxs touching range worker failed: {err}");
                TouchingRangeResponse {
                    status: "error",
                    addr: String::new(),
                    size: 0,
                    cursor: 0,
                    writers_before: Vec::new(),
                    writers_after: Vec::new(),
                    writers_total: 0,
                    readers_before: Vec::new(),
                    readers_after: Vec::new(),
                    readers_total: 0,
                }
            }),
    )
}

fn idxs_touching_range_response(
    inner: &crate::state::AppStateInner,
    q: TouchingRangeQuery,
) -> TouchingRangeResponse {
    let start = parse_int(&q.addr).unwrap_or(0);
    let size = q.size.max(1);
    let (writers, readers) = if let Some(mem) = inner.memshadow_if_ready() {
        touching_range_idxs_from_memshadow(mem, start, size)
    } else {
        (
            touching_range_idxs(
                inner
                    .index
                    .mem_writes
                    .iter()
                    .map(|m| (m.idx, m.addr, m.size)),
                start,
                size,
            ),
            touching_range_idxs(
                inner
                    .index
                    .mem_reads
                    .iter()
                    .map(|m| (m.idx, m.addr, m.size)),
                start,
                size,
            ),
        )
    };
    let (writers_before, writers_after) = split_around_cursor(&writers, q.cursor, q.limit);
    let (readers_before, readers_after) = split_around_cursor(&readers, q.cursor, q.limit);
    TouchingRangeResponse {
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
    }
}

#[derive(Debug, Deserialize)]
pub struct TouchingAddrQuery {
    pub addr: String,
    #[serde(default)]
    pub cursor: usize,
    #[serde(default = "default_addr_limit")]
    pub limit: usize,
    #[serde(default)]
    pub with_bytes: bool,
}

fn default_addr_limit() -> usize {
    30
}

#[derive(Debug, Serialize, Clone)]
pub struct TouchingAddrEntry {
    pub idx: usize,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte: Option<u8>,
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
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || idxs_touching_addr_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "idxs touching addr worker failed: {err}");
                TouchingAddrResponse {
                    status: "error",
                    addr: String::new(),
                    cursor: None,
                    before: Vec::new(),
                    after: Vec::new(),
                    total_before: 0,
                    total_after: 0,
                }
            }),
    )
}

fn idxs_touching_addr_response(
    inner: &crate::state::AppStateInner,
    q: TouchingAddrQuery,
) -> TouchingAddrResponse {
    let addr = parse_int(&q.addr).unwrap_or(0);
    let mem = if q.with_bytes {
        Some(inner.memshadow())
    } else {
        inner.memshadow_if_ready()
    };
    let mut entries: Vec<TouchingAddrEntry> = if let Some(mem) = mem {
        touching_addr_entries_from_memshadow(mem, addr, q.with_bytes)
    } else {
        touching_addr_entries_from_index(inner, addr)
    };
    entries.sort_by_key(|e| e.idx);
    let cut = entries.partition_point(|e| e.idx < q.cursor);
    let limit = effective_touch_limit(q.limit);
    let before_start = cut.saturating_sub(limit);
    let mut before = entries[before_start..cut].to_vec();
    before.reverse();
    let after = entries[cut..entries.len().min(cut + limit)].to_vec();
    TouchingAddrResponse {
        status: "ready",
        addr: q.addr,
        cursor: Some(q.cursor),
        before,
        after,
        total_before: cut,
        total_after: entries.len().saturating_sub(cut),
    }
}

fn touching_addr_entries_from_memshadow(
    mem: &tracemiku_core::prelude::MemShadow,
    addr: u64,
    include_byte: bool,
) -> Vec<TouchingAddrEntry> {
    mem.bytes
        .get(&addr)
        .map(|events| {
            events
                .iter()
                .filter_map(|ev| {
                    let kind = if ev.kind == "r" {
                        "r"
                    } else if ev.kind == "w" || ev.kind == "x" {
                        "w"
                    } else {
                        return None;
                    };
                    Some(TouchingAddrEntry {
                        idx: ev.idx,
                        kind,
                        byte: include_byte.then_some(ev.byte),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn touching_addr_entries_from_index(
    inner: &crate::state::AppStateInner,
    addr: u64,
) -> Vec<TouchingAddrEntry> {
    inner
        .index
        .mem_writes
        .iter()
        .filter(|m| touches_addr(m.addr, m.size, addr))
        .map(|m| TouchingAddrEntry {
            idx: m.idx,
            kind: "w",
            byte: None,
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
                    byte: None,
                }),
        )
        .collect()
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
    pub status: &'static str,
    pub pattern: String,
    pub since_idx: isize,
    pub count: usize,
    pub returned: usize,
    pub truncated: bool,
    pub hits: Vec<MemPatternHit>,
}

pub async fn find_mem_pattern_handler(
    State(state): State<AppState>,
    Query(q): Query<FindMemPatternQuery>,
) -> Json<FindMemPatternResponse> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || find_mem_pattern_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "find mem pattern worker failed: {err}");
                FindMemPatternResponse {
                    status: "error",
                    pattern: String::new(),
                    since_idx: -1,
                    count: 0,
                    returned: 0,
                    truncated: false,
                    hits: Vec::new(),
                }
            }),
    )
}

fn find_mem_pattern_response(
    inner: &crate::state::AppStateInner,
    q: FindMemPatternQuery,
) -> FindMemPatternResponse {
    let pattern = parse_hex_bytes(&q.bytes_hex).unwrap_or_default();
    let cursor = if q.since >= 0 {
        q.since as u64
    } else {
        u64::MAX
    };
    let max = effective_pattern_max(q.max);
    let mut count = 0usize;
    let mut hits = Vec::new();
    if !pattern.is_empty() {
        let mem = match inner.memshadow_ready_or_block_if_idle() {
            Ok(mem) => mem,
            Err(status) => {
                return FindMemPatternResponse {
                    status,
                    pattern: pattern.iter().map(|b| format!("{b:02x}")).collect(),
                    since_idx: q.since,
                    count: 0,
                    returned: 0,
                    truncated: false,
                    hits,
                };
            }
        };
        for &addr in mem.bytes.keys() {
            let mut first_idx: Option<usize> = None;
            let mut matched = true;
            for (offset, want) in pattern.iter().enumerate() {
                let (byte, _kind, idx) = mem.byte_at(addr + offset as u64, cursor);
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
            count += 1;
            if hits.len() < max {
                hits.push(MemPatternHit {
                    addr: format!("{addr:#x}"),
                    first_idx,
                });
            }
        }
    }
    let returned = hits.len();
    FindMemPatternResponse {
        status: "ready",
        pattern: pattern.iter().map(|b| format!("{b:02x}")).collect(),
        since_idx: q.since,
        count,
        returned,
        truncated: returned < count,
        hits,
    }
}

fn effective_pattern_max(raw: usize) -> usize {
    if raw == 0 {
        MAX_PATTERN_HITS
    } else {
        raw.min(MAX_PATTERN_HITS)
    }
}

fn parse_int(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

fn parse_optional_int(
    name: &str,
    value: &Option<String>,
) -> Result<Option<u64>, (StatusCode, String)> {
    let Some(raw) = value.as_deref() else {
        return Ok(None);
    };
    parse_int(raw).map(Some).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("bad {name}, expected decimal or hex: {raw:?}"),
        )
    })
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

fn matches_addr_filter(addr: u64, size: u32, addr_lo: Option<u64>, addr_hi: Option<u64>) -> bool {
    match (addr_lo, addr_hi) {
        (Some(lo), Some(hi)) => hi > lo && overlaps(addr, size, lo, hi.saturating_sub(lo)),
        (Some(lo), None) => addr >= lo,
        (None, Some(hi)) => addr < hi,
        (None, None) => true,
    }
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

fn touching_range_idxs_from_memshadow(
    mem: &tracemiku_core::memshadow::MemShadow,
    start: u64,
    size: u64,
) -> (Vec<usize>, Vec<usize>) {
    let mut writers = Vec::new();
    let mut readers = Vec::new();
    let end = start.saturating_add(size);
    for addr in start..end {
        let Some(events) = mem.bytes.get(&addr) else {
            continue;
        };
        for ev in events {
            if ev.kind == "r" {
                readers.push(ev.idx);
            } else if ev.kind == "w" || ev.kind == "x" {
                writers.push(ev.idx);
            }
        }
    }
    writers.sort_unstable();
    writers.dedup();
    readers.sort_unstable();
    readers.dedup();
    (writers, readers)
}

fn split_around_cursor(idxs: &[usize], cursor: usize, limit: usize) -> (Vec<usize>, Vec<usize>) {
    let limit = effective_touch_limit(limit);
    let cut = idxs.partition_point(|&idx| idx < cursor);
    let before_start = cut.saturating_sub(limit);
    let mut before = idxs[before_start..cut].to_vec();
    before.reverse();
    let after = idxs[cut..idxs.len().min(cut + limit)].to_vec();
    (before, after)
}

#[cfg(test)]
mod tests {
    use super::{effective_touch_limit, MAX_TOUCHING_IDXS_RETURNED};

    #[test]
    fn effective_touch_limit_caps_extreme_requests() {
        assert_eq!(effective_touch_limit(0), 0);
        assert_eq!(effective_touch_limit(60), 60);
        assert_eq!(
            effective_touch_limit(usize::MAX),
            MAX_TOUCHING_IDXS_RETURNED
        );
    }
}

fn source_reg_for_write_at(
    decoded: &DecodedInsn,
    record: &Record,
    dst_addr: u64,
) -> Option<String> {
    let op = decoded
        .mem_op
        .iter()
        .find(|op| op.is_write && addr_of(record, op) == dst_addr)
        .or_else(|| decoded.mem_op.iter().find(|op| op.is_write))?;
    if !op.src_reg.is_empty() {
        return Some(op.src_reg.clone());
    }
    decoded
        .regs_use
        .iter()
        .find(|reg| reg.as_str() != op.base.as_str() && reg.as_str() != op.idx.as_str())
        .cloned()
}

fn primary_base(meta: &TraceMeta) -> Option<u64> {
    meta.module.as_ref().and_then(|m| parse_int(&m.base))
}
