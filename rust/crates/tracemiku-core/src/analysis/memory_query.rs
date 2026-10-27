//! Memory query endpoints backed by Index + MemShadow.

use super::AnalysisError;
use serde::{Deserialize, Serialize};

use crate::disasm::addr_of;
use crate::prelude::*;

use crate::analysis::context::AnalysisContext;
use crate::analysis::parse;

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
    pub size: Option<u32>,
}

fn default_before_idx() -> isize {
    -1
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)] // Found carries full write details; NotFound is the miss shape.
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
        #[serde(skip_serializing_if = "Option::is_none")]
        copy_from: Option<String>,
        writes_before: usize,
        writes_after: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        unlogged_write_gap: Option<crate::memshadow::UnloggedWriteGap>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        byte_history: Vec<serde_json::Value>,
    },
    NotFound {
        status: &'static str,
        addr: String,
        before_idx: usize,
        writes_total: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        unlogged_write_gap: Option<crate::memshadow::UnloggedWriteGap>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        byte_history: Vec<serde_json::Value>,
    },
}

pub fn last_write_of_addr(
    state: &AnalysisContext,
    q: LastWriteOfAddrQuery,
) -> Result<LastWriteOfAddrResponse, AnalysisError> {
    let Some(addr) = parse::parse_hex_u64(&q.addr) else {
        return Ok(LastWriteOfAddrResponse::NotFound {
            status: "not-found",
            addr: q.addr,
            before_idx: 0,
            writes_total: 0,
            unlogged_write_gap: None,
            byte_history: Vec::new(),
        });
    };
    let inner = state.inner.clone();
    let _ = inner.memshadow()?;
    let response = last_write_of_addr_response(&inner, q, addr);
    Ok(response)
}

fn build_byte_history(
    mem: &crate::prelude::MemShadow,
    addr: u64,
    query_size: u32,
    before: usize,
) -> (
    Option<crate::memshadow::UnloggedWriteGap>,
    Vec<serde_json::Value>,
) {
    let mut primary_gap = mem.unlogged_write_gap_before(addr, before);
    let mut byte_history = Vec::new();
    if query_size > 1 {
        let clamped_size = query_size.min(4096);
        for offset in 0..clamped_size {
            let b_addr = addr.saturating_add(offset as u64);
            let gap = mem.unlogged_write_gap_before(b_addr, before);
            if primary_gap.is_none() && gap.is_some() {
                primary_gap = gap.clone();
            }
            let mut last_write_idx = None;
            let mut last_write_byte = None;
            if let Some(evs) = mem.bytes.get(&b_addr) {
                let pos = evs.partition_point(|ev| ev.idx() < before);
                for ev in evs[..pos].iter().rev() {
                    if ev.kind == "w" || ev.kind == "x" {
                        last_write_idx = Some(ev.idx());
                        last_write_byte = Some(ev.byte);
                        break;
                    }
                }
            }
            let (obs_byte, _, _) = mem.byte_at(b_addr, before.saturating_sub(1) as u64);
            byte_history.push(serde_json::json!({
                "offset": offset,
                "addr": format!("{b_addr:#x}"),
                "last_write_idx": last_write_idx,
                "last_write_byte": last_write_byte,
                "observed_byte": obs_byte,
                "unlogged_write_gap": gap,
            }));
        }
    }
    (primary_gap, byte_history)
}

fn last_write_of_addr_response(
    inner: &crate::analysis::context::AnalysisData,
    q: LastWriteOfAddrQuery,
    addr: u64,
) -> LastWriteOfAddrResponse {
    let before = if q.before_idx >= 0 {
        (q.before_idx as usize).min(inner.trace.len())
    } else {
        inner.trace.len()
    };
    let query_size = q.size.unwrap_or(1).max(1);
    if q.with_external {
        return last_write_of_addr_response_from_memshadow(inner, q, addr, before, query_size);
    }
    let mem = inner.memshadow_if_ready().expect("MemShadow preloaded");
    let (unlogged_write_gap, byte_history) = build_byte_history(mem, addr, query_size, before);
    let mut last_seen_idx: Option<usize> = None;
    let mut writes_before = 0usize;
    let mut writes_after = 0usize;
    let mut writer_idx: Option<usize> = None;
    let mut writer_addr: Option<u64> = None;
    let mut writer_size: Option<u32> = None;
    for write in &inner.index().mem_writes {
        let touches = if query_size == 1 {
            touches_addr(write.addr, write.size, addr)
        } else {
            overlaps(write.addr, write.size, addr, u64::from(query_size))
        };
        if !touches {
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
            unlogged_write_gap,
            byte_history,
        };
    };
    let record = inner.trace.record(writer_idx);
    let decoded = decode(record.pc, record.inst);
    let (func_name, _) = inner.symbols().lookup(record.pc);
    let func = (!func_name.is_empty()).then_some(func_name);
    let src_reg = source_reg_for_write_at(&decoded, &record, addr);
    let src_value = src_reg
        .as_deref()
        .and_then(|reg| record.reg_by_name(reg))
        .or_else(|| {
            let mut val = 0u64;
            let mut any = false;
            let base = writer_addr.unwrap_or(addr);
            let limit = writer_size.unwrap_or(1).min(8) as u64;
            for o in 0..limit {
                if let Some(ev) = mem.bytes.get(&base.saturating_add(o)).and_then(|evs| {
                    evs.iter()
                        .rev()
                        .find(|e| e.idx() == writer_idx && e.kind == "w")
                }) {
                    val |= u64::from(ev.byte) << (o * 8);
                    any = true;
                }
            }
            any.then_some(val)
        })
        .map(|v| format!("{v:#x}"));

    LastWriteOfAddrResponse::Found {
        status: "found",
        addr: q.addr.clone(),
        before_idx: before,
        writer_idx,
        write_kind: "w",
        writer_pc: format!("{:#x}", record.pc),
        rel: inner
            .modules
            .relative_offset(record.pc)
            .map(|off| format!("{off:#x}")),
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
        copy_from: None,
        writes_before,
        writes_after,
        unlogged_write_gap,
        byte_history,
    }
}

fn last_write_of_addr_response_from_memshadow(
    inner: &crate::analysis::context::AnalysisData,
    q: LastWriteOfAddrQuery,
    addr: u64,
    before: usize,
    query_size: u32,
) -> LastWriteOfAddrResponse {
    let mem = inner.memshadow_if_ready().expect("MemShadow preloaded");
    let (unlogged_write_gap, byte_history) = build_byte_history(mem, addr, query_size, before);
    let mut writes_before = 0usize;
    let mut writes_after = 0usize;
    let mut writer: Option<&crate::prelude::ShadowMemRec> = None;
    let mut writer_kind = "w";
    for write in &mem.writes {
        let touches = if query_size == 1 {
            touches_addr(write.addr, write.size, addr)
        } else {
            overlaps(write.addr, write.size, addr, u64::from(query_size))
        };
        if !touches {
            continue;
        }
        if write.idx < before {
            writes_before += 1;
            writer = Some(write);
            writer_kind = mem_write_kind_at(mem, addr.max(write.addr), write.idx).unwrap_or("w");
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
            unlogged_write_gap,
            byte_history,
        };
    };
    let record = inner.trace.record(write.idx);
    let decoded = decode(record.pc, record.inst);
    let (func_name, _) = inner.symbols().lookup(record.pc);
    let func = (!func_name.is_empty()).then_some(func_name);
    let src_reg = (writer_kind != "x")
        .then(|| source_reg_for_write_at(&decoded, &record, addr))
        .flatten();
    let src_value = src_reg
        .as_deref()
        .and_then(|reg| record.reg_by_name(reg))
        .unwrap_or(write.value);
    let copy_from = mem
        .copy_source_at(addr.max(write.addr), write.idx)
        .map(|src| format!("{src:#x}"));

    LastWriteOfAddrResponse::Found {
        status: "found",
        addr: q.addr,
        before_idx: before,
        writer_idx: write.idx,
        write_kind: writer_kind,
        writer_pc: format!("{:#x}", record.pc),
        rel: inner
            .modules
            .relative_offset(record.pc)
            .map(|off| format!("{off:#x}")),
        func,
        asm: format!("{} {}", decoded.mnemonic, decoded.op_str)
            .trim()
            .to_string(),
        dst_addr: format!("{:#x}", write.addr),
        size: write.size,
        src_reg,
        src_value: Some(format!("{src_value:#x}")),
        copy_from,
        writes_before,
        writes_after,
        unlogged_write_gap,
        byte_history,
    }
}

fn mem_write_kind_at(
    mem: &crate::prelude::MemShadow,
    addr: u64,
    idx: usize,
) -> Option<&'static str> {
    mem.bytes
        .get(&addr)?
        .iter()
        .find(|ev| ev.idx() == idx && (ev.kind == "w" || ev.kind == "x"))
        .map(|ev| ev.kind.as_str())
}

#[derive(Debug, Deserialize)]
pub struct MemWritesInRangeQuery {
    pub idx_lo: usize,
    #[serde(default = "default_idx_hi")]
    pub idx_hi: isize,
    #[serde(default)]
    pub with_external: bool,
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
    pub write_kind: &'static str,
    pub pc: String,
    pub rel: Option<String>,
    pub func: Option<String>,
    pub asm: String,
    pub dst_addr: String,
    pub size: u32,
    pub src_reg: Option<String>,
    pub src_value: String,
    pub byte0: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub copy_from: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MemWritesInRangeResponse {
    pub idx_range: Vec<usize>,
    pub matched: usize,
    pub returned: usize,
    pub truncated: bool,
    pub writes: Vec<MemWriteRow>,
}

pub fn mem_writes_in_range(
    state: &AnalysisContext,
    q: MemWritesInRangeQuery,
) -> Result<MemWritesInRangeResponse, AnalysisError> {
    let inner = state.inner.clone();
    let _ = inner.memshadow()?;
    mem_writes_in_range_response(&inner, q)
}

fn mem_writes_in_range_response(
    inner: &crate::analysis::context::AnalysisData,
    q: MemWritesInRangeQuery,
) -> Result<MemWritesInRangeResponse, AnalysisError> {
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
    if q.with_external || src_byte.is_some() {
        let memshadow = inner.memshadow_if_ready().expect("MemShadow preloaded");
        return Ok(mem_writes_in_range_from_memshadow(
            inner, max, lo, hi, addr_lo, addr_hi, src_byte, memshadow,
        ));
    }

    let mut matched = 0usize;
    let mut rows = Vec::new();
    let writes_start = inner.index().mem_writes.partition_point(|w| w.idx < lo);
    let writes_end = inner.index().mem_writes.partition_point(|w| w.idx < hi);
    for write in &inner.index().mem_writes[writes_start..writes_end] {
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
            .or_else(|| {
                let op = decoded
                    .mem_op
                    .iter()
                    .find(|op| op.is_write && addr_of(&record, op) == write.addr)
                    .or_else(|| decoded.mem_op.iter().find(|op| op.is_write))?;
                crate::memshadow::value_of_write(&inner.trace, write.idx, op, &decoded)
            })
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

        let (func_name, _) = inner.symbols().lookup(record.pc);
        rows.push(MemWriteRow {
            idx: write.idx,
            write_kind: "w",
            pc: format!("{:#x}", record.pc),
            rel: inner
                .modules
                .relative_offset(record.pc)
                .map(|off| format!("{off:#x}")),
            func: (!func_name.is_empty()).then_some(func_name),
            asm: format!("{} {}", decoded.mnemonic, decoded.op_str)
                .trim()
                .to_string(),
            dst_addr: format!("{:#x}", write.addr),
            size: write.size,
            src_reg,
            src_value: format!("{src_value:#x}"),
            byte0: (src_value & 0xff) as u8,
            copy_from: None,
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
    inner: &crate::analysis::context::AnalysisData,
    max: usize,
    lo: usize,
    hi: usize,
    addr_lo: Option<u64>,
    addr_hi: Option<u64>,
    src_byte: Option<u8>,
    memshadow: &crate::prelude::MemShadow,
) -> MemWritesInRangeResponse {
    let mut matched = 0usize;
    let mut rows = Vec::new();
    let writes_start = memshadow.writes.partition_point(|w| w.idx < lo);
    let writes_end = memshadow.writes.partition_point(|w| w.idx < hi);
    for write in &memshadow.writes[writes_start..writes_end] {
        if !matches_addr_filter(write.addr, write.size, addr_lo, addr_hi) {
            continue;
        }
        if src_byte.is_some_and(|b| (write.value & 0xff) as u8 != b) {
            continue;
        }
        matched += 1;
        if rows.len() >= max {
            continue;
        }

        let record = inner.trace.record(write.idx);
        let decoded = decode(record.pc, record.inst);
        let writer_kind = mem_write_kind_at(memshadow, write.addr, write.idx).unwrap_or("w");
        let src_reg = (writer_kind != "x")
            .then(|| source_reg_for_write_at(&decoded, &record, write.addr))
            .flatten();
        let (func_name, _) = inner.symbols().lookup(record.pc);
        rows.push(MemWriteRow {
            idx: write.idx,
            write_kind: writer_kind,
            pc: format!("{:#x}", record.pc),
            rel: inner
                .modules
                .relative_offset(record.pc)
                .map(|off| format!("{off:#x}")),
            func: (!func_name.is_empty()).then_some(func_name),
            asm: format!("{} {}", decoded.mnemonic, decoded.op_str)
                .trim()
                .to_string(),
            dst_addr: format!("{:#x}", write.addr),
            size: write.size,
            src_reg,
            src_value: format!("{:#x}", write.value),
            byte0: (write.value & 0xff) as u8,
            copy_from: memshadow
                .copy_source_at(write.addr, write.idx)
                .map(|src| format!("{src:#x}")),
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

pub fn idxs_touching_range(
    state: &AnalysisContext,
    q: TouchingRangeQuery,
) -> Result<TouchingRangeResponse, AnalysisError> {
    let inner = state.inner.clone();
    let _ = inner.memshadow()?;
    let response = idxs_touching_range_response(&inner, q);
    Ok(response)
}

fn idxs_touching_range_response(
    inner: &crate::analysis::context::AnalysisData,
    q: TouchingRangeQuery,
) -> TouchingRangeResponse {
    let start = parse::parse_hex_u64(&q.addr).unwrap_or(0);
    let size = q.size.max(1);
    let (writers, readers) = touching_range_idxs_from_memshadow(
        inner.memshadow_if_ready().expect("MemShadow preloaded"),
        start,
        size,
    );
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

pub fn idxs_touching_addr(
    state: &AnalysisContext,
    q: TouchingAddrQuery,
) -> Result<TouchingAddrResponse, AnalysisError> {
    let inner = state.inner.clone();
    let _ = inner.memshadow()?;
    let response = idxs_touching_addr_response(&inner, q);
    Ok(response)
}

fn idxs_touching_addr_response(
    inner: &crate::analysis::context::AnalysisData,
    q: TouchingAddrQuery,
) -> TouchingAddrResponse {
    let addr = parse::parse_hex_u64(&q.addr).unwrap_or(0);
    let mut entries = touching_addr_entries_from_memshadow(
        inner.memshadow_if_ready().expect("MemShadow preloaded"),
        addr,
        q.with_bytes,
    );
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
    mem: &crate::prelude::MemShadow,
    addr: u64,
    include_byte: bool,
) -> Vec<TouchingAddrEntry> {
    mem.bytes
        .get(&addr)
        .map(|events| {
            events
                .iter()
                .filter_map(|ev| {
                    let kind = if ev.kind == "r" || ev.kind == "w" || ev.kind == "x" {
                        ev.kind.as_str()
                    } else {
                        return None;
                    };
                    Some(TouchingAddrEntry {
                        idx: ev.idx(),
                        kind,
                        byte: include_byte.then_some(ev.byte),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overwritten_at_idx: Option<usize>,
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

pub fn find_mem_pattern(
    state: &AnalysisContext,
    q: FindMemPatternQuery,
) -> Result<FindMemPatternResponse, AnalysisError> {
    let inner = state.inner.clone();
    let _ = inner.memshadow()?;
    let response = find_mem_pattern_response(&inner, q);
    Ok(response)
}

fn byte_ever_matches(mem: &crate::memshadow::MemShadow, addr: u64, want: u8) -> bool {
    if let Some(evs) = mem.bytes.get(&addr) {
        if evs.iter().any(|ev| ev.byte == want) {
            return true;
        }
    }
    mem.snapshot
        .as_ref()
        .and_then(|s| s.byte_at(addr))
        .is_some_and(|b| b == want)
}

fn byte_validity_intervals(
    mem: &crate::memshadow::MemShadow,
    addr: u64,
    want: u8,
) -> Vec<(usize, usize)> {
    let mut intervals = Vec::new();
    let mut current_start: Option<usize> = None;
    if mem
        .snapshot
        .as_ref()
        .and_then(|s| s.byte_at(addr))
        .is_some_and(|b| b == want)
    {
        current_start = Some(0);
    }
    if let Some(evs) = mem.bytes.get(&addr) {
        for ev in evs {
            if ev.byte == want {
                if current_start.is_none() {
                    current_start = Some(ev.idx());
                }
            } else if let Some(start) = current_start.take() {
                if start < ev.idx() {
                    intervals.push((start, ev.idx()));
                }
            }
        }
    }
    if let Some(start) = current_start {
        intervals.push((start, usize::MAX));
    }
    intervals
}

fn intersect_intervals(a: &[(usize, usize)], b: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    while i < a.len() && j < b.len() {
        let start = a[i].0.max(b[j].0);
        let end = a[i].1.min(b[j].1);
        if start < end {
            out.push((start, end));
        }
        if a[i].1 < b[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

fn overwritten_after(
    mem: &crate::memshadow::MemShadow,
    addr: u64,
    pattern: &[u8],
    after_idx: u64,
) -> Option<usize> {
    let mut earliest: Option<usize> = None;
    for (offset, &want) in pattern.iter().enumerate() {
        let b_addr = addr.saturating_add(offset as u64);
        if let Some(evs) = mem.bytes.get(&b_addr) {
            let pos = evs.partition_point(|ev| (ev.idx() as u64) <= after_idx);
            if let Some(change_ev) = evs[pos..].iter().find(|ev| ev.byte != want) {
                earliest = Some(earliest.map_or(change_ev.idx(), |old| old.min(change_ev.idx())));
            }
        }
    }
    earliest
}

fn find_mem_pattern_response(
    inner: &crate::analysis::context::AnalysisData,
    q: FindMemPatternQuery,
) -> FindMemPatternResponse {
    let pattern = parse_hex_bytes(&q.bytes_hex).unwrap_or_default();
    let max = effective_pattern_max(q.max);
    let mut count = 0usize;
    let mut hits = Vec::new();
    if !pattern.is_empty() {
        let mem = inner.memshadow_if_ready().expect("MemShadow preloaded");
        if q.since >= 0 {
            let cursor = q.since as u64;
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
                        overwritten_at_idx: overwritten_after(mem, addr, &pattern, cursor),
                    });
                }
            }
        } else {
            for &addr in mem.bytes.keys() {
                let mut all_ever_match = true;
                for (offset, &want) in pattern.iter().enumerate() {
                    if !byte_ever_matches(mem, addr.saturating_add(offset as u64), want) {
                        all_ever_match = false;
                        break;
                    }
                }
                if !all_ever_match {
                    continue;
                }
                // End-of-trace fast check to preserve min-first_idx when still present at u64::MAX
                let mut end_matched = true;
                let mut end_first_idx: Option<usize> = None;
                for (offset, want) in pattern.iter().enumerate() {
                    let (byte, _kind, idx) =
                        mem.byte_at(addr.saturating_add(offset as u64), u64::MAX);
                    if byte != Some(*want) {
                        end_matched = false;
                        break;
                    }
                    if let Some(idx) = idx {
                        end_first_idx = Some(end_first_idx.map_or(idx, |old| old.min(idx)));
                    }
                }
                let mut windows = byte_validity_intervals(mem, addr, pattern[0]);
                for (offset, &want) in pattern.iter().enumerate().skip(1) {
                    if windows.is_empty() {
                        break;
                    }
                    let next_iv =
                        byte_validity_intervals(mem, addr.saturating_add(offset as u64), want);
                    windows = intersect_intervals(&windows, &next_iv);
                }
                let matched_window = windows.into_iter().find(|&(enter_idx, _)| {
                    let candidate_idx = if end_matched {
                        end_first_idx.unwrap_or(enter_idx)
                    } else {
                        enter_idx
                    };
                    q.idx_lo
                        .is_none_or(|lo| candidate_idx >= lo || enter_idx >= lo)
                        && q.idx_hi
                            .is_none_or(|hi| candidate_idx < hi || enter_idx < hi)
                });
                let Some((enter_idx, overwrite_idx)) = matched_window else {
                    continue;
                };
                let first_idx = if end_matched && overwrite_idx == usize::MAX {
                    end_first_idx.or(Some(enter_idx))
                } else {
                    Some(enter_idx)
                };
                let overwritten_at_idx = (overwrite_idx != usize::MAX).then_some(overwrite_idx);
                count += 1;
                if hits.len() < max {
                    hits.push(MemPatternHit {
                        addr: format!("{addr:#x}"),
                        first_idx,
                        overwritten_at_idx,
                    });
                }
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

fn parse_optional_int(name: &str, value: &Option<String>) -> Result<Option<u64>, AnalysisError> {
    let Some(raw) = value.as_deref() else {
        return Ok(None);
    };
    parse::parse_hex_u64(raw).map(Some).ok_or_else(|| {
        AnalysisError::invalid(format!(
            "bad {name}, expected hexadecimal or d-prefixed decimal: {raw:?}"
        ))
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

fn touching_range_idxs_from_memshadow(
    mem: &crate::memshadow::MemShadow,
    start: u64,
    size: u64,
) -> (Vec<usize>, Vec<usize>) {
    let mut writers = Vec::new();
    let mut readers = Vec::new();
    let end = start.saturating_add(size);
    // 地址空间可以很稀疏；只遍历已观测字节，开销不随地址区间长度增长。
    for (_, events) in mem.bytes.range(start..end) {
        for ev in events {
            if ev.kind == "r" {
                readers.push(ev.idx());
            } else if ev.kind == "w" || ev.kind == "x" {
                writers.push(ev.idx());
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

fn source_reg_for_write_at(
    decoded: &DecodedInsn,
    record: &Record,
    dst_addr: u64,
) -> Option<String> {
    let op = decoded
        .mem_op
        .iter()
        .find(|op| op.is_write && touches_addr(addr_of(record, op), op.size, dst_addr))
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

impl Default for LastWriteOfAddrQuery {
    fn default() -> Self {
        Self {
            addr: Default::default(),
            before_idx: default_before_idx(),
            with_external: Default::default(),
            size: None,
        }
    }
}

impl Default for MemWritesInRangeQuery {
    fn default() -> Self {
        Self {
            idx_lo: Default::default(),
            idx_hi: default_idx_hi(),
            with_external: Default::default(),
            src_byte: Default::default(),
            addr_lo: Default::default(),
            addr_hi: Default::default(),
            max: default_writes_max(),
        }
    }
}

impl Default for TouchingRangeQuery {
    fn default() -> Self {
        Self {
            addr: Default::default(),
            size: default_size(),
            cursor: Default::default(),
            limit: default_limit(),
        }
    }
}

impl Default for TouchingAddrQuery {
    fn default() -> Self {
        Self {
            addr: Default::default(),
            cursor: Default::default(),
            limit: default_addr_limit(),
            with_bytes: Default::default(),
        }
    }
}

impl Default for FindMemPatternQuery {
    fn default() -> Self {
        Self {
            bytes_hex: Default::default(),
            since: default_since(),
            max: default_pattern_max(),
            idx_lo: Default::default(),
            idx_hi: Default::default(),
        }
    }
}
