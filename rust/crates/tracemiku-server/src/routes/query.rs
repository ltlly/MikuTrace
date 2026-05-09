//! GET /api/query
//!
//! Small structured query surface for the web command palette. This is not SQL:
//! each kind maps to a bounded, typed trace index lookup so interactive queries
//! stay predictable and can be promoted into richer UI panels later.

use std::io::BufRead;

use axum::extract::{Query, State};
use axum::Json;
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::jni_scan::parse_int;
use crate::state::AppState;

const DEFAULT_LIMIT: usize = 200;
const MAX_LIMIT: usize = 5_000;

#[derive(Debug, Deserialize)]
pub struct TraceQuery {
    #[serde(default = "default_kind")]
    pub kind: String,
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub idx: Option<usize>,
    #[serde(default)]
    pub reg: Option<String>,
    #[serde(default)]
    pub addr: Option<String>,
    #[serde(default = "default_len")]
    pub len: u64,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_kind() -> String {
    "records".to_string()
}

fn default_len() -> u64 {
    1
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

#[derive(Debug, Serialize)]
pub struct TraceQueryResponse {
    pub status: &'static str,
    pub kind: String,
    pub q: String,
    pub count: usize,
    pub returned: usize,
    pub truncated: bool,
    pub max_used: usize,
    pub rows: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub async fn query_handler(
    State(state): State<AppState>,
    Query(q): Query<TraceQuery>,
) -> Json<TraceQueryResponse> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || query_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "query worker failed: {err}");
                TraceQueryResponse {
                    status: "error",
                    kind: String::new(),
                    q: String::new(),
                    count: 0,
                    returned: 0,
                    truncated: false,
                    max_used: 0,
                    rows: Vec::new(),
                    note: Some("query worker failed".to_string()),
                }
            }),
    )
}

fn query_response(inner: &crate::state::AppStateInner, q: TraceQuery) -> TraceQueryResponse {
    let limit = q.limit.clamp(1, MAX_LIMIT);
    let kind = q.kind.trim().to_ascii_lowercase();
    match kind.as_str() {
        "records" | "asm" => query_records(inner, q, limit),
        "regs" | "reg" => query_regs(inner, q, limit),
        "mem" | "memory" => query_mem(inner, q, limit, None),
        "reads" | "read" | "readers" => query_mem(inner, q, limit, Some("read")),
        "writes" | "write" | "writers" => query_mem(inner, q, limit, Some("write")),
        "functions" | "func" | "fn" => query_functions(inner, q, limit),
        "strings" | "string" => query_strings(inner, q, limit),
        "jni" | "jni-events" | "jni-calls" => query_jni(inner, q, limit),
        "provenance" | "prov" => query_provenance(inner, q, limit),
        _ => TraceQueryResponse {
            status: "error",
            kind,
            q: q.q,
            count: 0,
            returned: 0,
            truncated: false,
            max_used: limit,
            rows: Vec::new(),
            note: Some("unknown query kind".to_string()),
        },
    }
}

fn query_records(
    inner: &crate::state::AppStateInner,
    q: TraceQuery,
    limit: usize,
) -> TraceQueryResponse {
    let needle = q.q.trim();
    let re = RegexBuilder::new(needle)
        .case_insensitive(true)
        .build()
        .ok();
    let mut count = 0usize;
    let mut rows = Vec::new();
    for idx in 0..inner.trace.len() {
        let record = inner.trace.record(idx);
        let decoded = tracemiku_core::disasm::decode(record.pc, record.inst);
        let asm = format!("{} {}", decoded.mnemonic, decoded.op_str)
            .trim()
            .to_string();
        let (func_name, off) = inner.symbols.lookup(record.pc);
        let has_func = func_name != "?";
        let func = has_func.then_some(func_name);
        let text = format!("{} {} {}", record.pc, func.as_deref().unwrap_or(""), asm);
        if !matches_query(needle, re.as_ref(), &text) {
            continue;
        }
        count += 1;
        if rows.len() < limit {
            rows.push(json!({
                "idx": idx,
                "pc": format!("{:#x}", record.pc),
                "rel": inner.modules.relative_offset(record.pc).map(|off| format!("{off:#x}")),
                "func": func,
                "off": has_func.then_some(format!("{off:#x}")),
                "asm": asm,
                "kind": if decoded.is_call { "call" } else if decoded.is_ret { "ret" } else if decoded.is_branch { "branch" } else { "insn" },
            }));
        }
    }
    finish("records", q.q, limit, count, rows, None)
}

fn query_regs(
    inner: &crate::state::AppStateInner,
    q: TraceQuery,
    limit: usize,
) -> TraceQueryResponse {
    let reg = q.reg.clone().unwrap_or_else(|| q.q.trim().to_string());
    if reg.is_empty() {
        return finish(
            "regs",
            q.q,
            limit,
            0,
            Vec::new(),
            Some("missing reg".to_string()),
        );
    }
    let defs = inner.index.reg_defs.get(&reg).cloned().unwrap_or_default();
    let uses = inner.index.reg_uses.get(&reg).cloned().unwrap_or_default();
    let cursor = q.idx.unwrap_or(0);
    let mut candidates = Vec::new();
    for idx in defs {
        candidates.push((idx, "def"));
    }
    for idx in uses {
        candidates.push((idx, "use"));
    }
    candidates.sort_by_key(|(idx, kind)| (idx.abs_diff(cursor), *idx, *kind));
    let count = candidates.len();
    let rows = candidates
        .into_iter()
        .take(limit)
        .map(|(idx, access)| record_row(inner, idx, json!({ "access": access, "reg": reg })))
        .collect();
    finish("regs", q.q, limit, count, rows, None)
}

fn query_mem(
    inner: &crate::state::AppStateInner,
    q: TraceQuery,
    limit: usize,
    access_filter: Option<&'static str>,
) -> TraceQueryResponse {
    let Some(addr) = q
        .addr
        .as_deref()
        .and_then(parse_int)
        .or_else(|| parse_int(&q.q))
    else {
        return finish(
            "mem",
            q.q,
            limit,
            0,
            Vec::new(),
            Some("missing addr".to_string()),
        );
    };
    let size = q.len.max(1);
    let cursor = q.idx.unwrap_or(0);
    let mut candidates = Vec::new();
    for read in &inner.index.mem_reads {
        if ranges_overlap(read.addr, read.size as u64, addr, size) {
            candidates.push((read.idx, "read", read.addr, read.size));
        }
    }
    for write in &inner.index.mem_writes {
        if ranges_overlap(write.addr, write.size as u64, addr, size) {
            candidates.push((write.idx, "write", write.addr, write.size));
        }
    }
    candidates
        .sort_by_key(|(idx, access, addr, _size)| (idx.abs_diff(cursor), *idx, *access, *addr));
    if let Some(want) = access_filter {
        candidates.retain(|(_, access, _, _)| *access == want);
    }
    let count = candidates.len();
    let rows = candidates
        .into_iter()
        .take(limit)
        .map(|(idx, access, touched_addr, touched_size)| {
            record_row(
                inner,
                idx,
                json!({
                    "access": access,
                    "addr": format!("{touched_addr:#x}"),
                    "size": touched_size,
                }),
            )
        })
        .collect();
    let kind = match access_filter {
        Some("read") => "reads",
        Some("write") => "writes",
        _ => "mem",
    };
    finish(kind, q.q, limit, count, rows, None)
}

fn query_functions(
    inner: &crate::state::AppStateInner,
    q: TraceQuery,
    limit: usize,
) -> TraceQueryResponse {
    let needle = q.q.trim().to_ascii_lowercase();
    let mut matches = inner
        .function_index
        .entries
        .iter()
        .filter(|entry| needle.is_empty() || entry.name.to_ascii_lowercase().contains(&needle))
        .collect::<Vec<_>>();
    matches.sort_by(|a, b| {
        b.records
            .cmp(&a.records)
            .then_with(|| b.blocks.cmp(&a.blocks))
            .then_with(|| a.name.cmp(&b.name))
    });
    let count = matches.len();
    let rows = matches
        .into_iter()
        .take(limit)
        .map(|entry| {
            json!({
                "id": entry.id.as_str(),
                "name": entry.name.as_str(),
                "source": entry.source.as_str(),
                "entry_pc": entry.entry_pc.map(|pc| format!("{pc:#x}")),
                "blocks": entry.blocks,
                "records": entry.records,
                "trace_ir_id": entry.trace_ir_id.as_deref(),
                "bn_start": entry.bn_start.map(|pc| format!("{pc:#x}")),
            })
        })
        .collect();
    finish("functions", q.q, limit, count, rows, None)
}

fn query_strings(
    inner: &crate::state::AppStateInner,
    q: TraceQuery,
    limit: usize,
) -> TraceQueryResponse {
    let Some(mem) = inner.memshadow_if_ready() else {
        return TraceQueryResponse {
            status: "loading",
            kind: "strings".to_string(),
            q: q.q,
            count: 0,
            returned: 0,
            truncated: false,
            max_used: limit,
            rows: Vec::new(),
            note: Some("memory index loading".to_string()),
        };
    };
    let needle = (!q.q.trim().is_empty()).then(|| q.q.trim().to_ascii_lowercase());
    let mut count = 0usize;
    let mut rows = Vec::new();
    let mut run_start: Option<u64> = None;
    let mut run = Vec::<u8>::new();
    let mut prev_addr: Option<u64> = None;
    for (&addr, events) in &mem.bytes {
        if prev_addr.is_some_and(|prev| addr != prev + 1) {
            flush_query_string(
                needle.as_deref(),
                limit,
                &mut count,
                &mut rows,
                &mut run_start,
                &mut run,
            );
        }
        let byte = events.last().map(|event| event.byte).unwrap_or(0);
        if (32..127).contains(&byte) {
            if run_start.is_none() {
                run_start = Some(addr);
            }
            run.push(byte);
        } else {
            flush_query_string(
                needle.as_deref(),
                limit,
                &mut count,
                &mut rows,
                &mut run_start,
                &mut run,
            );
        }
        prev_addr = Some(addr);
    }
    flush_query_string(
        needle.as_deref(),
        limit,
        &mut count,
        &mut rows,
        &mut run_start,
        &mut run,
    );
    finish("strings", q.q, limit, count, rows, None)
}

fn query_jni(
    inner: &crate::state::AppStateInner,
    q: TraceQuery,
    limit: usize,
) -> TraceQueryResponse {
    let needle = q.q.trim();
    let scan = inner.jni_calls();
    let mut count = 0usize;
    let mut rows = Vec::new();
    for call in &scan.calls {
        let args_text = call.args_map().into_values().collect::<Vec<_>>().join(" ");
        let text = format!("{} {} {}", call.jni_fn, call.func_name, args_text);
        if !matches_query(needle, None, &text) {
            continue;
        }
        count += 1;
        if rows.len() < limit {
            rows.push(json!({
                "type": "call",
                "idx": call.idx,
                "pc": format!("{:#x}", call.pc),
                "rel": call.rel.map(|rel| format!("{rel:#x}")),
                "func": call.func_display(),
                "jni_fn": call.jni_fn.as_str(),
                "vtable_offset": format!("{:#x}", call.vtable_offset),
                "args": call.args_map(),
            }));
        }
    }

    let path = inner.trace_dir.join("jni_hooks.jsonl");
    if let Ok(file) = std::fs::File::open(path) {
        let reader = std::io::BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let Ok(value) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let id = value.get("id").and_then(Value::as_str).unwrap_or("");
            let text = format!("{id} {value}");
            if !matches_query(needle, None, &text) {
                continue;
            }
            count += 1;
            if rows.len() < limit {
                rows.push(json!({
                    "type": "event",
                    "idx": value.get("trace_idx").and_then(Value::as_u64),
                    "id": id,
                    "event": value,
                }));
            }
        }
    }

    finish("jni", q.q, limit, count, rows, None)
}

fn query_provenance(
    inner: &crate::state::AppStateInner,
    q: TraceQuery,
    limit: usize,
) -> TraceQueryResponse {
    let Some(addr) = q
        .addr
        .as_deref()
        .and_then(parse_int)
        .or_else(|| parse_int(&q.q))
    else {
        return finish(
            "provenance",
            q.q,
            limit,
            0,
            Vec::new(),
            Some("missing addr".to_string()),
        );
    };
    let len = q.len.max(1).min(limit as u64);
    let mut rows = Vec::new();
    for offset in 0..len {
        let a = addr.saturating_add(offset);
        let writers = inner
            .index
            .mem_writes
            .iter()
            .filter(|w| ranges_overlap(w.addr, w.size as u64, a, 1))
            .map(|w| w.idx)
            .take(16)
            .collect::<Vec<_>>();
        let readers = inner
            .index
            .mem_reads
            .iter()
            .filter(|r| ranges_overlap(r.addr, r.size as u64, a, 1))
            .map(|r| r.idx)
            .take(16)
            .collect::<Vec<_>>();
        rows.push(json!({
            "addr": format!("{a:#x}"),
            "writers": writers,
            "readers": readers,
        }));
    }
    let count = rows.len();
    finish("provenance", q.q, limit, count, rows, None)
}

fn record_row(inner: &crate::state::AppStateInner, idx: usize, extra: Value) -> Value {
    let record = inner.trace.record(idx);
    let decoded = tracemiku_core::disasm::decode(record.pc, record.inst);
    let (func_name, off) = inner.symbols.lookup(record.pc);
    let has_func = func_name != "?";
    json!({
        "idx": idx,
        "pc": format!("{:#x}", record.pc),
        "rel": inner.modules.relative_offset(record.pc).map(|off| format!("{off:#x}")),
        "func": has_func.then_some(func_name),
        "off": has_func.then_some(format!("{off:#x}")),
        "asm": format!("{} {}", decoded.mnemonic, decoded.op_str).trim().to_string(),
        "extra": extra,
    })
}

fn flush_query_string(
    needle: Option<&str>,
    limit: usize,
    count: &mut usize,
    rows: &mut Vec<Value>,
    run_start: &mut Option<u64>,
    run: &mut Vec<u8>,
) {
    let Some(addr) = *run_start else {
        return;
    };
    if run.len() >= 4 {
        let text = String::from_utf8_lossy(run).into_owned();
        if needle.map_or(true, |needle| text.to_ascii_lowercase().contains(needle)) {
            *count += 1;
            if rows.len() < limit {
                rows.push(json!({
                    "addr": format!("{addr:#x}"),
                    "len": text.len(),
                    "str": text,
                }));
            }
        }
    }
    *run_start = None;
    run.clear();
}

fn matches_query(needle: &str, re: Option<&regex::Regex>, text: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    re.map_or_else(
        || {
            text.to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
        },
        |re| re.is_match(text),
    )
}

fn ranges_overlap(a: u64, a_len: u64, b: u64, b_len: u64) -> bool {
    let a_end = a.saturating_add(a_len.max(1));
    let b_end = b.saturating_add(b_len.max(1));
    a < b_end && b < a_end
}

fn finish(
    kind: &str,
    q: String,
    limit: usize,
    count: usize,
    rows: Vec<Value>,
    note: Option<String>,
) -> TraceQueryResponse {
    TraceQueryResponse {
        status: "ready",
        kind: kind.to_string(),
        q,
        count,
        returned: rows.len(),
        truncated: rows.len() < count,
        max_used: limit,
        rows,
        note,
    }
}
