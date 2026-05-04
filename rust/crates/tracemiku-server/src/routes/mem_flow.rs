//! GET /api/mem-flow.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::*;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct MemFlowQuery {
    pub addr: String,
    #[serde(default = "default_count")]
    pub count: usize,
    pub idx_lo: Option<usize>,
    pub idx_hi: Option<usize>,
    #[serde(default = "default_events_per_byte")]
    pub events_per_byte: usize,
    #[serde(default)]
    pub writers_only: bool,
    #[serde(default)]
    pub readers_only: bool,
}

fn default_count() -> usize {
    8
}

fn default_events_per_byte() -> usize {
    10
}

#[derive(Debug, Serialize)]
pub struct MemFlowEvent {
    pub idx: usize,
    pub byte: u8,
    pub kind: &'static str,
    pub pc: String,
    pub rel: Option<String>,
    pub func: Option<String>,
    pub asm: String,
}

#[derive(Debug, Serialize)]
pub struct MemFlowByte {
    pub addr: String,
    pub events: Vec<MemFlowEvent>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct MemFlowResponse {
    pub addr: String,
    pub count: usize,
    pub bytes: Vec<MemFlowByte>,
}

pub async fn mem_flow_handler(
    State(state): State<AppState>,
    Query(q): Query<MemFlowQuery>,
) -> Result<Json<MemFlowResponse>, StatusCode> {
    let inner = state.inner.clone();
    tokio::task::spawn_blocking(move || mem_flow_response(&inner, q))
        .await
        .unwrap_or(Err(StatusCode::INTERNAL_SERVER_ERROR))
        .map(Json)
}

fn mem_flow_response(
    inner: &crate::state::AppStateInner,
    q: MemFlowQuery,
) -> Result<MemFlowResponse, StatusCode> {
    let start = parse_int(&q.addr).ok_or(StatusCode::BAD_REQUEST)?;
    let count = q.count.max(1);
    let cap = q.events_per_byte;
    let kind_filter = if q.writers_only {
        Some(("w", "x"))
    } else if q.readers_only {
        Some(("r", "r"))
    } else {
        None
    };
    let base = primary_base(&inner.meta);
    let mem = inner.memshadow();
    let mut bytes = Vec::with_capacity(count);
    for offset in 0..count {
        let addr = start + offset as u64;
        let raw = mem.bytes.get(&addr).map(Vec::as_slice).unwrap_or(&[]);
        let mut events = Vec::new();
        for ev in raw {
            if q.idx_lo.is_some_and(|lo| ev.idx < lo) {
                continue;
            }
            if q.idx_hi.is_some_and(|hi| ev.idx >= hi) {
                continue;
            }
            if kind_filter.is_some_and(|(a, b)| ev.kind != a && ev.kind != b) {
                continue;
            }
            let record = inner.trace.record(ev.idx);
            let decoded = decode(record.pc, record.inst);
            let (func_name, _) = inner.symbols.lookup(record.pc);
            events.push(MemFlowEvent {
                idx: ev.idx,
                byte: ev.byte,
                kind: ev.kind,
                pc: format!("{:#x}", record.pc),
                rel: base.map(|b| format!("{:#x}", record.pc.wrapping_sub(b))),
                func: (func_name != "?").then_some(func_name),
                asm: format!("{} {}", decoded.mnemonic, decoded.op_str)
                    .trim()
                    .to_string(),
            });
        }
        if cap > 0 && events.len() > cap {
            let keep_from = events.len() - cap;
            events = events.split_off(keep_from);
        }
        bytes.push(MemFlowByte {
            addr: format!("{addr:#x}"),
            events,
            total: raw.len(),
        });
    }
    Ok(MemFlowResponse {
        addr: q.addr,
        count,
        bytes,
    })
}

fn primary_base(meta: &TraceMeta) -> Option<u64> {
    meta.module.as_ref().and_then(|m| parse_int(&m.base))
}

fn parse_int(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}
