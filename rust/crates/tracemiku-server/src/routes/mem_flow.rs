//! GET /api/mem-flow.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::*;

use crate::state::AppState;

const MAX_MEM_FLOW_BYTES: usize = 4_096;
const MAX_MEM_FLOW_EVENTS_PER_BYTE: usize = 500;
const MAX_MEM_FLOW_RETURNED_EVENTS: usize = 10_000;

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

fn effective_count(raw: usize) -> usize {
    raw.clamp(1, MAX_MEM_FLOW_BYTES)
}

fn effective_events_per_byte(raw: usize) -> usize {
    if raw == 0 {
        MAX_MEM_FLOW_EVENTS_PER_BYTE
    } else {
        raw.min(MAX_MEM_FLOW_EVENTS_PER_BYTE)
    }
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
    pub status: &'static str,
    pub addr: String,
    pub count: usize,
    pub events_returned: usize,
    pub truncated: bool,
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
    let count = effective_count(q.count);
    let cap = effective_events_per_byte(q.events_per_byte);
    let kind_filter = if q.writers_only {
        Some(("w", "x"))
    } else if q.readers_only {
        Some(("r", "r"))
    } else {
        None
    };
    let base = primary_base(&inner.meta);
    let mem = match inner.memshadow_ready_or_block_if_idle() {
        Ok(mem) => mem,
        Err(status) => {
            return Ok(MemFlowResponse {
                status,
                addr: q.addr,
                count,
                events_returned: 0,
                truncated: false,
                bytes: Vec::new(),
            });
        }
    };
    let mut bytes = Vec::with_capacity(count);
    let mut events_returned = 0;
    let mut truncated = false;
    for offset in 0..count {
        let addr = start + offset as u64;
        let raw = mem.bytes.get(&addr).map(Vec::as_slice).unwrap_or(&[]);
        let remaining_total = MAX_MEM_FLOW_RETURNED_EVENTS.saturating_sub(events_returned);
        let per_byte_limit = cap.min(remaining_total);
        let mut selected = Vec::new();
        if per_byte_limit > 0 {
            for ev in raw.iter().rev() {
                if !event_matches(ev, q.idx_lo, q.idx_hi, kind_filter) {
                    continue;
                }
                if selected.len() >= per_byte_limit {
                    truncated = true;
                    break;
                }
                selected.push(ev);
            }
        } else if !raw.is_empty() {
            truncated = true;
        }
        selected.reverse();

        let mut events = Vec::with_capacity(selected.len());
        for ev in selected {
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
            events_returned += 1;
        }
        bytes.push(MemFlowByte {
            addr: format!("{addr:#x}"),
            events,
            total: raw.len(),
        });
    }
    Ok(MemFlowResponse {
        status: "ready",
        addr: q.addr,
        count,
        events_returned,
        truncated,
        bytes,
    })
}

fn event_matches(
    ev: &ByteEvent,
    idx_lo: Option<usize>,
    idx_hi: Option<usize>,
    kind_filter: Option<(&'static str, &'static str)>,
) -> bool {
    if idx_lo.is_some_and(|lo| ev.idx < lo) {
        return false;
    }
    if idx_hi.is_some_and(|hi| ev.idx >= hi) {
        return false;
    }
    if kind_filter.is_some_and(|(a, b)| ev.kind != a && ev.kind != b) {
        return false;
    }
    true
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

#[cfg(test)]
mod tests {
    use super::{
        effective_count, effective_events_per_byte, MAX_MEM_FLOW_BYTES,
        MAX_MEM_FLOW_EVENTS_PER_BYTE,
    };

    #[test]
    fn effective_count_caps_extreme_requests() {
        assert_eq!(effective_count(0), 1);
        assert_eq!(effective_count(128), 128);
        assert_eq!(effective_count(usize::MAX), MAX_MEM_FLOW_BYTES);
    }

    #[test]
    fn effective_events_per_byte_caps_extreme_requests() {
        assert_eq!(effective_events_per_byte(0), MAX_MEM_FLOW_EVENTS_PER_BYTE);
        assert_eq!(effective_events_per_byte(30), 30);
        assert_eq!(
            effective_events_per_byte(usize::MAX),
            MAX_MEM_FLOW_EVENTS_PER_BYTE
        );
    }
}
