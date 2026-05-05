//! GET /api/string-provenance.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::MemRec;

use crate::state::AppState;

const WRITERS_CAP: usize = 20;
const MAX_LENGTH: usize = 4096;

#[derive(Debug, Deserialize)]
pub struct StringProvenanceQuery {
    pub addr: String,
    #[serde(default = "default_length")]
    pub length: usize,
}

fn default_length() -> usize {
    32
}

#[derive(Debug, Serialize)]
pub struct StringProvByte {
    pub offset: usize,
    pub addr: String,
    pub byte: Option<u8>,
    pub kind: &'static str,
    pub current_idx: Option<usize>,
    pub current_writer_idx: Option<usize>,
    pub writers: Vec<usize>,
    pub readers: Vec<usize>,
    pub writers_total: usize,
    pub readers_total: usize,
}

#[derive(Debug, Serialize)]
pub struct StringProvenanceResponse {
    pub status: &'static str,
    pub addr: String,
    pub length: usize,
    pub bytes: Vec<StringProvByte>,
}

pub async fn string_provenance_handler(
    State(state): State<AppState>,
    Query(q): Query<StringProvenanceQuery>,
) -> Result<Json<StringProvenanceResponse>, StatusCode> {
    let inner = state.inner.clone();
    tokio::task::spawn_blocking(move || string_provenance_response(&inner, q))
        .await
        .unwrap_or(Err(StatusCode::INTERNAL_SERVER_ERROR))
        .map(Json)
}

fn string_provenance_response(
    inner: &crate::state::AppStateInner,
    q: StringProvenanceQuery,
) -> Result<StringProvenanceResponse, StatusCode> {
    let start = parse_int(&q.addr).ok_or(StatusCode::BAD_REQUEST)?;
    let length = q.length.clamp(1, MAX_LENGTH);
    let memshadow = match inner.memshadow_ready_or_block_if_idle() {
        Ok(memshadow) => memshadow,
        Err(status) => {
            return Ok(StringProvenanceResponse {
                status,
                addr: q.addr,
                length,
                bytes: Vec::new(),
            });
        }
    };
    let (mut writers, mut writers_total) =
        idxs_by_byte_from_memshadow(memshadow, start, length, true);
    fill_missing_idxs_by_byte(
        &inner.index.mem_writes,
        start,
        &mut writers,
        &mut writers_total,
    );
    let (mut readers, mut readers_total) =
        idxs_by_byte_from_memshadow(memshadow, start, length, false);
    fill_missing_idxs_by_byte(
        &inner.index.mem_reads,
        start,
        &mut readers,
        &mut readers_total,
    );
    let mut bytes = Vec::with_capacity(length);
    for offset in 0..length {
        let addr = start + offset as u64;
        let (byte, kind, current_idx) = memshadow.byte_at(addr, u64::MAX);
        let current_writer_idx = memshadow.latest_write_idx_strict_before(addr, usize::MAX);
        bytes.push(StringProvByte {
            offset,
            addr: format!("{addr:#x}"),
            byte,
            kind,
            current_idx,
            current_writer_idx,
            writers: writers[offset].clone(),
            readers: readers[offset].clone(),
            writers_total: writers_total[offset],
            readers_total: readers_total[offset],
        });
    }
    Ok(StringProvenanceResponse {
        status: "ready",
        addr: q.addr,
        length,
        bytes,
    })
}

fn idxs_by_byte_from_memshadow(
    memshadow: &tracemiku_core::memshadow::MemShadow,
    start: u64,
    length: usize,
    want_writers: bool,
) -> (Vec<Vec<usize>>, Vec<usize>) {
    let mut idxs = vec![Vec::new(); length];
    let mut totals = vec![0usize; length];
    for offset in 0..length {
        let Some(events) = memshadow.bytes.get(&(start + offset as u64)) else {
            continue;
        };
        for ev in events {
            let matches_kind = if want_writers {
                ev.kind == "w" || ev.kind == "x"
            } else {
                ev.kind == "r"
            };
            if !matches_kind {
                continue;
            }
            totals[offset] += 1;
            if idxs[offset].len() < WRITERS_CAP {
                idxs[offset].push(ev.idx);
            }
        }
    }
    (idxs, totals)
}

fn fill_missing_idxs_by_byte(
    recs: &[MemRec],
    start: u64,
    idxs: &mut [Vec<usize>],
    totals: &mut [usize],
) {
    let missing = totals.iter().map(|&total| total == 0).collect::<Vec<_>>();
    if !missing.iter().any(|&is_missing| is_missing) {
        return;
    }
    let length = totals.len();
    let end = start.saturating_add(length as u64);
    for rec in recs {
        let rec_end = rec.addr.saturating_add(rec.size as u64);
        let lo = rec.addr.max(start);
        let hi = rec_end.min(end);
        if lo >= hi {
            continue;
        }
        for addr in lo..hi {
            let offset = (addr - start) as usize;
            if !missing[offset] {
                continue;
            }
            totals[offset] += 1;
            if idxs[offset].len() < WRITERS_CAP {
                idxs[offset].push(rec.idx);
            }
        }
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
