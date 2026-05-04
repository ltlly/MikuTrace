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
    pub addr: String,
    pub byte: Option<u8>,
    pub kind: &'static str,
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
    let (writers, writers_total) = covering_idxs_by_byte(&inner.index.mem_writes, start, length);
    let (readers, readers_total) = covering_idxs_by_byte(&inner.index.mem_reads, start, length);
    let mut bytes = Vec::with_capacity(length);
    for offset in 0..length {
        let addr = start + offset as u64;
        let (byte, kind, _) = memshadow.byte_at(addr, u64::MAX);
        bytes.push(StringProvByte {
            addr: format!("{addr:#x}"),
            byte,
            kind,
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

fn covering_idxs_by_byte(
    recs: &[MemRec],
    start: u64,
    length: usize,
) -> (Vec<Vec<usize>>, Vec<usize>) {
    let mut idxs = vec![Vec::new(); length];
    let mut totals = vec![0usize; length];
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
            totals[offset] += 1;
            if idxs[offset].len() < WRITERS_CAP {
                idxs[offset].push(rec.idx);
            }
        }
    }
    (idxs, totals)
}

fn parse_int(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}
