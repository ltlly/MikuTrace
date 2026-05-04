//! GET /api/string-provenance.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::MemRec;

use crate::state::AppState;

const WRITERS_CAP: usize = 20;

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
    let start = parse_int(&q.addr).ok_or(StatusCode::BAD_REQUEST)?;
    let mut bytes = Vec::with_capacity(q.length);
    for offset in 0..q.length {
        let addr = start + offset as u64;
        let (byte, kind, _) = state.inner.memshadow.byte_at(addr, u64::MAX);
        let writer_idxs = covering_idxs(&state.inner.index.mem_writes, addr);
        let reader_idxs = covering_idxs(&state.inner.index.mem_reads, addr);
        bytes.push(StringProvByte {
            addr: format!("{addr:#x}"),
            byte,
            kind,
            writers: writer_idxs.iter().copied().take(WRITERS_CAP).collect(),
            readers: reader_idxs.iter().copied().take(WRITERS_CAP).collect(),
            writers_total: writer_idxs.len(),
            readers_total: reader_idxs.len(),
        });
    }
    Ok(Json(StringProvenanceResponse {
        status: "ready",
        addr: q.addr,
        length: q.length,
        bytes,
    }))
}

fn covering_idxs(recs: &[MemRec], target: u64) -> Vec<usize> {
    recs.iter()
        .filter(|rec| target >= rec.addr && target < rec.addr.saturating_add(rec.size as u64))
        .map(|rec| rec.idx)
        .collect()
}

fn parse_int(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}
