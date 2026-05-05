//! GET /api/mem-dump — hex dump of MemShadow at addr.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

const DEFAULT_MEM_DUMP_BYTES: usize = 128;
const MAX_MEM_DUMP_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
pub struct MemDumpQuery {
    /// Hex string ("0x7000") — Python accepts this form too.
    pub addr: String,
    #[serde(default = "default_count")]
    pub count: usize,
}

fn default_count() -> usize {
    DEFAULT_MEM_DUMP_BYTES
}

fn effective_count(raw: usize) -> usize {
    raw.clamp(1, MAX_MEM_DUMP_BYTES)
}

#[derive(Debug, Serialize)]
pub struct MemDumpByte {
    pub addr: String,
    pub byte: Option<u8>,
    pub kind: &'static str,
    pub src_idx: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct MemDumpResponse {
    pub status: &'static str,
    pub addr: String,
    pub count: usize,
    pub bytes: Vec<MemDumpByte>,
}

pub async fn mem_dump_handler(
    State(state): State<AppState>,
    Query(q): Query<MemDumpQuery>,
) -> Result<Json<MemDumpResponse>, axum::http::StatusCode> {
    let inner = state.inner.clone();
    tokio::task::spawn_blocking(move || mem_dump_response(&inner, q))
        .await
        .unwrap_or(Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR))
        .map(Json)
}

fn mem_dump_response(
    inner: &crate::state::AppStateInner,
    q: MemDumpQuery,
) -> Result<MemDumpResponse, axum::http::StatusCode> {
    let stripped = q.addr.trim_start_matches("0x").trim_start_matches("0X");
    let start =
        u64::from_str_radix(stripped, 16).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    let count = effective_count(q.count);
    let mem = match inner.memshadow_ready_or_block_if_idle() {
        Ok(mem) => mem,
        Err(status) => {
            return Ok(MemDumpResponse {
                status,
                addr: q.addr,
                count,
                bytes: Vec::new(),
            });
        }
    };
    let mut bytes = Vec::with_capacity(count);
    for i in 0..count {
        let a = start + i as u64;
        let (byte, kind, src) = mem.byte_at(a, u64::MAX);
        bytes.push(MemDumpByte {
            addr: format!("{a:#x}"),
            byte,
            kind,
            src_idx: src,
        });
    }
    Ok(MemDumpResponse {
        status: "ready",
        addr: q.addr,
        count,
        bytes,
    })
}
