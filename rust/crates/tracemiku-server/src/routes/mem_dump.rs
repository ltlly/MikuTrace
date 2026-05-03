//! GET /api/mem-dump — hex dump of MemShadow at addr.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct MemDumpQuery {
    /// Hex string ("0x7000") — Python accepts this form too.
    pub addr: String,
    #[serde(default = "default_count")]
    pub count: usize,
}

fn default_count() -> usize {
    256
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
    let stripped = q.addr.trim_start_matches("0x").trim_start_matches("0X");
    let start =
        u64::from_str_radix(stripped, 16).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    let mem = &state.inner.memshadow;
    let mut bytes = Vec::with_capacity(q.count);
    for i in 0..q.count {
        let a = start + i as u64;
        let (byte, kind, src) = mem.byte_at(a, u64::MAX);
        bytes.push(MemDumpByte {
            addr: format!("{a:#x}"),
            byte,
            kind,
            src_idx: src,
        });
    }
    Ok(Json(MemDumpResponse {
        status: "ready",
        addr: q.addr,
        count: q.count,
        bytes,
    }))
}
