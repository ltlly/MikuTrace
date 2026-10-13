//! 读取指定时刻的内存字节与完整度。

use super::AnalysisError;
use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;

const DEFAULT_MEM_DUMP_BYTES: usize = 128;
const MAX_MEM_DUMP_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
pub struct MemDumpQuery {
    /// Hex string ("0x7000") — Python accepts this form too.
    pub addr: String,
    #[serde(default = "default_count")]
    pub count: usize,
    #[serde(default)]
    pub cursor: Option<u64>,
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
    pub cursor: Option<u64>,
    pub observed_count: usize,
    pub completeness: f64,
    pub bytes: Vec<MemDumpByte>,
}

pub fn mem_dump(
    state: &AnalysisContext,
    q: MemDumpQuery,
) -> Result<MemDumpResponse, AnalysisError> {
    let inner = state.inner.clone();
    mem_dump_response(&inner, q)
}

fn mem_dump_response(
    inner: &crate::analysis::context::AnalysisData,
    q: MemDumpQuery,
) -> Result<MemDumpResponse, AnalysisError> {
    let start = crate::address_parse::parse_address(&q.addr)
        .map_err(|err| AnalysisError::invalid(err.to_string()))?;
    let count = effective_count(q.count);
    let mem = inner.memshadow();
    let mut bytes = Vec::with_capacity(count);
    let cursor = q.cursor.unwrap_or(u64::MAX);
    for i in 0..count {
        let a = start + i as u64;
        let (byte, kind, src) = mem.byte_at(a, cursor);
        bytes.push(MemDumpByte {
            addr: format!("{a:#x}"),
            byte,
            kind,
            src_idx: src,
        });
    }
    let observed_count = bytes.iter().filter(|b| b.byte.is_some()).count();
    let completeness = if count > 0 {
        observed_count as f64 / count as f64
    } else {
        1.0
    };
    Ok(MemDumpResponse {
        status: "ready",
        addr: q.addr,
        count,
        cursor: q.cursor,
        observed_count,
        completeness,
        bytes,
    })
}

impl Default for MemDumpQuery {
    fn default() -> Self {
        Self {
            addr: Default::default(),
            count: default_count(),
            cursor: Default::default(),
        }
    }
}
