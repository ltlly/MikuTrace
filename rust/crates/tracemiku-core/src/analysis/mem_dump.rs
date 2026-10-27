//! 读取指定时刻的内存字节与完整度。

use super::AnalysisError;
use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;

const DEFAULT_MEM_DUMP_BYTES: usize = 128;
const MAX_MEM_DUMP_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
pub struct MemDumpQuery {
    /// 运行时地址；省略时使用 so/off 定位。
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub so: Option<String>,
    #[serde(default)]
    pub off: Option<String>,
    #[serde(default = "default_count")]
    pub count: usize,
    #[serde(default)]
    pub at: Option<u64>,
    #[serde(default)]
    pub compare_at: Option<u64>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison: Option<MemComparison>,
}

#[derive(Debug, Serialize)]
pub struct MemComparison {
    pub at: u64,
    pub byte: Option<u8>,
    pub kind: &'static str,
    pub src_idx: Option<usize>,
    /// unknown 表示至少一个时刻没有观测值，不能宣称已知变化。
    pub change: &'static str,
}

#[derive(Debug, Serialize)]
pub struct MemDumpResponse {
    pub status: &'static str,
    pub addr: String,
    pub count: usize,
    pub at: Option<u64>,
    pub requested_count: usize,
    pub truncated: bool,
    pub observed_count: usize,
    pub completeness: f64,
    pub bytes: Vec<MemDumpByte>,
}

pub fn mem_dump(
    state: &AnalysisContext,
    mut q: MemDumpQuery,
) -> Result<MemDumpResponse, AnalysisError> {
    q.addr = format!(
        "{:#x}",
        super::resolve::memory_address(state, &q.addr, q.so.as_deref(), q.off.as_deref())?
    );
    let inner = state.inner.clone();
    mem_dump_response(&inner, q)
}

fn mem_dump_response(
    inner: &crate::analysis::context::AnalysisData,
    q: MemDumpQuery,
) -> Result<MemDumpResponse, AnalysisError> {
    let start = crate::address_parse::parse_address(&q.addr)
        .map_err(|err| AnalysisError::invalid(err.to_string()))?;
    if q.count == 0 {
        return Err(AnalysisError::invalid("count must be positive"));
    }
    let count = effective_count(q.count);
    start
        .checked_add(count as u64 - 1)
        .ok_or_else(|| AnalysisError::invalid("address range overflows u64"))?;
    for at in [q.at, q.compare_at].into_iter().flatten() {
        if at >= inner.trace.len() as u64 {
            return Err(AnalysisError::invalid("memory time is outside trace"));
        }
    }
    let mem = inner.memshadow()?;
    let mut bytes = Vec::with_capacity(count);
    let at = q.at.unwrap_or(u64::MAX);
    for i in 0..count {
        let a = start + i as u64;
        let (byte, kind, src) = mem.byte_at(a, at);
        bytes.push(MemDumpByte {
            addr: format!("{a:#x}"),
            byte,
            kind,
            src_idx: src,
            comparison: q.compare_at.map(|at| {
                let (previous, kind, src_idx) = mem.byte_at(a, at);
                let change = match (byte, previous) {
                    (Some(a), Some(b)) if a == b => "unchanged",
                    (Some(_), Some(_)) => "changed",
                    _ => "unknown",
                };
                MemComparison {
                    at,
                    byte: previous,
                    kind,
                    src_idx,
                    change,
                }
            }),
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
        at: q.at,
        requested_count: q.count,
        truncated: q.count > count,
        observed_count,
        completeness,
        bytes,
    })
}

impl Default for MemDumpQuery {
    fn default() -> Self {
        Self {
            addr: Default::default(),
            so: None,
            off: None,
            count: default_count(),
            at: Default::default(),
            compare_at: None,
        }
    }
}

/// 文件导出只接受完整已知区间，避免把填充值误写成运行时事实。
pub fn export_bytes(dump: &MemDumpResponse) -> Result<Vec<u8>, AnalysisError> {
    if dump.truncated {
        return Err(AnalysisError::limit("memory export exceeds 4096 bytes"));
    }
    dump.bytes
        .iter()
        .map(|b| {
            b.byte
                .ok_or_else(|| AnalysisError::invalid("memory export contains unknown bytes"))
        })
        .collect()
}
