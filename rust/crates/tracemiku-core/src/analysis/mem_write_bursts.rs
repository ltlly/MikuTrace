//! 查询按地址连续且首末记录落在指定时间窗内的写入区间。

use super::AnalysisError;
use crate::write_bursts::WriteBurstCandidate;
use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;

#[derive(Debug, Deserialize)]
pub struct WriteBurstsQuery {
    #[serde(default = "default_window")]
    pub window: usize,
    #[serde(default = "default_min_size")]
    pub min_size: u64,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_window() -> usize {
    500
}

fn default_min_size() -> u64 {
    16
}

fn default_limit() -> usize {
    500
}

const MAX_LIMIT: usize = 5_000;

#[derive(Debug, Serialize)]
pub struct WriteBurstsResponse {
    pub status: &'static str,
    pub window: usize,
    pub min_size: u64,
    pub limit: usize,
    pub count: usize,
    pub returned: usize,
    pub truncated: bool,
    pub candidates: Vec<WriteBurstCandidate>,
}

pub fn mem_write_bursts(
    state: &AnalysisContext,
    q: WriteBurstsQuery,
) -> Result<WriteBurstsResponse, AnalysisError> {
    let inner = state.inner.clone();
    let response = mem_write_bursts_response(&inner, q);
    Ok(response)
}

fn mem_write_bursts_response(
    inner: &crate::analysis::context::AnalysisData,
    q: WriteBurstsQuery,
) -> WriteBurstsResponse {
    let limit = q.limit.min(MAX_LIMIT);
    let mem = inner.memshadow();
    let (count, candidates) = inner.write_burst_candidates(mem, q.window, q.min_size, limit);

    WriteBurstsResponse {
        status: "ready",
        window: q.window,
        min_size: q.min_size,
        limit,
        count,
        returned: candidates.len(),
        truncated: candidates.len() < count,
        candidates,
    }
}

impl Default for WriteBurstsQuery {
    fn default() -> Self {
        Self {
            window: default_window(),
            min_size: default_min_size(),
            limit: default_limit(),
        }
    }
}
