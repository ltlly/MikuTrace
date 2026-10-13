//! 检测 hash finalize 写入模式。

use super::AnalysisError;
use crate::hashfin::HashFinalizeCandidate;
use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;

#[derive(Debug, Deserialize)]
pub struct HashFinalizeQuery {
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
pub struct HashFinalizeResponse {
    pub status: &'static str,
    pub window: usize,
    pub min_size: u64,
    pub limit: usize,
    pub count: usize,
    pub returned: usize,
    pub truncated: bool,
    pub candidates: Vec<HashFinalizeCandidate>,
}

pub fn hash_finalize_detect(
    state: &AnalysisContext,
    q: HashFinalizeQuery,
) -> Result<HashFinalizeResponse, AnalysisError> {
    let inner = state.inner.clone();
    let response = hash_finalize_response(&inner, q);
    Ok(response)
}

fn hash_finalize_response(
    inner: &crate::analysis::context::AnalysisData,
    q: HashFinalizeQuery,
) -> HashFinalizeResponse {
    let limit = q.limit.min(MAX_LIMIT);
    let mem = inner.memshadow();
    let (count, candidates) = inner.hash_finalize_candidates(mem, q.window, q.min_size, limit);

    HashFinalizeResponse {
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

impl Default for HashFinalizeQuery {
    fn default() -> Self {
        Self {
            window: default_window(),
            min_size: default_min_size(),
            limit: default_limit(),
        }
    }
}
