//! 查询执行指定块的记录下标。
//!
//! Returns record indices whose PC falls within the block whose start_pc
//! equals the input. Uses the global pc→idxs index and walks only instruction
//! PCs inside the block, avoiding an O(trace records) scan on large traces.

use super::AnalysisError;
use crate::prelude::parse_address;
use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;

const MAX_IDXS_FOR_BLOCK_RETURNED: usize = 5_000;

#[derive(Debug, Deserialize)]
pub struct IdxsForBlockQuery {
    pub pc: String,
    #[serde(default = "default_max")]
    pub max_count: usize,
    #[serde(default = "default_near")]
    pub near: isize,
}

fn default_max() -> usize {
    200
}
fn default_near() -> isize {
    -1
}

fn effective_max_count(raw: usize) -> usize {
    raw.min(MAX_IDXS_FOR_BLOCK_RETURNED)
}

#[derive(Debug, Serialize)]
pub struct IdxsForBlockResponse {
    pub status: &'static str,
    pub block: String,
    pub idxs: Vec<usize>,
    pub truncated: bool,
    pub total: usize,
}

pub fn idxs_for_block(
    state: &AnalysisContext,
    q: IdxsForBlockQuery,
) -> Result<IdxsForBlockResponse, AnalysisError> {
    let inner = state.inner.clone();
    let response = (idxs_for_block_response(&inner, q))?;
    Ok(response)
}

fn idxs_for_block_response(
    inner: &crate::analysis::context::AnalysisData,
    q: IdxsForBlockQuery,
) -> Result<IdxsForBlockResponse, AnalysisError> {
    // Parse via the shared core parser: an invalid `pc` surfaces as a distinct
    // Reject invalid input instead of silently resolving to 0 and missing a
    // block that never existed (audit P0-1).
    let target = parse_address(&q.pc).map_err(|_| AnalysisError::invalid("invalid query"))?;
    let cfg = inner.cfg()?;

    let block = cfg
        .block(target)
        .ok_or(AnalysisError::not_found("trace record or value not found"))?;
    let start = block.start_pc;
    let end = block.end_pc;

    let mut idxs = Vec::new();
    let mut pc = start;
    loop {
        if let Some(hit_idxs) = inner.index().pc_to_idxs.get(&pc) {
            idxs.extend(hit_idxs.iter().copied());
        }
        if end.saturating_sub(pc) < 4 {
            break;
        }
        pc = pc.saturating_add(4);
    }
    idxs.sort_unstable();

    let total = idxs.len();
    let max_count = effective_max_count(q.max_count);
    let truncated = total > max_count;
    if truncated {
        if q.near >= 0 {
            let near = q.near as usize;
            idxs.sort_unstable_by_key(|idx| idx.abs_diff(near));
            idxs.truncate(max_count);
            idxs.sort_unstable();
        } else {
            idxs.truncate(max_count);
        }
    }

    Ok(IdxsForBlockResponse {
        status: "ready",
        block: format!("{start:#x}"),
        idxs,
        truncated,
        total,
    })
}

#[cfg(test)]
mod tests {
    use super::{effective_max_count, MAX_IDXS_FOR_BLOCK_RETURNED};

    #[test]
    fn effective_max_count_caps_extreme_requests() {
        assert_eq!(effective_max_count(0), 0);
        assert_eq!(effective_max_count(200), 200);
        assert_eq!(effective_max_count(usize::MAX), MAX_IDXS_FOR_BLOCK_RETURNED);
    }
}

impl Default for IdxsForBlockQuery {
    fn default() -> Self {
        Self {
            pc: Default::default(),
            max_count: default_max(),
            near: default_near(),
        }
    }
}
