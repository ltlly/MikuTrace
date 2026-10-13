//! 以已采集状态为锚点验证 ARM64 指令语义。
use super::AnalysisError;
use crate::analysis::context::AnalysisContext;
use crate::replay::{replay_trace, ReplayReport};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ReplayQuery {
    #[serde(default)]
    pub start: usize,
    #[serde(default = "default_count")]
    pub count: usize,
}
fn default_count() -> usize {
    100
}

pub fn trace_replay(
    state: &AnalysisContext,
    query: ReplayQuery,
) -> Result<ReplayReport, AnalysisError> {
    let result = ({
        let trace = &state.inner.trace;
        if query.count == 0 || query.start >= trace.len() {
            return Err(AnalysisError::invalid(
                "positive count and start inside trace required",
            ));
        }
        let mem = state.inner.memshadow();
        replay_trace(trace, mem, query.start, query.count).map_err(AnalysisError::invalid)
    })?;
    Ok(result)
}

impl Default for ReplayQuery {
    fn default() -> Self {
        Self {
            start: Default::default(),
            count: default_count(),
        }
    }
}
