//! 从 trace 与 JNI 事件识别执行阶段。

use super::AnalysisError;
use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;
use crate::analysis::phase_scan::PhaseEntry;

const MAX_PHASES: usize = 5_000;

#[derive(Debug, Deserialize)]
pub struct AutoPhaseQuery {
    #[serde(default = "default_detect_byte_streams")]
    pub detect_byte_streams: bool,
    #[serde(default = "default_max_phases", alias = "limit")]
    pub max_phases: usize,
}

fn default_detect_byte_streams() -> bool {
    true
}

fn default_max_phases() -> usize {
    2000
}

fn effective_max_phases(raw: usize) -> usize {
    if raw == 0 {
        MAX_PHASES
    } else {
        raw.min(MAX_PHASES)
    }
}

#[derive(Debug, Serialize)]
pub struct AutoPhaseResponse {
    pub status: &'static str,
    pub trace_records: usize,
    pub total: usize,
    pub returned: usize,
    pub truncated: bool,
    pub phases: Vec<PhaseEntry>,
}

pub fn auto_phase_detect(
    state: &AnalysisContext,
    q: AutoPhaseQuery,
) -> Result<AutoPhaseResponse, AnalysisError> {
    let response = auto_phase_response(state, q);
    Ok(response)
}

fn auto_phase_response(state: &AnalysisContext, q: AutoPhaseQuery) -> AutoPhaseResponse {
    let max_phases = effective_max_phases(q.max_phases);
    let mem = state.inner.memshadow();
    let mut dedup = state.inner.auto_phases(mem, q.detect_byte_streams);
    let total = dedup.len();
    let truncated = total > max_phases;
    if truncated {
        dedup.truncate(max_phases);
    }
    AutoPhaseResponse {
        status: "ready",
        trace_records: state.inner.trace.len(),
        total,
        returned: dedup.len(),
        truncated,
        phases: dedup,
    }
}

#[cfg(test)]
mod tests {
    use super::{effective_max_phases, MAX_PHASES};

    #[test]
    fn effective_max_phases_caps_extreme_requests() {
        assert_eq!(effective_max_phases(0), MAX_PHASES);
        assert_eq!(effective_max_phases(200), 200);
        assert_eq!(effective_max_phases(usize::MAX), MAX_PHASES);
    }
}

impl Default for AutoPhaseQuery {
    fn default() -> Self {
        Self {
            detect_byte_streams: default_detect_byte_streams(),
            max_phases: default_max_phases(),
        }
    }
}
