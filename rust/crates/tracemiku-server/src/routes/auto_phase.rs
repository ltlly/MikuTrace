//! GET /api/auto-phase-detect.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::phase_scan::{jni_phases, PhaseEntry};
use crate::state::AppState;

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

pub async fn auto_phase_detect_handler(
    State(state): State<AppState>,
    Query(q): Query<AutoPhaseQuery>,
) -> Json<AutoPhaseResponse> {
    Json(
        tokio::task::spawn_blocking(move || auto_phase_response(&state, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "auto phase worker failed: {err}");
                AutoPhaseResponse {
                    status: "error",
                    trace_records: 0,
                    total: 0,
                    returned: 0,
                    truncated: false,
                    phases: Vec::new(),
                }
            }),
    )
}

fn auto_phase_response(state: &AppState, q: AutoPhaseQuery) -> AutoPhaseResponse {
    let max_phases = effective_max_phases(q.max_phases);
    let mem = match state.inner.memshadow_ready_or_block_if_idle() {
        Ok(mem) => mem,
        Err(status) => {
            let mut phases = jni_phases(&state.inner.trace_dir);
            phases.sort_by_key(|p| p.idx);
            let total = phases.len();
            let truncated = total > max_phases;
            if truncated {
                phases.truncate(max_phases);
            }
            return AutoPhaseResponse {
                status,
                trace_records: state.inner.trace.len(),
                total,
                returned: phases.len(),
                truncated,
                phases,
            };
        }
    };
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
