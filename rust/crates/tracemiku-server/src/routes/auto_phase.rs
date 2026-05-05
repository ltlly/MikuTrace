//! GET /api/auto-phase-detect.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::phase_scan::{jni_phases, PhaseEntry};
use crate::state::AppState;

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
    let mem = match state.inner.memshadow_ready_or_block_if_idle() {
        Ok(mem) => mem,
        Err(status) => {
            let mut phases = jni_phases(&state.inner.trace_dir);
            phases.sort_by_key(|p| p.idx);
            return AutoPhaseResponse {
                status,
                trace_records: state.inner.trace.len(),
                total: phases.len(),
                returned: phases.len(),
                truncated: false,
                phases,
            };
        }
    };
    let mut dedup = state.inner.auto_phases(mem, q.detect_byte_streams);
    let total = dedup.len();
    let max_phases = q.max_phases;
    let truncated = max_phases > 0 && total > max_phases;
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
