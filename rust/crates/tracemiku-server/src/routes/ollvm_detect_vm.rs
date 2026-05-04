//! GET /api/ollvm-detect-vm.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::ollvm_detect_vm;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct OllvmDetectVmQuery {
    #[serde(default = "default_min_entries")]
    pub min_entries: usize,
    #[serde(default = "default_threshold")]
    pub threshold: f64,
}

fn default_min_entries() -> usize {
    10
}

fn default_threshold() -> f64 {
    0.5
}

#[derive(Debug, Serialize)]
pub struct OllvmCandidate {
    pub fn_pc: String,
    pub entry_count: u64,
    pub confidence: f64,
    pub reason: String,
    pub hint: String,
}

#[derive(Debug, Serialize)]
pub struct OllvmDetectVmResponse {
    pub min_entries: usize,
    pub threshold: f64,
    pub count: usize,
    pub candidates: Vec<OllvmCandidate>,
}

pub async fn ollvm_detect_vm_handler(
    State(state): State<AppState>,
    Query(q): Query<OllvmDetectVmQuery>,
) -> Json<OllvmDetectVmResponse> {
    let candidates: Vec<OllvmCandidate> = ollvm_detect_vm(
        &state.inner.trace,
        q.min_entries.max(1),
        q.threshold.clamp(0.0, 1.0),
    )
    .into_iter()
    .map(|finding| OllvmCandidate {
        fn_pc: format!("{:#x}", finding.fn_pc),
        entry_count: finding.entry_count,
        confidence: finding.confidence,
        reason: finding.reasons.join(" + "),
        hint: finding.hint,
    })
    .collect();

    Json(OllvmDetectVmResponse {
        min_entries: q.min_entries.max(1),
        threshold: q.threshold.clamp(0.0, 1.0),
        count: candidates.len(),
        candidates,
    })
}
