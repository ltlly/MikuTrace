//! 从执行行为检测 OLLVM 风格 VM 特征。

use super::AnalysisError;
use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;

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

pub fn ollvm_detect_vm(
    state: &AnalysisContext,
    q: OllvmDetectVmQuery,
) -> Result<OllvmDetectVmResponse, AnalysisError> {
    let min_entries = q.min_entries.max(1);
    let threshold = q.threshold.clamp(0.0, 1.0);
    let inner = state.inner.clone();
    let response = {
        let candidates: Vec<OllvmCandidate> = inner
            .ollvm_findings(min_entries, threshold)
            .into_iter()
            .map(|finding| OllvmCandidate {
                fn_pc: format!("{:#x}", finding.fn_pc),
                entry_count: finding.entry_count,
                confidence: finding.confidence,
                reason: finding.reasons.join(" + "),
                hint: finding.hint,
            })
            .collect();

        OllvmDetectVmResponse {
            min_entries,
            threshold,
            count: candidates.len(),
            candidates,
        }
    };
    Ok(response)
}

impl Default for OllvmDetectVmQuery {
    fn default() -> Self {
        Self {
            min_entries: default_min_entries(),
            threshold: default_threshold(),
        }
    }
}
