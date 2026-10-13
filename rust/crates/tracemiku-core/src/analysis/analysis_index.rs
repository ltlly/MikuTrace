use super::AnalysisError;
use serde::Serialize;

use crate::analysis::context::AnalysisContext;

const TOP_PC_LIMIT: usize = 128;
const TOP_FUNCTION_LIMIT: usize = 128;

#[derive(Debug, Serialize)]
pub struct AnalysisIndexResponse {
    pub sidecar: String,
    pub summary: crate::analysis_index::AnalysisSummary,
    pub checkpoint_count: usize,
    pub mem_last_def_count: usize,
    pub top_pcs: Vec<crate::analysis_index::PcSummary>,
    pub top_functions: Vec<crate::analysis_index::FunctionSummary>,
}

pub fn analysis_index(state: &AnalysisContext) -> Result<AnalysisIndexResponse, AnalysisError> {
    let response = analysis_index_response(state);
    Ok(response)
}

fn analysis_index_response(state: &AnalysisContext) -> AnalysisIndexResponse {
    let analysis = state.inner.analysis_index();
    let mut top_pcs = analysis.pc_summaries.iter().collect::<Vec<_>>();
    top_pcs.sort_unstable_by(|a, b| {
        b.record_count
            .cmp(&a.record_count)
            .then_with(|| a.pc.cmp(&b.pc))
    });
    let top_pcs = top_pcs
        .into_iter()
        .take(TOP_PC_LIMIT)
        .cloned()
        .collect::<Vec<_>>();

    let mut top_functions = analysis.function_summaries.iter().collect::<Vec<_>>();
    top_functions.sort_unstable_by(|a, b| {
        b.total_records
            .cmp(&a.total_records)
            .then_with(|| b.call_count.cmp(&a.call_count))
            .then_with(|| a.fn_pc.cmp(&b.fn_pc))
    });
    let top_functions = top_functions
        .into_iter()
        .take(TOP_FUNCTION_LIMIT)
        .cloned()
        .collect::<Vec<_>>();

    AnalysisIndexResponse {
        sidecar: crate::analysis_index::AnalysisIndex::sidecar_path(&state.inner.trace)
            .display()
            .to_string(),
        summary: analysis.summary.clone(),
        checkpoint_count: analysis.reg_checkpoints.len(),
        mem_last_def_count: analysis.mem_last_def.len(),
        top_pcs,
        top_functions,
    }
}
