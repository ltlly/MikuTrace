use super::*;

pub(super) fn query_json(trace_dir: PathBuf, query: Query) -> anyhow::Result<()> {
    print_pretty(&query_value(trace_dir, query)?)
}

pub(super) fn query_value(trace_dir: PathBuf, query: Query) -> anyhow::Result<serde_json::Value> {
    query_value_on(&AnalysisContext::load(trace_dir)?, query)
}

pub(super) fn query_value_on(
    context: &AnalysisContext,
    query: Query,
) -> anyhow::Result<serde_json::Value> {
    Ok(tracemiku_core::analysis::execute(context, query)?)
}
