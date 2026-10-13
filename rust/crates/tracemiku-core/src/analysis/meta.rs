use crate::analysis::context::AnalysisContext;

pub fn meta(state: &AnalysisContext) -> serde_json::Value {
    // Use serde_json::Value rather than a typed response so the wire shape
    // is dictated by serde::Serialize on TraceMeta itself (single source).
    serde_json::to_value(&state.inner.meta).unwrap()
}
