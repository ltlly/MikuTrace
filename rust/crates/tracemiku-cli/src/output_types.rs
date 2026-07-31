//! Typed output models for CLI analysis commands.
//!
//! Each command's stdout JSON is built from a typed struct here instead of
//! ad-hoc `serde_json::json!`. Serialization via `serde_json::to_value` is
//! byte-identical to the previous hand-built maps (field names and types are
//! the committed AI-facing contract — see contract_* tests), so AI consumers
//! see no change. `schemars` derives let us generate JSON Schema for the
//! surfaces later without touching output code.

use serde::Serialize;

/// output-backtrace top level: `output_to_input_backward_trace` report.
#[derive(Debug, Clone, Serialize)]
pub struct BacktraceReport {
    pub status: &'static str,
    pub strategy: &'static str,
    pub source: serde_json::Value,
    pub patterns: Vec<serde_json::Value>,
    pub taint: serde_json::Value,
    pub notes: Vec<&'static str>,
}

/// Shared explanatory notes for the output-backtrace report.
pub const BACKTRACE_NOTES: [&str; 3] = [
    "This report intentionally starts at the observed output and walks upward through memory writers and register taint.",
    "For JNI NewStringUTF outputs, the hooked bytes are treated as ground truth; memory dumps can show object/runtime layout noise.",
    "Continue with patterns[].hit_reports[].writer_seeds or taint.runs[].summary.function_counts to choose the next function to decompile.",
];

/// output-map top level: `output_base64_group_map` report (full mode).
#[derive(Debug, Clone, Serialize)]
pub struct OutputMapReport {
    pub status: &'static str,
    pub strategy: &'static str,
    pub source: serde_json::Value,
    pub text_len: usize,
    pub base64_context: serde_json::Value,
    pub group_total: usize,
    pub selected_group_start: usize,
    pub selected_group_end: usize,
    pub selected_semantic_range: Option<serde_json::Value>,
    pub selected_hit_order: String,
    pub selected_hit_rank: usize,
    pub tree_frontier_with_next: bool,
    pub index_tree_depth: usize,
    pub index_tree_max_nodes: usize,
    pub hit_candidates: Vec<serde_json::Value>,
    pub selected_hit: Option<serde_json::Value>,
    pub selected_range: serde_json::Value,
    pub find_mem_pattern: serde_json::Value,
    pub semantic_writer_map: serde_json::Value,
    pub groups: Vec<serde_json::Value>,
}

/// stats command top level.
#[derive(Debug, Clone, Serialize)]
pub struct StatsReport {
    pub path: String,
    pub records: usize,
    pub method: String,
    pub cmd: Option<i64>,
    pub fn_addr: Option<String>,
    pub module: Option<tracemiku_core::prelude::ModuleInfo>,
    pub modules: Vec<tracemiku_core::prelude::ModuleInfo>,
    pub modules_total: usize,
    pub modules_truncated: bool,
}
