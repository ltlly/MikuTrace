//! Typed output models for the byte-lineage batch report.

use serde::Serialize;

/// byte-lineage batch result entry: one byte's lineage row.
#[derive(Debug, Clone, Serialize)]
pub struct LineageRow {
    pub offset: usize,
    pub addr: String,
    pub lineage: serde_json::Value,
}

/// byte-lineage batch top level (count > 1).
#[derive(Debug, Clone, Serialize)]
pub struct LineageBatchReport {
    pub status: String,
    pub start_addr: String,
    pub before_idx: usize,
    pub count: usize,
    pub mode: String,
    pub error_count: usize,
    pub decision_counts: Vec<serde_json::Value>,
    pub upstream_counts: Vec<serde_json::Value>,
    pub step_stats: serde_json::Value,
    pub frontier_groups: Vec<serde_json::Value>,
    pub results: Vec<LineageRow>,
}
