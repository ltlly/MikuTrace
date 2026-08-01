//! Typed output models for the byte-lineage batch report.

use schemars::JsonSchema;
use serde::Serialize;

/// Structured source classification for one byte's value.
/// Derived from the byte-lineage steps chain without changing the analysis.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ByteOrigin {
    /// Value ultimately came from a register at a trace index.
    Register {
        /// Register name (e.g., "w0", "x2").
        reg: String,
        /// Trace record index where the register value originated.
        #[serde(skip_serializing_if = "Option::is_none")]
        idx: Option<usize>,
    },
    /// Value came from an ordinary memory write.
    Memory {
        /// Address written.
        addr: u64,
        /// Trace record index of the write instruction.
        #[serde(skip_serializing_if = "Option::is_none")]
        idx: Option<usize>,
    },
    /// Value came from an external write (MemShadow kind "x").
    ExternalWrite {
        /// Address written by the external source.
        addr: u64,
        /// Trace record index when the external write was observed.
        #[serde(skip_serializing_if = "Option::is_none")]
        idx: Option<usize>,
    },
    /// Value is a compile-time constant (immediate write, e.g. xzr).
    Constant {
        /// The constant value.
        value: i64,
    },
    /// Value source is unknown (no writer, missing trace data).
    Unknown,
}

/// byte-lineage batch result entry: one byte's lineage row.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct LineageRow {
    pub offset: usize,
    pub addr: String,
    pub lineage: serde_json::Value,
    /// Structured source classification for this byte.
    pub origin: ByteOrigin,
}

/// byte-lineage batch top level (count > 1).
#[derive(Debug, Clone, Serialize, JsonSchema)]
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
