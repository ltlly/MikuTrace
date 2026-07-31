//! Typed output models for the vm command family (vm-slice / vm-ops).

use schemars::JsonSchema;
use serde::Serialize;

/// vm-slice top level.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct VmSliceReport {
    pub status: &'static str,
    pub start: usize,
    pub end: usize,
    pub vm_profile: serde_json::Value,
    pub returned: usize,
    pub source_returned: usize,
    pub only_vm: bool,
    pub vm_base_ip: Option<String>,
    pub records: Vec<serde_json::Value>,
}

/// vm-ops top level.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct VmOpsReport {
    pub status: &'static str,
    pub start: usize,
    pub end: usize,
    pub vm_profile: serde_json::Value,
    pub source_requested: usize,
    pub source_returned: usize,
    pub source_maybe_truncated: bool,
    pub source_chunks: usize,
    pub chunk_size: usize,
    pub vm_rows: usize,
    pub vm_base_ip: Option<String>,
    pub vm_state_base: Option<String>,
    pub ops_returned: usize,
    pub truncated: bool,
    pub ops: Vec<serde_json::Value>,
}
