//! Typed output models for CLI analysis commands.
//!
//! 组合报告的顶层模型与 JSON Schema。嵌套证据由相应 core 查询生成，
//! 字段形状及含义由 contract_* 测试约束。
//!
//! 截断元数据现状（字段名已被 contract_* 契约测试锁定，统一或改名需
//! 全链路同步，故先在此登记）：
//!
//! - `byte-lineage`（`--count > 1` 批量模式）：`status: "partial_error"` +
//!   `error_count` 数量字段。
//!
//! 新增输出的截断表达统一使用 `truncated: bool` + 数量字段（如
//! `returned`/`total`）的模式，不再引入新的截断字段拼写。

pub use crate::replay::ReplayReport;

use schemars::JsonSchema;
use serde::Serialize;

/// output-backtrace top level: `output_to_input_backward_trace` report.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct BacktraceReport {
    pub status: &'static str,
    pub strategy: &'static str,
    pub source: serde_json::Value,
    pub patterns: Vec<serde_json::Value>,
    pub taint: serde_json::Value,
    pub notes: Vec<&'static str>,
}

/// Shared explanatory notes for the output-backtrace report.
pub const BACKTRACE_NOTES: [&str; 2] = [
    "This report intentionally starts at the observed output and walks upward through memory writers and register taint.",
    "Continue with patterns[].hit_reports[].writer_seeds or taint.runs[].summary.function_counts to choose the next function to decompile.",
];
