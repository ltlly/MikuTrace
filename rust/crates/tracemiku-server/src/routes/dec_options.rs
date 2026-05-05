use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;

use crate::state::TraceIrBuildOptions;

pub fn default_tier() -> String {
    "hot".to_string()
}

pub fn default_split_top_k() -> usize {
    10
}

pub fn default_split_min_records() -> usize {
    50
}

#[derive(Debug, Clone, Deserialize)]
pub struct DecIrQuery {
    #[serde(default)]
    pub hooks: String,
    #[serde(default)]
    pub with_memshadow: String,
    #[serde(default = "default_split_top_k")]
    pub split_top_k: usize,
    #[serde(default = "default_split_min_records")]
    pub split_min_records: usize,
}

impl DecIrQuery {
    pub fn to_options(&self) -> TraceIrBuildOptions {
        TraceIrBuildOptions {
            hook_paths: hook_paths_from_str(&self.hooks),
            with_memshadow: boolish(&self.with_memshadow),
            split_top_k: self.split_top_k,
            split_min_records: self.split_min_records,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DecFnQuery {
    #[serde(default = "default_tier")]
    pub tier: String,
    #[serde(default)]
    pub hooks: String,
    #[serde(default)]
    pub with_memshadow: String,
    #[serde(default = "default_split_top_k")]
    pub split_top_k: usize,
    #[serde(default = "default_split_min_records")]
    pub split_min_records: usize,
}

impl DecFnQuery {
    pub fn to_options(&self) -> TraceIrBuildOptions {
        TraceIrBuildOptions {
            hook_paths: hook_paths_from_str(&self.hooks),
            with_memshadow: boolish(&self.with_memshadow),
            split_top_k: self.split_top_k,
            split_min_records: self.split_min_records,
        }
    }
}

pub fn hook_paths_from_value(value: &Value) -> Vec<PathBuf> {
    match value {
        Value::String(s) => hook_paths_from_str(s),
        Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect(),
        _ => Vec::new(),
    }
}

fn hook_paths_from_str(raw: &str) -> Vec<PathBuf> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn boolish(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}
