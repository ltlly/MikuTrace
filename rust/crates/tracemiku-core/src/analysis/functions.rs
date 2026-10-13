//! 从符号与运行时 CFG 汇总函数。

use super::AnalysisError;
use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;

use crate::prelude::FunctionEntry;

use crate::analysis::context::{AnalysisContext, AnalysisData};

const MAX_FUNCTIONS: usize = 10_000;

#[derive(Debug, Serialize)]
pub struct FunctionsResponse {
    pub counts: HashMap<String, u64>,
    pub functions: Vec<FunctionEntry>,
    pub total_functions: usize,
    pub returned_functions: usize,
    pub max_functions_used: usize,
    pub truncated: bool,
}

pub fn functions(state: &AnalysisContext) -> Result<FunctionsResponse, AnalysisError> {
    let inner = state.inner.clone();
    let response = functions_response(inner);
    Ok(response)
}

fn functions_response(inner: Arc<AnalysisData>) -> FunctionsResponse {
    let fns = inner.function_index().entries.clone();
    functions_response_from_entries(fns)
}

fn functions_response_from_entries(fns: Vec<FunctionEntry>) -> FunctionsResponse {
    let mut counts: HashMap<String, u64> = HashMap::new();
    counts.insert("symbol".to_string(), 0);
    for f in &fns {
        *counts.entry(f.source.clone()).or_insert(0) += 1;
    }
    let total_functions = fns.len();
    let mut functions = fns;
    if functions.len() > MAX_FUNCTIONS {
        functions.truncate(MAX_FUNCTIONS);
    }
    let returned_functions = functions.len();
    FunctionsResponse {
        counts,
        functions,
        total_functions,
        returned_functions,
        max_functions_used: MAX_FUNCTIONS,
        truncated: total_functions > returned_functions,
    }
}
