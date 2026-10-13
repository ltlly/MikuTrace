//! 从 trace 识别 JNI 调用。

use super::AnalysisError;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;
use crate::analysis::jni_scan::JniCallRecord;

const MAX_HITS: usize = 5_000;

#[derive(Debug, Deserialize)]
pub struct JniCallsQuery {
    pub in_fn: Option<String>,
    #[serde(default = "default_max")]
    pub max: usize,
}

fn default_max() -> usize {
    200
}

#[derive(Debug, Clone, Serialize)]
pub struct JniCallHit {
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub func: Option<String>,
    pub jni_fn: String,
    pub vtable_offset: String,
    pub args: HashMap<&'static str, String>,
}

#[derive(Debug, Serialize)]
pub struct JniCallsResponse {
    pub in_fn: Option<String>,
    pub count: usize,
    pub returned: usize,
    pub truncated: bool,
    pub hits: Vec<JniCallHit>,
    pub vtable_size: usize,
}

pub fn jni_calls(
    state: &AnalysisContext,
    q: JniCallsQuery,
) -> Result<JniCallsResponse, AnalysisError> {
    let response = {
        let scan = state.inner.jni_calls();
        let max_hits = effective_max(q.max);
        let mut count = 0usize;
        let mut hits = Vec::with_capacity(max_hits.min(256));
        for call in &scan.calls {
            if q.in_fn
                .as_deref()
                .is_some_and(|want| call.func_name.as_str() != want)
            {
                continue;
            }
            count += 1;
            if hits.len() < max_hits {
                hits.push(jni_call_hit(call));
            }
        }
        let returned = hits.len();
        JniCallsResponse {
            in_fn: q.in_fn,
            count,
            returned,
            truncated: returned < count,
            hits,
            vtable_size: scan.vtable_size,
        }
    };
    Ok(response)
}

fn effective_max(raw: usize) -> usize {
    if raw == 0 {
        MAX_HITS
    } else {
        raw.min(MAX_HITS)
    }
}

fn jni_call_hit(call: &JniCallRecord) -> JniCallHit {
    JniCallHit {
        idx: call.idx,
        pc: format!("{:#x}", call.pc),
        rel: call.rel.map(|rel| format!("{rel:#x}")),
        func: call.func_display(),
        jni_fn: call.jni_fn.clone(),
        vtable_offset: format!("{:#x}", call.vtable_offset),
        args: call.args_map(),
    }
}

impl Default for JniCallsQuery {
    fn default() -> Self {
        Self {
            in_fn: Default::default(),
            max: default_max(),
        }
    }
}
