//! JNI 对象的运行时使用历史。

use super::AnalysisError;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::analysis::context::{AnalysisContext, AnalysisData};
use crate::analysis::jni_scan::JniCallRecord;
use crate::analysis::parse;

const MAX_HITS: usize = 5_000;

#[derive(Debug, Deserialize)]
pub struct JobjHistoryQuery {
    pub jobject: String,
    #[serde(default)]
    pub start: usize,
    #[serde(default = "default_end")]
    pub end: isize,
    #[serde(default = "default_max")]
    pub max: usize,
}

fn default_end() -> isize {
    -1
}

fn default_max() -> usize {
    200
}

#[derive(Debug, Serialize)]
pub struct JobjHistoryHit {
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub func: Option<String>,
    pub jni_fn: String,
    pub vtable_offset: String,
    pub match_arg: &'static str,
    pub args: HashMap<&'static str, String>,
}

#[derive(Debug, Serialize)]
pub struct JobjHistoryResponse {
    pub jobject: String,
    pub start: usize,
    pub end: usize,
    pub count: usize,
    pub returned: usize,
    pub truncated: bool,
    pub hits: Vec<JobjHistoryHit>,
}

pub fn jobj_history(
    state: &AnalysisContext,
    q: JobjHistoryQuery,
) -> Result<JobjHistoryResponse, AnalysisError> {
    let target = parse::parse_dec_u64(&q.jobject).ok_or(AnalysisError::invalid("invalid query"))?;
    let end = if q.end >= 0 {
        (q.end as usize).min(state.inner.trace.len())
    } else {
        state.inner.trace.len()
    };
    let inner = state.inner.clone();
    let response = jobj_history_response(&inner, q, target, end);
    Ok(response)
}

fn jobj_history_response(
    inner: &AnalysisData,
    q: JobjHistoryQuery,
    target: u64,
    end: usize,
) -> JobjHistoryResponse {
    let scan = inner.jni_calls();
    let max_hits = effective_max(q.max);
    let mut count = 0usize;
    let mut hits = Vec::with_capacity(max_hits.min(256));
    for call in &scan.calls {
        if call.idx < q.start {
            continue;
        }
        if call.idx >= end {
            break;
        }
        let Some(match_arg) = ["x1", "x2", "x3", "x4"]
            .into_iter()
            .find(|arg| call.arg(arg) == Some(target))
        else {
            continue;
        };
        count += 1;
        if hits.len() < max_hits {
            hits.push(jobj_history_hit(call, match_arg));
        }
    }
    let returned = hits.len();
    JobjHistoryResponse {
        jobject: format!("{target:#x}"),
        start: q.start,
        end,
        count,
        returned,
        truncated: returned < count,
        hits,
    }
}

fn effective_max(raw: usize) -> usize {
    if raw == 0 {
        MAX_HITS
    } else {
        raw.min(MAX_HITS)
    }
}

fn jobj_history_hit(call: &JniCallRecord, match_arg: &'static str) -> JobjHistoryHit {
    JobjHistoryHit {
        idx: call.idx,
        pc: format!("{:#x}", call.pc),
        rel: call.rel.map(|rel| format!("{rel:#x}")),
        func: call.func_display(),
        jni_fn: call.jni_fn.clone(),
        vtable_offset: format!("{:#x}", call.vtable_offset),
        match_arg,
        args: call.args_map_without_x0(),
    }
}

impl Default for JobjHistoryQuery {
    fn default() -> Self {
        Self {
            jobject: Default::default(),
            start: Default::default(),
            end: default_end(),
            max: default_max(),
        }
    }
}
