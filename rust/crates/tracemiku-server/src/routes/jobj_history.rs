//! GET /api/jobj-history.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::routes::jni_calls::{parse_int, scan_jni_calls};
use crate::state::AppState;

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
    pub hits: Vec<JobjHistoryHit>,
}

pub async fn jobj_history_handler(
    State(state): State<AppState>,
    Query(q): Query<JobjHistoryQuery>,
) -> Result<Json<JobjHistoryResponse>, StatusCode> {
    let target = parse_int(&q.jobject).ok_or(StatusCode::BAD_REQUEST)?;
    let end = if q.end >= 0 {
        (q.end as usize).min(state.inner.trace.len())
    } else {
        state.inner.trace.len()
    };
    let (calls, _) = scan_jni_calls(&state, None, 0);
    let mut hits = Vec::new();
    for call in calls {
        if call.idx < q.start {
            continue;
        }
        if call.idx >= end {
            break;
        }
        let Some(match_arg) = ["x1", "x2", "x3", "x4"]
            .into_iter()
            .find(|arg| call.args.get(arg).and_then(|v| parse_int(v)) == Some(target))
        else {
            continue;
        };
        hits.push(JobjHistoryHit {
            idx: call.idx,
            pc: call.pc,
            rel: call.rel,
            func: call.func,
            jni_fn: call.jni_fn,
            vtable_offset: call.vtable_offset,
            match_arg,
            args: call
                .args
                .into_iter()
                .filter(|(k, _)| matches!(*k, "x1" | "x2" | "x3" | "x4"))
                .collect(),
        });
        if q.max > 0 && hits.len() >= q.max {
            break;
        }
    }
    Ok(Json(JobjHistoryResponse {
        jobject: format!("{target:#x}"),
        start: q.start,
        end,
        count: hits.len(),
        hits,
    }))
}
