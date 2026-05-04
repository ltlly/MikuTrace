//! GET /api/jni-strings.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::routes::jni_calls::{parse_int, scan_jni_calls};
use crate::state::AppState;
use tracemiku_core::prelude::MemShadow;

#[derive(Debug, Deserialize)]
pub struct JniStringsQuery {
    #[serde(default = "default_max")]
    pub max: usize,
    #[serde(default = "default_max_len")]
    pub max_len: usize,
}

fn default_max() -> usize {
    200
}

fn default_max_len() -> usize {
    128
}

#[derive(Debug, Serialize)]
pub struct JniStringHit {
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub func: Option<String>,
    pub jni_fn: String,
    pub arg_name: &'static str,
    pub direction: &'static str,
    pub x1: String,
    pub x2: String,
    pub buffer_addr: Option<String>,
    pub observed_bytes: Option<usize>,
    pub string: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct JniStringsResponse {
    pub count: usize,
    pub with_observed_string: usize,
    pub without_observed_string: usize,
    pub note: &'static str,
    pub hits: Vec<JniStringHit>,
}

pub async fn jni_strings_handler(
    State(state): State<AppState>,
    Query(q): Query<JniStringsQuery>,
) -> Json<JniStringsResponse> {
    Json(
        tokio::task::spawn_blocking(move || jni_strings_response(&state, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "jni strings worker failed: {err}");
                JniStringsResponse {
                    count: 0,
                    with_observed_string: 0,
                    without_observed_string: 0,
                    note: "worker failed",
                    hits: Vec::new(),
                }
            }),
    )
}

fn jni_strings_response(state: &AppState, q: JniStringsQuery) -> JniStringsResponse {
    let (calls, _) = scan_jni_calls(state, None, 0);
    let mem = state.inner.memshadow();
    let mut hits = Vec::new();
    for call in calls {
        let Some((arg_name, direction)) = jni_string_op(&call.jni_fn) else {
            continue;
        };
        let (buffer_addr, cursor) = match direction {
            "out_x0" if call.idx + 1 < state.inner.trace.len() => (
                state.inner.trace.record(call.idx + 1).reg_by_name("x0"),
                call.idx + 1,
            ),
            "out_x4" => (call.args.get("x4").and_then(|v| parse_int(v)), call.idx),
            "in" => (call.args.get(arg_name).and_then(|v| parse_int(v)), call.idx),
            _ => (None, call.idx),
        };
        let (observed_bytes, string) = if let Some(addr) = buffer_addr {
            let (s, seen) = read_string(mem, addr, cursor, q.max_len);
            (Some(seen), s)
        } else {
            (None, None)
        };
        hits.push(JniStringHit {
            idx: call.idx,
            pc: call.pc,
            rel: call.rel,
            func: call.func,
            jni_fn: call.jni_fn,
            arg_name,
            direction,
            x1: call.args.get("x1").cloned().unwrap_or_else(|| "0x0".into()),
            x2: call.args.get("x2").cloned().unwrap_or_else(|| "0x0".into()),
            buffer_addr: buffer_addr.map(|addr| format!("{addr:#x}")),
            observed_bytes,
            string,
        });
        if q.max > 0 && hits.len() >= q.max {
            break;
        }
    }
    let with_observed_string = hits.iter().filter(|hit| hit.string.is_some()).count();
    JniStringsResponse {
        count: hits.len(),
        with_observed_string,
        without_observed_string: hits.len() - with_observed_string,
        note: "buffers in libart heap are Stalker-excluded; agent-side hook on GetStringUTFChars needed for content",
        hits,
    }
}

fn jni_string_op(name: &str) -> Option<(&'static str, &'static str)> {
    match name {
        "NewString" => Some(("x1", "out_x0")),
        "NewStringUTF" => Some(("x1", "out_x0")),
        "GetStringChars" => Some(("x1", "out_x0")),
        "GetStringUTFChars" => Some(("x1", "out_x0")),
        "ReleaseStringChars" => Some(("x2", "in")),
        "ReleaseStringUTFChars" => Some(("x2", "in")),
        "GetStringRegion" => Some(("x4", "out_x4")),
        "GetStringUTFRegion" => Some(("x4", "out_x4")),
        "GetStringLength" => Some(("x1", "in")),
        "GetStringUTFLength" => Some(("x1", "in")),
        "GetStringCritical" => Some(("x1", "out_x0")),
        "ReleaseStringCritical" => Some(("x2", "in")),
        _ => None,
    }
}

fn read_string(
    mem: &MemShadow,
    addr: u64,
    cursor: usize,
    max_len: usize,
) -> (Option<String>, usize) {
    if addr == 0 {
        return (None, 0);
    }
    let mut bytes = Vec::new();
    let mut seen = 0;
    for offset in 0..max_len {
        let (byte, _, _) = mem.byte_at(addr + offset as u64, cursor as u64);
        let Some(byte) = byte else {
            if seen == 0 {
                return (None, 0);
            }
            break;
        };
        seen += 1;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }
    if bytes.is_empty() {
        return (None, seen);
    }
    (Some(String::from_utf8_lossy(&bytes).into_owned()), seen)
}
