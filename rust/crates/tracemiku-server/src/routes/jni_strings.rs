//! GET /api/jni-strings.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;
use tracemiku_core::prelude::MemShadow;

const MAX_HITS: usize = 5_000;
const MAX_STRING_LEN: usize = 4_096;

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

fn effective_max_len(raw: usize) -> usize {
    raw.clamp(1, MAX_STRING_LEN)
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
    pub status: &'static str,
    pub count: usize,
    pub returned: usize,
    pub truncated: bool,
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
                    status: "error",
                    count: 0,
                    returned: 0,
                    truncated: false,
                    with_observed_string: 0,
                    without_observed_string: 0,
                    note: "worker failed",
                    hits: Vec::new(),
                }
            }),
    )
}

fn jni_strings_response(state: &AppState, q: JniStringsQuery) -> JniStringsResponse {
    let mem = match state.inner.memshadow_ready_or_block_if_idle() {
        Ok(mem) => mem,
        Err(status) => {
            let status = status.status_str();
            return JniStringsResponse {
                status,
                count: 0,
                returned: 0,
                truncated: false,
                with_observed_string: 0,
                without_observed_string: 0,
                note: "memory index is still loading",
                hits: Vec::new(),
            };
        }
    };
    let scan = state.inner.jni_calls();
    let max_hits = effective_max(q.max);
    let mut count = 0usize;
    let mut hits = Vec::with_capacity(max_hits.min(256));
    for call in &scan.calls {
        let Some((arg_name, direction)) = jni_string_op(&call.jni_fn) else {
            continue;
        };
        count += 1;
        if hits.len() >= max_hits {
            continue;
        }
        let (buffer_addr, cursor) = match direction {
            "out_x0" if call.idx + 1 < state.inner.trace.len() => (
                state.inner.trace.record(call.idx + 1).reg_by_name("x0"),
                call.idx + 1,
            ),
            "out_x4" => (call.arg("x4"), call.idx),
            "in" => (call.arg(arg_name), call.idx),
            _ => (None, call.idx),
        };
        let (observed_bytes, string) = if let Some(addr) = buffer_addr {
            let (s, seen) = read_string(mem, addr, cursor, effective_max_len(q.max_len));
            (Some(seen), s)
        } else {
            (None, None)
        };
        hits.push(JniStringHit {
            idx: call.idx,
            pc: format!("{:#x}", call.pc),
            rel: call.rel.map(|rel| format!("{rel:#x}")),
            func: call.func_display(),
            jni_fn: call.jni_fn.clone(),
            arg_name,
            direction,
            x1: format!("{:#x}", call.arg("x1").unwrap_or(0)),
            x2: format!("{:#x}", call.arg("x2").unwrap_or(0)),
            buffer_addr: buffer_addr.map(|addr| format!("{addr:#x}")),
            observed_bytes,
            string,
        });
    }
    let with_observed_string = hits.iter().filter(|hit| hit.string.is_some()).count();
    let returned = hits.len();
    JniStringsResponse {
        status: "ready",
        count,
        returned,
        truncated: returned < count,
        with_observed_string,
        without_observed_string: returned - with_observed_string,
        note: "buffers in libart heap are Stalker-excluded; agent-side hook on GetStringUTFChars needed for content",
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

#[cfg(test)]
mod tests {
    use super::{effective_max, effective_max_len, MAX_HITS, MAX_STRING_LEN};

    #[test]
    fn effective_max_caps_extreme_requests() {
        assert_eq!(effective_max(0), MAX_HITS);
        assert_eq!(effective_max(200), 200);
        assert_eq!(effective_max(usize::MAX), MAX_HITS);
    }

    #[test]
    fn effective_max_len_caps_extreme_requests() {
        assert_eq!(effective_max_len(0), 1);
        assert_eq!(effective_max_len(128), 128);
        assert_eq!(effective_max_len(usize::MAX), MAX_STRING_LEN);
    }
}
