//! 已识别 JNI UTF-8 缓冲区的有界字节预览，不读取 jobject 内部布局。

use super::AnalysisError;
use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;
use crate::prelude::MemShadow;

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
    pub bytes_hex: Option<String>,
    pub string: Option<String>,
    pub read_stop: &'static str,
}

#[derive(Debug, Serialize)]
pub struct JniStringsResponse {
    pub status: &'static str,
    pub count: usize,
    pub returned: usize,
    pub truncated: bool,
    pub with_observed_string: usize,
    pub without_observed_string: usize,
    pub encoding: &'static str,
    pub display_encoding: &'static str,
    pub note: &'static str,
    pub hits: Vec<JniStringHit>,
}

pub fn jni_strings(
    state: &AnalysisContext,
    q: JniStringsQuery,
) -> Result<JniStringsResponse, AnalysisError> {
    let response = jni_strings_response(state, q);
    Ok(response)
}

fn jni_strings_response(state: &AnalysisContext, q: JniStringsQuery) -> JniStringsResponse {
    let mem = state.inner.memshadow();
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
            "out_x0"
                if call.idx + 1 < state.inner.trace.len()
                    && call.pc.checked_add(4) == Some(state.inner.trace.pc(call.idx + 1)) =>
            {
                (
                    state.inner.trace.record(call.idx + 1).reg_by_name("x0"),
                    call.idx + 1,
                )
            }
            "in" => (call.arg(arg_name), call.idx),
            _ => (None, call.idx),
        };
        let (observed_bytes, bytes_hex, string, read_stop) = if let Some(addr) = buffer_addr {
            let (bytes, seen, stop) = read_string(mem, addr, cursor, effective_max_len(q.max_len));
            let string = bytes
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned());
            let hex = bytes.map(|b| b.iter().map(|byte| format!("{byte:02x}")).collect());
            (Some(seen), hex, string, stop)
        } else {
            (None, None, None, "return_unobserved")
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
            bytes_hex,
            string,
            read_stop,
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
        encoding: "modified_utf8",
        display_encoding: "utf8_lossy",
        note: "仅预览 NewStringUTF 输入、GetStringUTFChars 已观测返回、ReleaseStringUTFChars 输入；字节来自 MemShadow。string 是 UTF-8 有损显示，精确内容见 bytes_hex；返回缓冲区长度未知，遇 NUL 或上限不代表已证明完整字符串。",
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
        "NewStringUTF" => Some(("x1", "in")),
        "GetStringUTFChars" => Some(("x0", "out_x0")),
        "ReleaseStringUTFChars" => Some(("x2", "in")),
        _ => None,
    }
}

fn read_string(
    mem: &MemShadow,
    addr: u64,
    cursor: usize,
    max_len: usize,
) -> (Option<Vec<u8>>, usize, &'static str) {
    if addr == 0 {
        return (None, 0, "null_pointer");
    }
    let mut bytes = Vec::new();
    let mut seen = 0;
    let mut stop = "limit";
    for offset in 0..max_len {
        let Some(byte_addr) = addr.checked_add(offset as u64) else {
            stop = "address_overflow";
            break;
        };
        let (byte, _, _) = mem.byte_at(byte_addr, cursor as u64);
        let Some(byte) = byte else {
            stop = "missing";
            break;
        };
        seen += 1;
        if byte == 0 {
            stop = "nul";
            break;
        }
        bytes.push(byte);
    }
    ((seen > 0).then_some(bytes), seen, stop)
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

impl Default for JniStringsQuery {
    fn default() -> Self {
        Self {
            max: default_max(),
            max_len: default_max_len(),
        }
    }
}
