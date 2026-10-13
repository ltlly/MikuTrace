//! 已识别 JNI UTF-8 缓冲区的有界字节预览，不读取 jobject 内部布局。

use serde::Serialize;

use crate::analysis::context::AnalysisContext;
use crate::prelude::MemShadow;

const MAX_STRING_LEN: usize = 4_096;

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
    use super::{effective_max_len, MAX_STRING_LEN};

    #[test]
    fn effective_max_len_caps_extreme_requests() {
        assert_eq!(effective_max_len(0), 1);
        assert_eq!(effective_max_len(128), 128);
        assert_eq!(effective_max_len(usize::MAX), MAX_STRING_LEN);
    }
}

pub(crate) fn preview_call(
    state: &AnalysisContext,
    call: &super::jni_scan::JniCallRecord,
    max_len: usize,
) -> Option<JniStringHit> {
    let (arg_name, direction) = jni_string_op(&call.jni_fn)?;
    let mem = state.inner.memshadow();
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
        let (bytes, seen, stop) = read_string(mem, addr, cursor, effective_max_len(max_len));
        let string = bytes
            .as_ref()
            .map(|b| String::from_utf8_lossy(b).into_owned());
        let hex = bytes.map(|b| b.iter().map(|byte| format!("{byte:02x}")).collect());
        (Some(seen), hex, string, stop)
    } else {
        (None, None, None, "return_unobserved")
    };
    Some(JniStringHit {
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
    })
}
