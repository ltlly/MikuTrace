//! 从 trace 识别 JNI 调用。

use super::AnalysisError;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;
use crate::analysis::jni_scan::JniCallRecord;

const MAX_HITS: usize = 5_000;

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

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct JniInspectQuery {
    pub in_fn: Option<String>,
    pub name: Option<String>,
    pub jobject: Option<String>,
    pub start: usize,
    pub end: Option<usize>,
    pub cursor: usize,
    pub limit: usize,
    pub strings: bool,
    pub max_len: usize,
}
impl Default for JniInspectQuery {
    fn default() -> Self {
        Self {
            in_fn: None,
            name: None,
            jobject: None,
            start: 0,
            end: None,
            cursor: 0,
            limit: 200,
            strings: false,
            max_len: 256,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct JniInspectionHit {
    #[serde(flatten)]
    pub call: JniCallHit,
    pub match_args: Vec<&'static str>,
    pub string_preview: Option<super::jni_strings::JniStringHit>,
}
#[derive(Debug, Serialize)]
pub struct JniInspection {
    pub count: usize,
    pub returned: usize,
    pub truncated: bool,
    pub cursor: usize,
    pub next_cursor: Option<usize>,
    pub start: usize,
    pub end: usize,
    pub encoding: Option<&'static str>,
    pub display_encoding: Option<&'static str>,
    pub hits: Vec<JniInspectionHit>,
    pub vtable_size: usize,
}
pub fn inspect(
    state: &AnalysisContext,
    q: JniInspectQuery,
) -> Result<JniInspection, AnalysisError> {
    if q.limit == 0 {
        return Err(AnalysisError::invalid("limit must be positive"));
    }
    let target = q
        .jobject
        .as_deref()
        .map(crate::address_parse::parse_address)
        .transpose()
        .map_err(|e| AnalysisError::invalid(e.to_string()))?;
    let end = q
        .end
        .unwrap_or(state.inner.trace.len())
        .min(state.inner.trace.len());
    if q.start > end {
        return Err(AnalysisError::invalid("start exceeds end"));
    }
    let scan = state.inner.jni_calls();
    let mut count = 0;
    let mut hits = Vec::new();
    for call in &scan.calls {
        if call.idx < q.start
            || call.idx >= end
            || q.in_fn.as_ref().is_some_and(|name| &call.func_name != name)
            || q.name.as_ref().is_some_and(|name| &call.jni_fn != name)
        {
            continue;
        }
        if q.strings
            && !matches!(
                call.jni_fn.as_str(),
                "NewStringUTF" | "GetStringUTFChars" | "ReleaseStringUTFChars"
            )
        {
            continue;
        }
        let match_args: Vec<_> = ["x1", "x2", "x3", "x4"]
            .into_iter()
            .filter(|reg| target.is_some() && call.arg(reg) == target)
            .collect();
        if target.is_some() && match_args.is_empty() {
            continue;
        }
        let ordinal = count;
        count += 1;
        if ordinal < q.cursor || hits.len() >= q.limit.min(MAX_HITS) {
            continue;
        }
        let string_preview = if q.strings {
            super::jni_strings::preview_call(state, call, q.max_len)?
        } else {
            None
        };
        hits.push(JniInspectionHit {
            call: jni_call_hit(call),
            match_args,
            string_preview,
        });
    }
    let next = q.cursor.saturating_add(hits.len());
    let truncated = next < count;
    Ok(JniInspection {
        count,
        returned: hits.len(),
        truncated,
        cursor: q.cursor,
        next_cursor: truncated.then_some(next),
        start: q.start,
        end,
        encoding: q.strings.then_some("modified_utf8"),
        display_encoding: q.strings.then_some("utf8_lossy"),
        hits,
        vtable_size: scan.vtable_size,
    })
}
