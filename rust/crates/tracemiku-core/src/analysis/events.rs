//! 直接读取采集 sidecar；缺失、损坏、预算耗尽分别表达，不加载 trace。
use super::AnalysisError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    path::Path,
};
const BUDGET: usize = 8 * 1024 * 1024;
const MAX_LINE: usize = 64 * 1024;
// 留出顶层字段、标点和计数器的序列化空间。
const ENVELOPE_BYTES: usize = 1024;

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub source: String,
    pub id: Option<String>,
    pub status: Option<String>,
    pub is_fork_like: Option<bool>,
    pub start: Option<usize>,
    pub end: Option<usize>,
    pub cursor: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
}
fn default_limit() -> usize {
    1000
}
#[derive(Debug, Serialize)]
pub struct EventRow {
    pub source: String,
    pub cursor: String,
    pub event: Value,
}
#[derive(Debug, Serialize)]
pub struct EventsResponse {
    pub source: String,
    pub available: bool,
    pub returned: usize,
    pub truncated: bool,
    pub next_cursor: Option<String>,
    pub invalid_lines: usize,
    pub oversized_lines: usize,
    pub scanned_bytes: usize,
    pub budget_bytes: usize,
    pub stop_reason: &'static str,
    pub events: Vec<EventRow>,
}
fn matches(event: &Value, q: &EventsQuery) -> bool {
    let idx = event.get("trace_idx").and_then(Value::as_u64);
    !q.id
        .as_ref()
        .is_some_and(|id| event.get("id").and_then(Value::as_str) != Some(id))
        && !q
            .status
            .as_ref()
            .is_some_and(|s| event.get("attach_status").and_then(Value::as_str) != Some(s))
        && !q
            .is_fork_like
            .is_some_and(|b| event.get("is_fork_like").and_then(Value::as_bool) != Some(b))
        && !q.start.is_some_and(|lo| idx.is_none_or(|i| i < lo as u64))
        && !q.end.is_some_and(|hi| idx.is_none_or(|i| i >= hi as u64))
}
fn io_error(e: std::io::Error) -> AnalysisError {
    AnalysisError::internal(e.to_string())
}

pub fn read_events(path: &Path, q: EventsQuery) -> Result<EventsResponse, AnalysisError> {
    if !matches!(q.source.as_str(), "jni" | "fork") {
        return Err(AnalysisError::invalid("source must be jni or fork"));
    }
    if q.start.zip(q.end).is_some_and(|(a, b)| a > b) || q.limit == 0 {
        return Err(AnalysisError::invalid("invalid time window or zero limit"));
    }
    if q.source == "jni" && (q.status.is_some() || q.is_fork_like.is_some())
        || q.source == "fork" && q.id.is_some()
    {
        return Err(AnalysisError::invalid(
            "filter does not apply to selected source",
        ));
    }
    let cursor = match q.cursor.as_deref() {
        None => 0,
        Some(raw) => raw
            .strip_prefix(&format!("{}:", q.source))
            .and_then(|v| v.parse::<usize>().ok())
            .ok_or_else(|| {
                AnalysisError::invalid("cursor belongs to another source or is malformed")
            })?,
    };
    let file = path.join(if q.source == "jni" {
        "jni_hooks.jsonl"
    } else {
        "meta.json"
    });
    let mut out = EventsResponse {
        source: q.source.clone(),
        available: true,
        returned: 0,
        truncated: false,
        next_cursor: None,
        invalid_lines: 0,
        oversized_lines: 0,
        scanned_bytes: 0,
        budget_bytes: BUDGET,
        stop_reason: "end",
        events: Vec::new(),
    };
    let mut input = match std::fs::File::open(file) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            out.available = false;
            out.stop_reason = "missing";
            return Ok(out);
        }
        Err(e) => return Err(io_error(e)),
    };
    let limit = q.limit.min(5000);
    let mut output_bytes = ENVELOPE_BYTES;
    if q.source == "fork" {
        if input.metadata().map_err(io_error)?.len() > BUDGET as u64 {
            return Err(AnalysisError::limit("meta.json exceeds 8 MiB event budget"));
        }
        let mut raw = Vec::new();
        input
            .take(BUDGET as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(io_error)?;
        if raw.len() > BUDGET {
            return Err(AnalysisError::limit("meta.json exceeds 8 MiB event budget"));
        }
        out.scanned_bytes = raw.len();
        let meta: Value = serde_json::from_slice(&raw)
            .map_err(|e| AnalysisError::invalid(format!("invalid meta.json: {e}")))?;
        let events = meta
            .get("fork_events")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if cursor > events.len() {
            return Err(AnalysisError::invalid("event cursor is past end of array"));
        }
        for (ordinal, event) in events.iter().enumerate().skip(cursor) {
            if !matches(event, &q) {
                continue;
            }
            let row = EventRow {
                source: q.source.clone(),
                cursor: format!("fork:{ordinal}"),
                event: event.clone(),
            };
            let bytes = serde_json::to_vec(&row)
                .map_err(|e| AnalysisError::internal(e.to_string()))?
                .len()
                + 1;
            if bytes > BUDGET - ENVELOPE_BYTES {
                return Err(AnalysisError::limit(
                    "single fork event exceeds response budget",
                ));
            }
            if out.events.len() >= limit || output_bytes + bytes > BUDGET {
                out.truncated = true;
                out.next_cursor = Some(format!("fork:{ordinal}"));
                out.stop_reason = "limit";
                break;
            }
            output_bytes += bytes;
            out.events.push(row);
        }
    } else {
        let length = input.metadata().map_err(io_error)?.len();
        if cursor as u64 > length {
            return Err(AnalysisError::invalid("event cursor is past end of file"));
        }
        if cursor > 0 {
            input
                .seek(SeekFrom::Start(cursor as u64 - 1))
                .map_err(io_error)?;
            let mut prev = [0];
            input.read_exact(&mut prev).map_err(io_error)?;
            if cursor as u64 != length && prev[0] != b'\n' {
                return Err(AnalysisError::invalid(
                    "event cursor must point to a line boundary",
                ));
            }
        }
        input
            .seek(SeekFrom::Start(cursor as u64))
            .map_err(io_error)?;
        let mut reader = BufReader::new(input);
        let mut offset = cursor;
        loop {
            if BUDGET - out.scanned_bytes < MAX_LINE + 1 {
                out.truncated = (offset as u64) < length;
                out.next_cursor = out.truncated.then(|| format!("jni:{offset}"));
                out.stop_reason = if out.truncated { "scan_budget" } else { "end" };
                break;
            }
            let mut line = Vec::new();
            // Cap one allocation, then discard the rest of an oversized line in bounded chunks.
            let mut n = (&mut reader)
                .take((MAX_LINE + 1) as u64)
                .read_until(b'\n', &mut line)
                .map_err(io_error)?;
            if n == 0 {
                break;
            }
            out.scanned_bytes += n;
            let mut oversized = line.len() > MAX_LINE;
            while line.last() != Some(&b'\n') && n == MAX_LINE + 1 {
                if out.scanned_bytes >= BUDGET {
                    return Err(AnalysisError::limit("JNI event line exceeds scan budget"));
                }
                line.clear();
                n = (&mut reader)
                    .take((MAX_LINE + 1).min(BUDGET - out.scanned_bytes) as u64)
                    .read_until(b'\n', &mut line)
                    .map_err(io_error)?;
                out.scanned_bytes += n;
                oversized = true;
                if line.last() != Some(&b'\n') && out.scanned_bytes == BUDGET {
                    return Err(AnalysisError::limit("JNI event line exceeds scan budget"));
                }
                if n == 0 {
                    break;
                }
            }
            if oversized {
                out.oversized_lines += 1;
            }
            let row = offset;
            offset = cursor.saturating_add(out.scanned_bytes);
            if !oversized {
                match serde_json::from_slice::<Value>(&line) {
                    Ok(event) if event.is_object() => {
                        if matches(&event, &q) {
                            let event = EventRow {
                                source: q.source.clone(),
                                cursor: format!("jni:{row}"),
                                event,
                            };
                            let bytes = serde_json::to_vec(&event)
                                .map_err(|e| AnalysisError::internal(e.to_string()))?
                                .len()
                                + 1;
                            if out.events.len() == limit || output_bytes + bytes > BUDGET {
                                out.truncated = true;
                                out.next_cursor = Some(format!("jni:{row}"));
                                out.stop_reason = "limit";
                                break;
                            }
                            output_bytes += bytes;
                            out.events.push(event);
                        }
                    }
                    _ => out.invalid_lines += 1,
                }
            }
            if out.scanned_bytes >= BUDGET {
                out.truncated = !reader.fill_buf().map_err(io_error)?.is_empty();
                out.next_cursor = out.truncated.then(|| format!("jni:{offset}"));
                out.stop_reason = if out.truncated { "scan_budget" } else { "end" };
                break;
            }
        }
    }
    out.returned = out.events.len();
    Ok(out)
}
