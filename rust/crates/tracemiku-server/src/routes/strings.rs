//! GET /api/strings — printable ASCII runs from MemShadow.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use tracemiku_core::prelude::MemShadow;

use crate::state::AppState;

const DEFAULT_LIMIT: usize = 500;
const MAX_LIMIT: usize = 5_000;

#[derive(Debug, Deserialize)]
pub struct StringsQuery {
    #[serde(default = "default_min_len")]
    pub min_len: usize,
    #[serde(default)]
    pub q: String,
    /// -1 = no cursor filter; >=0 = only strings whose every byte was written
    /// at idx <= cursor. (Python uses signed int and -1 sentinel; preserved.)
    #[serde(default = "default_cursor")]
    pub cursor: i64,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_min_len() -> usize {
    4
}
fn default_cursor() -> i64 {
    -1
}
fn default_limit() -> usize {
    DEFAULT_LIMIT
}

#[derive(Debug, Serialize)]
pub struct StringEntry {
    pub addr: String,
    pub len: usize,
    pub str: String,
}

#[derive(Debug, Serialize)]
pub struct StringsResponse {
    pub status: &'static str,
    pub count: usize,
    pub returned: usize,
    pub truncated: bool,
    pub cursor: i64,
    pub strings: Vec<StringEntry>,
}

pub async fn strings_handler(
    State(state): State<AppState>,
    Query(q): Query<StringsQuery>,
) -> Json<StringsResponse> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || strings_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "strings worker failed: {err}");
                StringsResponse {
                    status: "error",
                    count: 0,
                    returned: 0,
                    truncated: false,
                    cursor: -1,
                    strings: Vec::new(),
                }
            }),
    )
}

fn strings_response(inner: &crate::state::AppStateInner, q: StringsQuery) -> StringsResponse {
    let mem = match inner.memshadow_ready_or_block_if_idle() {
        Ok(mem) => mem,
        Err(status) => {
            let status = status.status_str();
            return StringsResponse {
                status,
                count: 0,
                returned: 0,
                truncated: false,
                cursor: q.cursor,
                strings: Vec::new(),
            };
        }
    };
    let limit = effective_limit(q.limit);
    let (count, strings) = collect_strings(mem, q.min_len, &q.q, q.cursor, limit);
    let returned = strings.len();
    StringsResponse {
        status: "ready",
        count,
        returned,
        truncated: returned < count,
        cursor: q.cursor,
        strings,
    }
}

fn effective_limit(raw: usize) -> usize {
    if raw == 0 {
        MAX_LIMIT
    } else {
        raw.min(MAX_LIMIT)
    }
}

fn collect_strings(
    mem: &MemShadow,
    min_len: usize,
    query: &str,
    cursor: i64,
    limit: usize,
) -> (usize, Vec<StringEntry>) {
    if mem.bytes.is_empty() {
        return (0, Vec::new());
    }

    let needle = (!query.is_empty()).then(|| query.to_ascii_lowercase());
    let cursor = (cursor >= 0).then_some(cursor as u64);
    let mut count = 0usize;
    let mut out = Vec::with_capacity(limit.min(256));
    let mut run_start: Option<u64> = None;
    let mut run_chars: Vec<u8> = Vec::new();
    let mut prev_addr: Option<u64> = None;

    for (&addr, events) in &mem.bytes {
        if let Some(prev) = prev_addr {
            if addr != prev + 1 {
                flush_run(
                    mem,
                    &mut count,
                    &mut out,
                    &mut run_start,
                    &mut run_chars,
                    min_len,
                    needle.as_deref(),
                    cursor,
                    limit,
                );
            }
        }
        let byte = events.last().map(|event| event.byte).unwrap_or(0);
        if (32..127).contains(&byte) {
            if run_start.is_none() {
                run_start = Some(addr);
            }
            run_chars.push(byte);
        } else {
            flush_run(
                mem,
                &mut count,
                &mut out,
                &mut run_start,
                &mut run_chars,
                min_len,
                needle.as_deref(),
                cursor,
                limit,
            );
        }
        prev_addr = Some(addr);
    }
    flush_run(
        mem,
        &mut count,
        &mut out,
        &mut run_start,
        &mut run_chars,
        min_len,
        needle.as_deref(),
        cursor,
        limit,
    );

    (count, out)
}

#[allow(clippy::too_many_arguments)]
fn flush_run(
    mem: &MemShadow,
    count: &mut usize,
    out: &mut Vec<StringEntry>,
    run_start: &mut Option<u64>,
    run_chars: &mut Vec<u8>,
    min_len: usize,
    needle: Option<&str>,
    cursor: Option<u64>,
    limit: usize,
) {
    let Some(addr) = *run_start else {
        return;
    };
    if run_chars.len() >= min_len
        && cursor.is_none_or(|cursor| {
            (0..run_chars.len() as u64).all(|offset| {
                let (byte, _kind, src) = mem.byte_at(addr + offset, cursor);
                matches!((byte, src), (Some(_), Some(idx)) if (idx as u64) <= cursor)
            })
        })
    {
        let text = String::from_utf8_lossy(run_chars).into_owned();
        if needle.is_none_or(|needle| text.to_ascii_lowercase().contains(needle)) {
            *count += 1;
            if out.len() < limit {
                out.push(StringEntry {
                    addr: format!("{addr:#x}"),
                    len: text.len(),
                    str: text,
                });
            }
        }
    }
    *run_start = None;
    run_chars.clear();
}
