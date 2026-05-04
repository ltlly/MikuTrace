//! GET /api/reg-timeline and /api/mem-diff.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RegTimelineQuery {
    pub reg: String,
    #[serde(default)]
    pub start: usize,
    #[serde(default = "default_end")]
    pub end: isize,
    #[serde(default = "default_max_points")]
    pub max_points: usize,
}

fn default_end() -> isize {
    -1
}

fn default_max_points() -> usize {
    1000
}

#[derive(Debug, Serialize)]
pub struct RegTimelinePoint {
    pub idx: usize,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct RegTimelineResponse {
    pub reg: String,
    pub start: usize,
    pub end: usize,
    pub count: usize,
    pub points: Vec<RegTimelinePoint>,
    pub truncated: bool,
}

pub async fn reg_timeline_handler(
    State(state): State<AppState>,
    Query(q): Query<RegTimelineQuery>,
) -> Result<Json<RegTimelineResponse>, StatusCode> {
    if q.reg == "xzr" || q.reg == "wzr" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let n = state.inner.trace.len();
    let end = if q.end < 0 || q.end as usize > n {
        n
    } else {
        q.end as usize
    };
    let start = q.start.min(end);
    let mut points = Vec::new();
    let mut prev: Option<u64> = None;
    let mut truncated = false;
    for i in start..end {
        let record = state.inner.trace.record(i);
        let Some(value) = record.reg_by_name(&q.reg) else {
            return Err(StatusCode::BAD_REQUEST);
        };
        if prev != Some(value) {
            if points.len() >= q.max_points {
                truncated = true;
                break;
            }
            points.push(RegTimelinePoint {
                idx: i,
                value: format!("{value:#x}"),
            });
            prev = Some(value);
        }
    }
    Ok(Json(RegTimelineResponse {
        reg: q.reg,
        start,
        end,
        count: points.len(),
        points,
        truncated,
    }))
}

#[derive(Debug, Deserialize)]
pub struct MemDiffQuery {
    pub idx: usize,
    pub addr: String,
    #[serde(default = "default_mem_diff_size")]
    pub size: usize,
}

fn default_mem_diff_size() -> usize {
    16
}

#[derive(Debug, Serialize)]
pub struct MemDiffByte {
    pub addr: String,
    pub before: Option<u8>,
    pub after: Option<u8>,
    pub changed: bool,
}

#[derive(Debug, Serialize)]
pub struct MemDiffResponse {
    pub status: &'static str,
    pub idx: usize,
    pub addr: String,
    pub size: usize,
    pub bytes: Vec<MemDiffByte>,
    pub changed_count: usize,
}

pub async fn mem_diff_handler(
    State(state): State<AppState>,
    Query(q): Query<MemDiffQuery>,
) -> Json<MemDiffResponse> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || mem_diff_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "mem diff worker failed: {err}");
                MemDiffResponse {
                    status: "error",
                    idx: 0,
                    addr: String::new(),
                    size: 0,
                    bytes: Vec::new(),
                    changed_count: 0,
                }
            }),
    )
}

fn mem_diff_response(inner: &crate::state::AppStateInner, q: MemDiffQuery) -> MemDiffResponse {
    let start = parse_int(&q.addr).unwrap_or(0);
    let before_t = q.idx.saturating_sub(1) as u64;
    let after_t = q.idx as u64;
    let mut bytes = Vec::with_capacity(q.size);
    let mut changed_count = 0usize;
    let mem = match inner.memshadow_if_ready() {
        Some(mem) => mem,
        None if inner.memshadow_status() == "idle" => inner.memshadow(),
        None => {
            return MemDiffResponse {
                status: "loading",
                idx: q.idx,
                addr: q.addr,
                size: q.size,
                bytes,
                changed_count,
            };
        }
    };
    for offset in 0..q.size {
        let addr = start + offset as u64;
        let (before, _, _) = mem.byte_at(addr, before_t);
        let (after, _, _) = mem.byte_at(addr, after_t);
        let changed = before != after;
        if changed {
            changed_count += 1;
        }
        bytes.push(MemDiffByte {
            addr: format!("{addr:#x}"),
            before,
            after,
            changed,
        });
    }
    MemDiffResponse {
        status: "ready",
        idx: q.idx,
        addr: q.addr,
        size: q.size,
        bytes,
        changed_count,
    }
}

fn parse_int(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}
