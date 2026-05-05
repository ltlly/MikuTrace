//! GET /api/reg-timeline and /api/mem-diff.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::thread;

use crate::state::AppState;

const REG_TIMELINE_PARALLEL_MIN_RECORDS: usize = 250_000;
const REG_TIMELINE_MIN_CHUNK_RECORDS: usize = 200_000;
const REG_TIMELINE_DIRECT_SCAN_RECORDS: usize = 250_000;
const REG_TIMELINE_CACHE_MAX_POINTS: usize = 500_000;
const MAX_REG_TIMELINE_POINTS: usize = 10_000;
const MAX_MEM_DIFF_SIZE: usize = 4_096;

pub(crate) fn reg_timeline_worker_count(records: usize) -> usize {
    tracemiku_core::parallel::worker_count(
        records,
        "TRACEMIKU_REG_TIMELINE_THREADS",
        REG_TIMELINE_PARALLEL_MIN_RECORDS,
        REG_TIMELINE_MIN_CHUNK_RECORDS,
    )
}

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

fn effective_max_points(raw: usize) -> usize {
    raw.min(MAX_REG_TIMELINE_POINTS)
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
    let inner = state.inner.clone();
    let response = tokio::task::spawn_blocking(move || reg_timeline_response(&inner, q))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "reg timeline worker failed: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })??;
    Ok(Json(response))
}

fn reg_timeline_response(
    inner: &crate::state::AppStateInner,
    mut q: RegTimelineQuery,
) -> Result<RegTimelineResponse, StatusCode> {
    q.max_points = effective_max_points(q.max_points);
    let n = inner.trace.len();
    let end = if q.end < 0 || q.end as usize > n {
        n
    } else {
        q.end as usize
    };
    let start = q.start.min(end);
    if let Some(timeline) = lookup_cached_reg_timeline(inner, &q.reg) {
        return reg_timeline_response_from_timeline(inner, q, start, end, &timeline);
    }

    if let Some((points, truncated)) =
        try_direct_reg_timeline(inner, &q.reg, start, end, q.max_points)?
    {
        return Ok(RegTimelineResponse {
            reg: q.reg,
            start,
            end,
            count: points.len(),
            points,
            truncated,
        });
    }

    let timeline = cached_reg_timeline(inner, &q.reg)?;
    reg_timeline_response_from_timeline(inner, q, start, end, &timeline)
}

fn reg_timeline_response_from_timeline(
    inner: &crate::state::AppStateInner,
    q: RegTimelineQuery,
    start: usize,
    end: usize,
    timeline: &[(usize, u64)],
) -> Result<RegTimelineResponse, StatusCode> {
    let mut points = Vec::new();
    let mut truncated = false;

    if start < end {
        let start_value = inner
            .trace
            .record(start)
            .reg_by_name(&q.reg)
            .ok_or(StatusCode::BAD_REQUEST)?;
        push_reg_timeline_point(
            &mut points,
            start,
            start_value,
            q.max_points,
            &mut truncated,
        );
        if !truncated {
            for &(idx, value) in timeline.iter() {
                if idx <= start {
                    continue;
                }
                if idx >= end {
                    break;
                }
                if !push_reg_timeline_point(&mut points, idx, value, q.max_points, &mut truncated) {
                    break;
                }
            }
        }
    }

    Ok(RegTimelineResponse {
        reg: q.reg,
        start,
        end,
        count: points.len(),
        points,
        truncated,
    })
}

fn push_reg_timeline_point(
    points: &mut Vec<RegTimelinePoint>,
    idx: usize,
    value: u64,
    max_points: usize,
    truncated: &mut bool,
) -> bool {
    if points.len() >= max_points {
        *truncated = true;
        return false;
    }
    points.push(RegTimelinePoint {
        idx,
        value: format!("{value:#x}"),
    });
    true
}

fn try_direct_reg_timeline(
    inner: &crate::state::AppStateInner,
    reg: &str,
    start: usize,
    end: usize,
    max_points: usize,
) -> Result<Option<(Vec<RegTimelinePoint>, bool)>, StatusCode> {
    let mut points = Vec::new();
    let mut prev: Option<u64> = None;
    let mut truncated = false;
    let budget_end = start
        .saturating_add(REG_TIMELINE_DIRECT_SCAN_RECORDS)
        .min(end);

    for i in start..budget_end {
        let value = inner
            .trace
            .record(i)
            .reg_by_name(reg)
            .ok_or(StatusCode::BAD_REQUEST)?;
        if prev != Some(value) {
            if !push_reg_timeline_point(&mut points, i, value, max_points, &mut truncated) {
                return Ok(Some((points, true)));
            }
            prev = Some(value);
        }
    }

    if budget_end == end {
        Ok(Some((points, false)))
    } else {
        Ok(None)
    }
}

fn cached_reg_timeline(
    inner: &crate::state::AppStateInner,
    reg: &str,
) -> Result<Arc<Vec<(usize, u64)>>, StatusCode> {
    if let Some(cached) = lookup_cached_reg_timeline(inner, reg) {
        return Ok(cached);
    }

    let timeline = Arc::new(build_reg_timeline(inner, reg)?);
    if timeline.len() > REG_TIMELINE_CACHE_MAX_POINTS {
        tracing::info!(
            target: "tracemiku-server",
            reg,
            points = timeline.len(),
            max_points = REG_TIMELINE_CACHE_MAX_POINTS,
            "register timeline too large to cache"
        );
        return Ok(timeline);
    }

    Ok(inner
        .reg_timeline_cache
        .lock()
        .expect("reg timeline cache poisoned")
        .entry(reg.to_string())
        .or_insert_with(|| timeline.clone())
        .clone())
}

fn lookup_cached_reg_timeline(
    inner: &crate::state::AppStateInner,
    reg: &str,
) -> Option<Arc<Vec<(usize, u64)>>> {
    inner
        .reg_timeline_cache
        .lock()
        .expect("reg timeline cache poisoned")
        .get(reg)
        .cloned()
}

fn build_reg_timeline(
    inner: &crate::state::AppStateInner,
    reg: &str,
) -> Result<Vec<(usize, u64)>, StatusCode> {
    let n = inner.trace.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    // Validate before spawning workers so bad register names fail quickly.
    inner
        .trace
        .record(0)
        .reg_by_name(reg)
        .ok_or(StatusCode::BAD_REQUEST)?;

    let workers = reg_timeline_worker_count(n);
    if workers <= 1 {
        return build_reg_timeline_range(inner, reg, 0, n);
    }

    tracing::info!(
        target: "tracemiku-server",
        records = n,
        workers,
        reg,
        "building register timeline in parallel"
    );
    let chunk_size = n.div_ceil(workers);
    let partials = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let start = worker * chunk_size;
            let end = (start + chunk_size).min(n);
            if start >= end {
                continue;
            }
            handles.push(scope.spawn(move || build_reg_timeline_range(inner, reg, start, end)));
        }
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            })
            .collect::<Result<Vec<_>, StatusCode>>()
    })?;

    let mut merged = Vec::new();
    let mut prev: Option<u64> = None;
    for partial in partials {
        for (idx, value) in partial {
            if prev != Some(value) {
                merged.push((idx, value));
                prev = Some(value);
            }
        }
    }
    Ok(merged)
}

fn build_reg_timeline_range(
    inner: &crate::state::AppStateInner,
    reg: &str,
    start: usize,
    end: usize,
) -> Result<Vec<(usize, u64)>, StatusCode> {
    let mut points = Vec::new();
    let mut prev: Option<u64> = None;
    for i in start..end {
        let value = inner
            .trace
            .record(i)
            .reg_by_name(reg)
            .ok_or(StatusCode::BAD_REQUEST)?;
        if prev != Some(value) {
            points.push((i, value));
            prev = Some(value);
        }
    }
    Ok(points)
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

fn effective_mem_diff_size(raw: usize) -> usize {
    raw.clamp(1, MAX_MEM_DIFF_SIZE)
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
    let size = effective_mem_diff_size(q.size);
    let before_t = q.idx.saturating_sub(1) as u64;
    let after_t = q.idx as u64;
    let mut bytes = Vec::with_capacity(size);
    let mut changed_count = 0usize;
    let mem = match inner.memshadow_ready_or_block_if_idle() {
        Ok(mem) => mem,
        Err(status) => {
            return MemDiffResponse {
                status,
                idx: q.idx,
                addr: q.addr,
                size,
                bytes,
                changed_count,
            };
        }
    };
    for offset in 0..size {
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
        size,
        bytes,
        changed_count,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        effective_max_points, effective_mem_diff_size, MAX_MEM_DIFF_SIZE, MAX_REG_TIMELINE_POINTS,
    };

    #[test]
    fn effective_max_points_caps_extreme_requests() {
        assert_eq!(effective_max_points(0), 0);
        assert_eq!(effective_max_points(1000), 1000);
        assert_eq!(effective_max_points(usize::MAX), MAX_REG_TIMELINE_POINTS);
    }

    #[test]
    fn effective_mem_diff_size_caps_extreme_requests() {
        assert_eq!(effective_mem_diff_size(0), 1);
        assert_eq!(effective_mem_diff_size(16), 16);
        assert_eq!(effective_mem_diff_size(usize::MAX), MAX_MEM_DIFF_SIZE);
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
