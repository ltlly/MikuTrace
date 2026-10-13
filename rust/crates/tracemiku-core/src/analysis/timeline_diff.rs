//! 有界寄存器变化与等值查询。

use super::AnalysisError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::thread;

use crate::analysis::context::AnalysisContext;

const REG_TIMELINE_PARALLEL_MIN_RECORDS: usize = 250_000;
const REG_TIMELINE_MIN_CHUNK_RECORDS: usize = 200_000;
const REG_TIMELINE_DIRECT_SCAN_RECORDS: usize = 250_000;
const REG_TIMELINE_CACHE_MAX_POINTS: usize = 500_000;
const MAX_REG_TIMELINE_POINTS: usize = 10_000;

pub(crate) fn reg_timeline_worker_count(records: usize) -> usize {
    crate::parallel::worker_count(
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

pub fn reg_timeline(
    state: &AnalysisContext,
    q: RegTimelineQuery,
) -> Result<RegTimelineResponse, AnalysisError> {
    if q.reg == "xzr" || q.reg == "wzr" {
        return Err(AnalysisError::invalid("invalid query"));
    }
    let inner = state.inner.clone();
    let response = (reg_timeline_response(&inner, q))?;
    Ok(response)
}

fn reg_timeline_response(
    inner: &crate::analysis::context::AnalysisData,
    mut q: RegTimelineQuery,
) -> Result<RegTimelineResponse, AnalysisError> {
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
    inner: &crate::analysis::context::AnalysisData,
    q: RegTimelineQuery,
    start: usize,
    end: usize,
    timeline: &[(usize, u64)],
) -> Result<RegTimelineResponse, AnalysisError> {
    let mut points = Vec::new();
    let mut truncated = false;

    if start < end {
        let start_value = inner
            .trace
            .record(start)
            .reg_by_name(&q.reg)
            .ok_or(AnalysisError::invalid("invalid query"))?;
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
    inner: &crate::analysis::context::AnalysisData,
    reg: &str,
    start: usize,
    end: usize,
    max_points: usize,
) -> Result<Option<(Vec<RegTimelinePoint>, bool)>, AnalysisError> {
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
            .ok_or(AnalysisError::invalid("invalid query"))?;
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
    inner: &crate::analysis::context::AnalysisData,
    reg: &str,
) -> Result<Arc<Vec<(usize, u64)>>, AnalysisError> {
    if let Some(cached) = lookup_cached_reg_timeline(inner, reg) {
        return Ok(cached);
    }

    let timeline = Arc::new(build_reg_timeline(inner, reg)?);
    if timeline.len() > REG_TIMELINE_CACHE_MAX_POINTS {
        tracing::info!(
            target: "tracemiku-core",
            reg,
            points = timeline.len(),
            max_points = REG_TIMELINE_CACHE_MAX_POINTS,
            "register timeline too large to cache"
        );
        return Ok(timeline);
    }

    Ok(
        crate::analysis::context::lock_or_recover(&inner.reg_timeline_cache)
            .entry(reg.to_string())
            .or_insert_with(|| timeline.clone())
            .clone(),
    )
}

fn lookup_cached_reg_timeline(
    inner: &crate::analysis::context::AnalysisData,
    reg: &str,
) -> Option<Arc<Vec<(usize, u64)>>> {
    crate::analysis::context::lock_or_recover(&inner.reg_timeline_cache)
        .get(reg)
        .cloned()
}

fn build_reg_timeline(
    inner: &crate::analysis::context::AnalysisData,
    reg: &str,
) -> Result<Vec<(usize, u64)>, AnalysisError> {
    let n = inner.trace.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    // Validate before spawning workers so bad register names fail quickly.
    inner
        .trace
        .record(0)
        .reg_by_name(reg)
        .ok_or(AnalysisError::invalid("invalid query"))?;

    let workers = reg_timeline_worker_count(n);
    if workers <= 1 {
        return build_reg_timeline_range(inner, reg, 0, n);
    }

    tracing::info!(
        target: "tracemiku-core",
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
                    .map_err(|_| AnalysisError::internal("analysis failed"))?
            })
            .collect::<Result<Vec<_>, AnalysisError>>()
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
    inner: &crate::analysis::context::AnalysisData,
    reg: &str,
    start: usize,
    end: usize,
) -> Result<Vec<(usize, u64)>, AnalysisError> {
    let mut points = Vec::new();
    let mut prev: Option<u64> = None;
    for i in start..end {
        let value = inner
            .trace
            .record(i)
            .reg_by_name(reg)
            .ok_or(AnalysisError::invalid("invalid query"))?;
        if prev != Some(value) {
            points.push((i, value));
            prev = Some(value);
        }
    }
    Ok(points)
}

#[cfg(test)]
mod tests {
    use super::{effective_max_points, MAX_REG_TIMELINE_POINTS};

    #[test]
    fn effective_max_points_caps_extreme_requests() {
        assert_eq!(effective_max_points(0), 0);
        assert_eq!(effective_max_points(1000), 1000);
        assert_eq!(effective_max_points(usize::MAX), MAX_REG_TIMELINE_POINTS);
    }
}

impl Default for RegTimelineQuery {
    fn default() -> Self {
        Self {
            reg: Default::default(),
            start: Default::default(),
            end: default_end(),
            max_points: default_max_points(),
        }
    }
}

/// 等值查询返回每次匹配的执行前状态，变化查询复用原时间线实现。
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct RegInspectQuery {
    pub reg: String,
    pub start: usize,
    pub end: isize,
    pub max_points: usize,
    pub equals: Option<String>,
}
impl Default for RegInspectQuery {
    fn default() -> Self {
        Self {
            reg: String::new(),
            start: 0,
            end: -1,
            max_points: 1000,
            equals: None,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct RegInspection {
    #[serde(flatten)]
    pub timeline: RegTimelineResponse,
    pub mode: &'static str,
    pub next_cursor: Option<usize>,
}
pub fn inspect_register(
    state: &AnalysisContext,
    q: RegInspectQuery,
) -> Result<RegInspection, AnalysisError> {
    let end = if q.end < 0 {
        state.inner.trace.len()
    } else {
        (q.end as usize).min(state.inner.trace.len())
    };
    if q.max_points == 0 || q.start > end || !super::records::valid_register(&q.reg) {
        return Err(AnalysisError::invalid(
            "invalid register, window or zero limit",
        ));
    }
    let Some(raw) = q.equals else {
        let timeline = reg_timeline(
            state,
            RegTimelineQuery {
                reg: q.reg,
                start: q.start,
                end: q.end,
                max_points: q.max_points,
            },
        )?;
        let next_cursor = timeline.truncated.then(|| {
            timeline
                .points
                .last()
                .map_or(q.start, |p| p.idx.saturating_add(1))
        });
        return Ok(RegInspection {
            timeline,
            mode: "changes",
            next_cursor,
        });
    };
    let target = crate::address_parse::parse_address(&raw)
        .map_err(|e| AnalysisError::invalid(e.to_string()))?;
    let end = if q.end < 0 {
        state.inner.trace.len()
    } else {
        (q.end as usize).min(state.inner.trace.len())
    };
    if q.start > end || q.max_points == 0 {
        return Err(AnalysisError::invalid(
            "invalid register window or zero limit",
        ));
    }
    let mut points = Vec::new();
    let mut truncated = false;
    let limit = q.max_points.min(MAX_REG_TIMELINE_POINTS);
    for idx in q.start..end {
        let value = state
            .inner
            .trace
            .record(idx)
            .reg_by_name(&q.reg)
            .ok_or_else(|| AnalysisError::invalid("unknown register"))?;
        if value != target {
            continue;
        }
        if points.len() == limit {
            truncated = true;
            break;
        }
        points.push(RegTimelinePoint {
            idx,
            value: format!("{value:#x}"),
        });
    }
    let next_cursor = truncated.then(|| points.last().unwrap().idx + 1);
    Ok(RegInspection {
        timeline: RegTimelineResponse {
            reg: q.reg,
            start: q.start,
            end,
            count: points.len(),
            points,
            truncated,
        },
        mode: "equals",
        next_cursor,
    })
}
