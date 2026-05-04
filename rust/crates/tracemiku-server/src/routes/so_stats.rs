//! GET /api/so-stats?top=&all=

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct SoStatsQuery {
    #[serde(default = "default_top")]
    pub top: usize,
    #[serde(default)]
    pub all: bool,
}

fn default_top() -> usize {
    50
}

#[derive(Debug, Serialize)]
pub struct SoStatsModule {
    pub name: String,
    pub base: String,
    pub end: String,
    pub size: u64,
    pub records: usize,
    pub percent: f64,
}

#[derive(Debug, Serialize)]
pub struct SoStatsResponse {
    pub records: usize,
    pub modules_total: usize,
    pub unknown_records: usize,
    pub unknown_percent: f64,
    pub modules: Vec<SoStatsModule>,
}

pub async fn so_stats_handler(
    State(state): State<AppState>,
    Query(q): Query<SoStatsQuery>,
) -> Json<SoStatsResponse> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || so_stats_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "so stats worker failed: {err}");
                SoStatsResponse {
                    records: 0,
                    modules_total: 0,
                    unknown_records: 0,
                    unknown_percent: 0.0,
                    modules: Vec::new(),
                }
            }),
    )
}

fn so_stats_response(inner: &crate::state::AppStateInner, q: SoStatsQuery) -> SoStatsResponse {
    let total = inner.trace.len();
    let mut counts = vec![0usize; inner.meta.modules.len()];
    let mut unknown_records = 0usize;

    let ranges: Vec<(u64, u64)> = inner
        .meta
        .modules
        .iter()
        .map(|m| {
            let base = u64::from_str_radix(m.base.trim_start_matches("0x"), 16).unwrap_or(0);
            let end = u64::from_str_radix(m.end.trim_start_matches("0x"), 16)
                .unwrap_or_else(|_| base.saturating_add(m.size));
            (base, end)
        })
        .collect();

    for (&pc, idxs) in &inner.index.pc_to_idxs {
        let records = idxs.len();
        if let Some((idx, _)) = ranges
            .iter()
            .enumerate()
            .find(|(_, (base, end))| pc >= *base && pc < *end)
        {
            counts[idx] += records;
        } else {
            unknown_records += records;
        }
    }

    let mut modules: Vec<SoStatsModule> = inner
        .meta
        .modules
        .iter()
        .cloned()
        .zip(counts)
        .filter(|(_, records)| q.all || *records > 0)
        .map(|(m, records)| SoStatsModule {
            name: m.name,
            base: m.base,
            end: m.end,
            size: m.size,
            records,
            percent: percent(records, total),
        })
        .collect();
    modules.sort_by(|a, b| b.records.cmp(&a.records).then_with(|| a.name.cmp(&b.name)));
    if !q.all && q.top > 0 {
        modules.truncate(q.top);
    }

    SoStatsResponse {
        records: total,
        modules_total: inner.meta.modules.len(),
        unknown_records,
        unknown_percent: percent(unknown_records, total),
        modules,
    }
}

fn percent(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64) * 100.0 / (total as f64)
    }
}
