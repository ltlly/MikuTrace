//! GET /api/bfs-slice — backward BFS slice over the persistent dependency CSR.
//!
//! Returns the rows the seed transitively depends on. A `data_only=true` query
//! drops control edges, matching the convention from `tracemiku_core::bfs_slice`
//! (and `imj01y/trace-ui` `query/slice.rs`).
//!
//! Multi-seed queries accept comma-separated `idxs=`, `regs=`, or `addrs=`. The
//! `mode=` query selects how seed slices combine: `union` (default) or
//! `intersection` ("common ancestors").

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use tracemiku_core::bfs_slice::{
    bfs_slice_multi, slice_edge_stats, Bitset, SliceMode, SliceOptions, SliceResult,
};

use crate::routes::seed_resolver::{
    annotate_outside_trace, render_dep_node, resolve_addr, resolve_reg, split_csv, DepNode,
    ResolvedSeed,
};
use crate::state::AppState;

const DEFAULT_LIMIT: usize = 5_000;
const MAX_LIMIT: usize = 200_000;
const MAX_SEEDS: usize = 16;
/// Maximum number of enriched (pc/asm/func) rows we serialize. Beyond this the
/// `slice` array drops back to plain idx integers so multi-MB responses stay
/// within axum's default body limits.
const ROW_DETAIL_BUDGET: usize = 2_000;

#[derive(Debug, Deserialize)]
pub struct BfsSliceQuery {
    pub idx: Option<usize>,
    pub idxs: Option<String>,
    pub reg: Option<String>,
    pub regs: Option<String>,
    pub addr: Option<String>,
    pub addrs: Option<String>,
    pub before: Option<usize>,
    #[serde(default)]
    pub data_only: bool,
    #[serde(default = "default_limit")]
    pub limit: usize,
    pub mode: Option<String>,
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

#[derive(Debug, Serialize, Default)]
pub struct EdgeStats {
    pub reg: usize,
    pub address: usize,
    pub mem: usize,
    pub control: usize,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct BfsSliceResponse {
    pub status: &'static str,
    pub seed: ResolvedSeed,
    pub seeds: Vec<ResolvedSeed>,
    /// Slice idxs — always present, in BFS-discovery order for single-seed
    /// queries and ascending order for multi-seed queries.
    pub slice: Vec<usize>,
    /// First [`ROW_DETAIL_BUDGET`] rows enriched with pc/asm/func/expression so
    /// the client doesn't need a per-row `/api/record/{idx}` round trip.
    pub rows: Vec<DepNode>,
    pub slice_count: usize,
    pub truncated: bool,
    pub rows_capped: bool,
    pub node_limit: usize,
    pub data_only: bool,
    pub edge_stats: EdgeStats,
    pub mode: &'static str,
}

pub async fn bfs_slice_handler(
    State(state): State<AppState>,
    Query(q): Query<BfsSliceQuery>,
) -> Result<Json<BfsSliceResponse>, (StatusCode, String)> {
    let response = tokio::task::spawn_blocking(move || bfs_slice_response(&state, q))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "bfs-slice worker failed: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bfs-slice worker failed".to_string(),
            )
        })?;
    Ok(Json(response))
}

fn bfs_slice_response(state: &AppState, q: BfsSliceQuery) -> BfsSliceResponse {
    let before = q.before.unwrap_or_else(|| state.inner.trace.len());
    let mode = parse_mode(q.mode.as_deref());
    let limit = q.limit.clamp(1, MAX_LIMIT);
    let opts = SliceOptions {
        data_only: q.data_only,
        max_nodes: limit,
    };

    let mut resolved = resolve_all_seeds(state, &q, before);
    if resolved.is_empty() {
        let placeholder = ResolvedSeed::placeholder("provide idx, idxs, reg, regs, addr, or addrs");
        return BfsSliceResponse {
            status: "ready",
            seed: placeholder.clone(),
            seeds: vec![placeholder],
            slice: Vec::new(),
            rows: Vec::new(),
            slice_count: 0,
            truncated: false,
            rows_capped: false,
            node_limit: limit,
            data_only: q.data_only,
            edge_stats: EdgeStats::default(),
            mode: mode_str(mode),
        };
    }

    let trace_len = state.inner.trace.len();
    annotate_outside_trace(resolved.iter_mut(), trace_len);

    let analysis = state.inner.analysis_index();
    let valid_seeds: Vec<usize> = resolved
        .iter()
        .filter_map(|s| s.idx.filter(|&idx| idx < trace_len))
        .collect();
    let result: SliceResult = if valid_seeds.is_empty() {
        SliceResult {
            marked: Bitset::with_len(trace_len),
            idxs: Vec::new(),
            truncated: false,
        }
    } else {
        bfs_slice_multi(&analysis.deps, trace_len, &valid_seeds, mode, opts)
    };
    let stats = slice_edge_stats(&analysis.deps, &result);
    let primary = resolved[0].clone();
    let rows = render_rows(state, &result.idxs);
    let rows_capped = result.idxs.len() > rows.len();
    BfsSliceResponse {
        status: "ready",
        seed: primary,
        seeds: resolved,
        slice_count: result.idxs.len(),
        rows,
        slice: result.idxs,
        truncated: result.truncated,
        rows_capped,
        node_limit: limit,
        data_only: q.data_only,
        edge_stats: EdgeStats {
            reg: stats.reg,
            address: stats.address,
            mem: stats.mem,
            control: stats.control,
            total: stats.total(),
        },
        mode: mode_str(mode),
    }
}

fn render_rows(state: &AppState, idxs: &[usize]) -> Vec<DepNode> {
    idxs.iter()
        .take(ROW_DETAIL_BUDGET)
        .map(|&idx| render_dep_node(state, idx, 0, None))
        .collect()
}

fn parse_mode(raw: Option<&str>) -> SliceMode {
    match raw.unwrap_or("union").to_ascii_lowercase().as_str() {
        "intersection" | "intersect" | "and" => SliceMode::Intersection,
        _ => SliceMode::Union,
    }
}

fn mode_str(mode: SliceMode) -> &'static str {
    match mode {
        SliceMode::Union => "union",
        SliceMode::Intersection => "intersection",
    }
}

fn resolve_all_seeds(state: &AppState, q: &BfsSliceQuery, before: usize) -> Vec<ResolvedSeed> {
    let mut seeds: Vec<ResolvedSeed> = Vec::new();

    let push = |seeds: &mut Vec<ResolvedSeed>, seed: ResolvedSeed| -> bool {
        if seeds.len() >= MAX_SEEDS {
            return false;
        }
        seeds.push(seed);
        true
    };

    if let Some(idx) = q.idx {
        push(&mut seeds, ResolvedSeed::for_idx(idx, None, q.before));
    }
    if let Some(idxs_raw) = q.idxs.as_deref() {
        for token in split_csv(idxs_raw) {
            if !push(&mut seeds, ResolvedSeed::for_idx_token(token, q.before)) {
                break;
            }
        }
    }
    if let Some(reg) = q.reg.as_deref() {
        push(&mut seeds, resolve_reg(state, reg, before));
    }
    if let Some(regs_raw) = q.regs.as_deref() {
        for token in split_csv(regs_raw) {
            if !push(&mut seeds, resolve_reg(state, token, before)) {
                break;
            }
        }
    }
    if let Some(addr) = q.addr.as_deref() {
        push(&mut seeds, resolve_addr(state, addr, before));
    }
    if let Some(addrs_raw) = q.addrs.as_deref() {
        for token in split_csv(addrs_raw) {
            if !push(&mut seeds, resolve_addr(state, token, before)) {
                break;
            }
        }
    }
    seeds
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::parse::parse_dec_u64;

    #[test]
    fn parse_mode_defaults_to_union() {
        assert!(matches!(parse_mode(None), SliceMode::Union));
        assert!(matches!(parse_mode(Some("union")), SliceMode::Union));
        assert!(matches!(parse_mode(Some("garbage")), SliceMode::Union));
    }

    #[test]
    fn parse_mode_accepts_intersection_aliases() {
        assert!(matches!(
            parse_mode(Some("intersection")),
            SliceMode::Intersection
        ));
        assert!(matches!(
            parse_mode(Some("intersect")),
            SliceMode::Intersection
        ));
        assert!(matches!(parse_mode(Some("and")), SliceMode::Intersection));
        assert!(matches!(
            parse_mode(Some("INTERSECTION")),
            SliceMode::Intersection
        ));
    }

    #[test]
    fn parse_dec_u64_accepts_hex_and_decimal() {
        assert_eq!(parse_dec_u64("0x42"), Some(0x42));
        assert_eq!(parse_dec_u64("66"), Some(66));
    }
}
