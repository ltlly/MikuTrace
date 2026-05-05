//! GET /api/cfg-svg
//!
//! Render the trace-derived CFG as Graphviz SVG. This is the Rust/Solid v2
//! replacement for Python webui/server.py::cfg_svg.

use std::collections::{HashMap, HashSet, VecDeque};
use std::process::Stdio;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::state::{AppState, AppStateInner, CfgSvgCached};

#[derive(Debug, Deserialize)]
pub struct CfgSvgQuery {
    #[serde(default, rename = "fn")]
    pub fn_name: String,
    #[serde(default)]
    pub pc: String,
    #[serde(default = "default_local_depth")]
    pub local_depth: usize,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub force: bool,
}

fn default_timeout() -> u64 {
    60
}

fn default_local_depth() -> usize {
    2
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum CfgSvgResponse {
    Ready {
        svg: String,
        #[serde(rename = "fn")]
        fn_name: Option<String>,
        block_count: usize,
        total_block_count: usize,
        cached: bool,
    },
    Empty {
        #[serde(rename = "fn")]
        fn_name: Option<String>,
        svg: Option<String>,
    },
    Large {
        #[serde(rename = "fn")]
        fn_name: Option<String>,
        svg: Option<String>,
        layout_mode: &'static str,
        focus_pc: Option<String>,
        selected_block: Option<String>,
        shown_block_count: usize,
        hidden_block_count: usize,
        neighborhood_depth: usize,
        block_count: usize,
        edge_count: usize,
        drawn_edge_count: usize,
        hidden_edge_count: usize,
        total_block_count: usize,
        dot_bytes: usize,
    },
    Error {
        err: String,
    },
}

const AUTO_DOT_MAX_BLOCKS: usize = 120;
const AUTO_DOT_MAX_EDGES: usize = 250;
const FORCE_DOT_MAX_BLOCKS: usize = 400;
const FORCE_DOT_MAX_EDGES: usize = 1_000;
const AUTO_CACHED_MAX_SVG_BYTES: usize = 1_500_000;
const LARGE_OVERVIEW_MAX_BLOCKS: usize = 2_000;
const LARGE_OVERVIEW_MAX_EDGES: usize = 6_000;
const LARGE_OVERVIEW_MAX_DRAWN_EDGES: usize = 320;
const LOCAL_CFG_MAX_BLOCKS: usize = 180;
const LOCAL_CFG_MAX_EDGES: usize = 520;
const LOCAL_CFG_MAX_DEPTH: usize = 5;
const LOCAL_CFG_SCC_MAX_BLOCKS: usize = 64;

fn estimate_dot_bytes(block_count: usize, edge_count: usize) -> usize {
    // Large auto-skip responses should not build the full Graphviz dot just to
    // report its size. This estimate is only used for the UI warning.
    4096usize
        .saturating_add(block_count.saturating_mul(1800))
        .saturating_add(edge_count.saturating_mul(120))
}

pub async fn cfg_svg_handler(
    State(state): State<AppState>,
    Query(q): Query<CfgSvgQuery>,
) -> Json<CfgSvgResponse> {
    let filter_fn = normalize_fn_filter(&q.fn_name);
    let focus_pc = normalize_pc_filter(&q.pc);
    let local_depth = q.local_depth.clamp(1, LOCAL_CFG_MAX_DEPTH);
    let cache_key = filter_fn.as_deref().unwrap_or("<all>").to_string();

    if let Some(cached) = state
        .inner
        .cfg_svg_cache
        .lock()
        .expect("cfg svg cache poisoned")
        .get(&cache_key)
        .cloned()
    {
        if q.force
            || (cached.block_count <= AUTO_DOT_MAX_BLOCKS
                && cached.svg.len() <= AUTO_CACHED_MAX_SVG_BYTES)
        {
            return Json(CfgSvgResponse::Ready {
                svg: cached.svg,
                fn_name: filter_fn,
                block_count: cached.block_count,
                total_block_count: cached.total_block_count,
                cached: true,
            });
        }
    }

    let inner = state.inner.clone();
    let force = q.force;
    let prepare_filter = filter_fn.clone();
    let prepare_cache_key = cache_key.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        prepare_cfg_svg(
            inner,
            prepare_filter,
            focus_pc,
            local_depth,
            prepare_cache_key,
            force,
        )
    })
    .await
    .unwrap_or_else(|err| {
        tracing::warn!(target: "tracemiku-server", "cfg svg prepare worker failed: {err}");
        CfgSvgPrepared::Response(CfgSvgResponse::Error {
            err: "cfg svg prepare worker failed".to_string(),
        })
    });

    let (dot, fn_name, block_count, total_block_count, cache_key) = match prepared {
        CfgSvgPrepared::Response(response) => return Json(response),
        CfgSvgPrepared::Dot {
            dot,
            fn_name,
            block_count,
            total_block_count,
            cache_key,
        } => (dot, fn_name, block_count, total_block_count, cache_key),
    };

    let timeout = q.timeout.clamp(5, 300);
    match render_dot_to_svg(dot, timeout).await {
        Ok(svg) => {
            let cached = CfgSvgCached {
                svg: svg.clone(),
                block_count,
                total_block_count,
            };
            state
                .inner
                .cfg_svg_cache
                .lock()
                .expect("cfg svg cache poisoned")
                .insert(cache_key, cached);
            Json(CfgSvgResponse::Ready {
                svg,
                fn_name,
                block_count,
                total_block_count,
                cached: false,
            })
        }
        Err(err) => Json(CfgSvgResponse::Error { err }),
    }
}

enum CfgSvgPrepared {
    Response(CfgSvgResponse),
    Dot {
        dot: String,
        fn_name: Option<String>,
        block_count: usize,
        total_block_count: usize,
        cache_key: String,
    },
}

fn prepare_cfg_svg(
    inner: std::sync::Arc<AppStateInner>,
    filter_fn: Option<String>,
    focus_pc: Option<u64>,
    local_depth: usize,
    cache_key: String,
    force: bool,
) -> CfgSvgPrepared {
    let included = included_blocks(&inner.cfg, &inner.symbols, filter_fn.as_deref());
    if included.is_empty() {
        return CfgSvgPrepared::Response(CfgSvgResponse::Empty {
            fn_name: filter_fn,
            svg: None,
        });
    }

    let included_starts: HashSet<u64> = included.iter().map(|b| b.start_pc).collect();
    let edge_count = included_edge_count(&inner, &included_starts);
    let auto_too_large = included.len() > AUTO_DOT_MAX_BLOCKS || edge_count > AUTO_DOT_MAX_EDGES;
    let force_too_large = included.len() > FORCE_DOT_MAX_BLOCKS || edge_count > FORCE_DOT_MAX_EDGES;
    if (!force && auto_too_large) || (force && force_too_large) {
        let fallback = focus_pc
            .and_then(|pc| {
                build_local_cfg_svg(
                    &inner,
                    &included,
                    &included_starts,
                    pc,
                    local_depth,
                    edge_count,
                )
            })
            .or_else(|| {
                if included.len() <= LARGE_OVERVIEW_MAX_BLOCKS
                    && edge_count <= LARGE_OVERVIEW_MAX_EDGES
                {
                    Some(build_large_overview_svg(
                        &inner,
                        &included,
                        &included_starts,
                        edge_count,
                    ))
                } else {
                    None
                }
            });
        let drawn_edge_count = fallback.as_ref().map_or(0, |o| o.drawn_edge_count);
        let hidden_edge_count = fallback
            .as_ref()
            .map_or(edge_count, |o| o.hidden_edge_count);
        let shown_block_count = fallback.as_ref().map_or(0, |o| o.shown_block_count);
        let hidden_block_count = fallback
            .as_ref()
            .map_or(included.len(), |o| o.hidden_block_count);
        let layout_mode = fallback.as_ref().map_or("none", |o| o.layout_mode);
        let focus_pc_out = fallback.as_ref().and_then(|o| o.focus_pc);
        let selected_block = fallback.as_ref().and_then(|o| o.selected_block);
        let neighborhood_depth = fallback.as_ref().map_or(0, |o| o.neighborhood_depth);
        return CfgSvgPrepared::Response(CfgSvgResponse::Large {
            fn_name: filter_fn,
            svg: fallback.map(|o| o.svg),
            layout_mode,
            focus_pc: focus_pc_out.map(|pc| format!("{pc:#x}")),
            selected_block: selected_block.map(|pc| format!("{pc:#x}")),
            shown_block_count,
            hidden_block_count,
            neighborhood_depth,
            block_count: included.len(),
            edge_count,
            drawn_edge_count,
            hidden_edge_count,
            total_block_count: inner.cfg.block_count(),
            dot_bytes: estimate_dot_bytes(included.len(), edge_count),
        });
    }

    CfgSvgPrepared::Dot {
        dot: build_dot(&inner, &included, &included_starts),
        fn_name: filter_fn,
        block_count: included.len(),
        total_block_count: inner.cfg.block_count(),
        cache_key,
    }
}

struct LargeOverviewSvg {
    svg: String,
    layout_mode: &'static str,
    focus_pc: Option<u64>,
    selected_block: Option<u64>,
    shown_block_count: usize,
    hidden_block_count: usize,
    neighborhood_depth: usize,
    drawn_edge_count: usize,
    hidden_edge_count: usize,
}

#[derive(Debug, Clone)]
struct OverviewEdge {
    src: u64,
    dst: u64,
    count: u64,
    distance: usize,
    class: &'static str,
}

fn build_large_overview_svg(
    inner: &crate::state::AppStateInner,
    included: &[&tracemiku_core::cfg::Block],
    included_starts: &HashSet<u64>,
    total_edge_count: usize,
) -> LargeOverviewSvg {
    let base = inner
        .meta
        .module
        .as_ref()
        .and_then(|m| parse_hex_u64(&m.base))
        .unwrap_or(0);
    let n = included.len().max(1);
    let cols = ((n as f64).sqrt().ceil() as usize).clamp(1, 24);
    let rows = n.div_ceil(cols);
    let margin = 24.0f64;
    let node_w = 150.0f64;
    let node_h = 42.0f64;
    let gap_x = 34.0f64;
    let gap_y = 28.0f64;
    let width = margin * 2.0 + cols as f64 * node_w + cols.saturating_sub(1) as f64 * gap_x;
    let height = margin * 2.0 + rows as f64 * node_h + rows.saturating_sub(1) as f64 * gap_y;

    let mut positions: HashMap<u64, (f64, f64)> = HashMap::new();
    let mut order: HashMap<u64, usize> = HashMap::new();
    for (i, block) in included.iter().enumerate() {
        let col = i % cols;
        let row = i / cols;
        let x = margin + col as f64 * (node_w + gap_x);
        let y = margin + row as f64 * (node_h + gap_y);
        positions.insert(block.start_pc, (x, y));
        order.insert(block.start_pc, i);
    }
    let edges = large_overview_edges(inner, included_starts, &order);
    let drawn_edge_count = edges.len();
    let hidden_edge_count = total_edge_count.saturating_sub(drawn_edge_count);

    let mut out = String::new();
    out.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width:.0}\" height=\"{height:.0}\" \
         viewBox=\"0 0 {width:.0} {height:.0}\">"
    ));
    out.push_str(
        "<style>\
         .tm-bg{fill:#0e1117}.tm-edge{stroke:#58a6ff;stroke-opacity:.24;stroke-width:1.1}\
         .tm-edge-hot{stroke:#f7b32b;stroke-opacity:.42;stroke-width:1.35}.tm-edge-self{stroke:#bc8cff;stroke-opacity:.5}\
         .tm-node rect{fill:#161b22;stroke:#30363d;stroke-width:1.2;rx:3}\
         .tm-node:hover rect{stroke:#58a6ff;stroke-width:2}.tm-hot rect{stroke:#f7b32b}\
         .tm-title{fill:#d0d7de;font:11px JetBrainsMono,monospace}.tm-sub{fill:#8b949e;font:9px JetBrainsMono,monospace}\
         </style>",
    );
    out.push_str(&format!(
        "<rect class=\"tm-bg\" x=\"0\" y=\"0\" width=\"{width:.0}\" height=\"{height:.0}\"/>"
    ));
    out.push_str("<g class=\"tm-edges\">");
    for edge in &edges {
        let Some((sx, sy)) = positions.get(&edge.src) else {
            continue;
        };
        let Some((dx, dy)) = positions.get(&edge.dst) else {
            continue;
        };
        let title = html_esc(&format!(
            "{:#x} -> {:#x} · x{} · distance {}",
            edge.src, edge.dst, edge.count, edge.distance
        ));
        out.push_str(&format!(
            "<line class=\"{}\" x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\"><title>{}</title></line>",
            edge.class,
            sx + node_w / 2.0,
            sy + node_h / 2.0,
            dx + node_w / 2.0,
            dy + node_h / 2.0,
            title
        ));
    }
    out.push_str("</g><g class=\"tm-nodes\">");
    for block in included {
        let Some((x, y)) = positions.get(&block.start_pc) else {
            continue;
        };
        let class = if block.executions > 10 {
            "tm-node tm-hot"
        } else {
            "tm-node"
        };
        let rel = html_esc(&rel_pc(block.start_pc, base));
        let title = html_esc(&format!(
            "block {:#x}..{:#x}, {} executions",
            block.start_pc, block.end_pc, block.executions
        ));
        out.push_str(&format!(
            "<a href=\"#hdr_b{:x}\"><g class=\"{}\"><title>{}</title>\
             <rect x=\"{:.1}\" y=\"{:.1}\" width=\"{node_w:.1}\" height=\"{node_h:.1}\"/>\
             <text class=\"tm-title\" x=\"{:.1}\" y=\"{:.1}\">{}</text>\
             <text class=\"tm-sub\" x=\"{:.1}\" y=\"{:.1}\">x{} · end {}</text>\
             </g></a>",
            block.start_pc,
            class,
            title,
            x,
            y,
            x + 9.0,
            y + 17.0,
            rel,
            x + 9.0,
            y + 32.0,
            block.executions,
            html_esc(&rel_pc(block.end_pc, base))
        ));
    }
    if hidden_edge_count > 0 {
        out.push_str(&format!(
            "<text class=\"tm-sub\" x=\"{:.1}\" y=\"{:.1}\">overview: {} drawn / {} hidden edges</text>",
            margin,
            height - 8.0,
            drawn_edge_count,
            hidden_edge_count
        ));
    }
    out.push_str("</g></svg>");
    LargeOverviewSvg {
        svg: out,
        layout_mode: "overview",
        focus_pc: None,
        selected_block: None,
        shown_block_count: included.len(),
        hidden_block_count: 0,
        neighborhood_depth: 0,
        drawn_edge_count,
        hidden_edge_count,
    }
}

fn large_overview_edges(
    inner: &crate::state::AppStateInner,
    included_starts: &HashSet<u64>,
    order: &HashMap<u64, usize>,
) -> Vec<OverviewEdge> {
    let mut candidates = Vec::new();
    for edge in inner.cfg.graph.edge_indices() {
        let Some((src_node, dst_node)) = inner.cfg.graph.edge_endpoints(edge) else {
            continue;
        };
        let Some(src) = inner.cfg.graph.node_weight(src_node) else {
            continue;
        };
        let Some(dst) = inner.cfg.graph.node_weight(dst_node) else {
            continue;
        };
        if !included_starts.contains(&src.start_pc) || !included_starts.contains(&dst.start_pc) {
            continue;
        }
        let Some(src_i) = order.get(&src.start_pc).copied() else {
            continue;
        };
        let Some(dst_i) = order.get(&dst.start_pc).copied() else {
            continue;
        };
        let Some(meta) = inner.cfg.graph.edge_weight(edge) else {
            continue;
        };
        let distance = src_i.abs_diff(dst_i);
        let class = if src.start_pc == dst.start_pc {
            "tm-edge tm-edge-self"
        } else if meta.count >= 10 {
            "tm-edge tm-edge-hot"
        } else {
            "tm-edge"
        };
        candidates.push(OverviewEdge {
            src: src.start_pc,
            dst: dst.start_pc,
            count: meta.count,
            distance,
            class,
        });
    }

    if candidates.len() <= LARGE_OVERVIEW_MAX_DRAWN_EDGES {
        return candidates;
    }

    candidates.sort_by(|a, b| {
        let a_required = a.src == a.dst || a.distance <= 2;
        let b_required = b.src == b.dst || b.distance <= 2;
        b_required
            .cmp(&a_required)
            .then_with(|| b.count.cmp(&a.count))
            .then_with(|| a.distance.cmp(&b.distance))
            .then_with(|| a.src.cmp(&b.src))
            .then_with(|| a.dst.cmp(&b.dst))
    });

    let mut selected = Vec::with_capacity(LARGE_OVERVIEW_MAX_DRAWN_EDGES);
    let mut seen = HashSet::new();
    for edge in candidates {
        if selected.len() >= LARGE_OVERVIEW_MAX_DRAWN_EDGES {
            break;
        }
        if seen.insert((edge.src, edge.dst)) {
            selected.push(edge);
        }
    }
    selected
}

#[derive(Debug, Clone)]
struct LocalEdge {
    src: u64,
    dst: u64,
    kind: String,
    count: u64,
    class: &'static str,
}

fn build_local_cfg_svg(
    inner: &crate::state::AppStateInner,
    included: &[&tracemiku_core::cfg::Block],
    included_starts: &HashSet<u64>,
    focus_pc: u64,
    requested_depth: usize,
    total_edge_count: usize,
) -> Option<LargeOverviewSvg> {
    let focus_block = inner.cfg.block_containing(focus_pc)?;
    if !included_starts.contains(&focus_block.start_pc) {
        return None;
    }

    let depth = requested_depth.clamp(1, LOCAL_CFG_MAX_DEPTH);
    let mut blocks_by_pc: HashMap<u64, &tracemiku_core::cfg::Block> = HashMap::new();
    let mut scc_groups: HashMap<u32, Vec<u64>> = HashMap::new();
    for block in included {
        blocks_by_pc.insert(block.start_pc, *block);
        scc_groups
            .entry(block.scc_id)
            .or_default()
            .push(block.start_pc);
    }

    let (incoming, outgoing) = local_edge_maps(inner, included_starts);
    let mut selected: HashSet<u64> = HashSet::new();
    let mut dist: HashMap<u64, i32> = HashMap::new();
    let mut queue: VecDeque<(u64, i32)> = VecDeque::new();
    let focus_start = focus_block.start_pc;
    selected.insert(focus_start);
    dist.insert(focus_start, 0);
    queue.push_back((focus_start, 0));

    while let Some((pc, d)) = queue.pop_front() {
        if d.unsigned_abs() as usize >= depth {
            continue;
        }
        for (dst, _meta) in outgoing.get(&pc).into_iter().flatten() {
            local_maybe_push(*dst, d + 1, &mut selected, &mut dist, &mut queue);
        }
        for (src, _meta) in incoming.get(&pc).into_iter().flatten() {
            local_maybe_push(*src, d - 1, &mut selected, &mut dist, &mut queue);
        }
    }

    // Keep small loops intact around the focus block. Very large SCCs are the
    // exact case where full expansion turns into unreadable dispatcher noise,
    // so they remain represented through nearby incoming/outgoing edges.
    if let Some(scc) = scc_groups.get(&focus_block.scc_id) {
        if scc.len() > 1 && scc.len() <= LOCAL_CFG_SCC_MAX_BLOCKS {
            for pc in scc {
                if included_starts.contains(pc) {
                    selected.insert(*pc);
                    dist.entry(*pc).or_insert(0);
                }
            }
        }
    }

    if selected.len() > LOCAL_CFG_MAX_BLOCKS {
        let mut ranked: Vec<u64> = selected.iter().copied().collect();
        ranked.sort_by(|a, b| {
            let da = dist.get(a).copied().unwrap_or(0).unsigned_abs();
            let db = dist.get(b).copied().unwrap_or(0).unsigned_abs();
            let ea = blocks_by_pc.get(a).map_or(0, |b| b.executions);
            let eb = blocks_by_pc.get(b).map_or(0, |b| b.executions);
            da.cmp(&db).then_with(|| eb.cmp(&ea)).then_with(|| a.cmp(b))
        });
        ranked.truncate(LOCAL_CFG_MAX_BLOCKS);
        ranked.push(focus_start);
        selected = ranked.into_iter().collect();
    }

    let mut edges = local_edges(&outgoing, &selected, &dist, focus_start);
    let raw_edge_count = edges.len();
    if edges.len() > LOCAL_CFG_MAX_EDGES {
        edges.sort_by(|a, b| {
            let a_focus = a.src == focus_start || a.dst == focus_start;
            let b_focus = b.src == focus_start || b.dst == focus_start;
            let a_near = edge_distance(a, &dist);
            let b_near = edge_distance(b, &dist);
            b_focus
                .cmp(&a_focus)
                .then_with(|| b.count.cmp(&a.count))
                .then_with(|| a_near.cmp(&b_near))
                .then_with(|| a.src.cmp(&b.src))
                .then_with(|| a.dst.cmp(&b.dst))
        });
        edges.truncate(LOCAL_CFG_MAX_EDGES);
    }

    let base = inner
        .meta
        .module
        .as_ref()
        .and_then(|m| parse_hex_u64(&m.base))
        .unwrap_or(0);
    let svg = render_local_cfg_svg(
        included.len(),
        total_edge_count,
        focus_pc,
        focus_start,
        &selected,
        &dist,
        &edges,
        &blocks_by_pc,
        base,
        depth,
        raw_edge_count,
    );
    Some(LargeOverviewSvg {
        svg,
        layout_mode: "local",
        focus_pc: Some(focus_pc),
        selected_block: Some(focus_start),
        shown_block_count: selected.len(),
        hidden_block_count: included.len().saturating_sub(selected.len()),
        neighborhood_depth: depth,
        drawn_edge_count: edges.len(),
        hidden_edge_count: total_edge_count.saturating_sub(edges.len()),
    })
}

type LocalEdgeMap = HashMap<u64, Vec<(u64, tracemiku_core::cfg::EdgeMeta)>>;

fn local_edge_maps(
    inner: &crate::state::AppStateInner,
    included_starts: &HashSet<u64>,
) -> (LocalEdgeMap, LocalEdgeMap) {
    let mut incoming: LocalEdgeMap = HashMap::new();
    let mut outgoing: LocalEdgeMap = HashMap::new();
    for edge in inner.cfg.graph.edge_indices() {
        let Some((src_node, dst_node)) = inner.cfg.graph.edge_endpoints(edge) else {
            continue;
        };
        let Some(src) = inner.cfg.graph.node_weight(src_node) else {
            continue;
        };
        let Some(dst) = inner.cfg.graph.node_weight(dst_node) else {
            continue;
        };
        if !included_starts.contains(&src.start_pc) || !included_starts.contains(&dst.start_pc) {
            continue;
        }
        let Some(meta) = inner.cfg.graph.edge_weight(edge).cloned() else {
            continue;
        };
        outgoing
            .entry(src.start_pc)
            .or_default()
            .push((dst.start_pc, meta.clone()));
        incoming
            .entry(dst.start_pc)
            .or_default()
            .push((src.start_pc, meta));
    }
    for edges in outgoing.values_mut() {
        edges.sort_by_key(|(pc, _)| *pc);
    }
    for edges in incoming.values_mut() {
        edges.sort_by_key(|(pc, _)| *pc);
    }
    (incoming, outgoing)
}

fn local_maybe_push(
    pc: u64,
    next_dist: i32,
    selected: &mut HashSet<u64>,
    dist: &mut HashMap<u64, i32>,
    queue: &mut VecDeque<(u64, i32)>,
) {
    let should_update = dist.get(&pc).is_none_or(|old| next_dist.abs() < old.abs());
    if should_update {
        dist.insert(pc, next_dist);
        queue.push_back((pc, next_dist));
    }
    selected.insert(pc);
}

fn local_edges(
    outgoing: &LocalEdgeMap,
    selected: &HashSet<u64>,
    dist: &HashMap<u64, i32>,
    focus_start: u64,
) -> Vec<LocalEdge> {
    let mut out = Vec::new();
    for src in selected {
        for (dst, meta) in outgoing.get(src).into_iter().flatten() {
            if !selected.contains(dst) {
                continue;
            }
            let class = if *src == focus_start || *dst == focus_start {
                "tm-local-edge tm-local-edge-focus"
            } else if meta.kind == "call-return" {
                "tm-local-edge tm-local-edge-call"
            } else if dist.get(dst).copied().unwrap_or(0) <= dist.get(src).copied().unwrap_or(0) {
                "tm-local-edge tm-local-edge-back"
            } else if meta.count >= 10 {
                "tm-local-edge tm-local-edge-hot"
            } else {
                "tm-local-edge"
            };
            out.push(LocalEdge {
                src: *src,
                dst: *dst,
                kind: meta.kind.clone(),
                count: meta.count,
                class,
            });
        }
    }
    out.sort_by_key(|e| (e.src, e.dst, e.kind.clone()));
    out
}

fn edge_distance(edge: &LocalEdge, dist: &HashMap<u64, i32>) -> u32 {
    dist.get(&edge.src)
        .copied()
        .unwrap_or(0)
        .unsigned_abs()
        .saturating_add(dist.get(&edge.dst).copied().unwrap_or(0).unsigned_abs())
}

#[allow(clippy::too_many_arguments)]
fn render_local_cfg_svg(
    total_blocks: usize,
    total_edges: usize,
    focus_pc: u64,
    focus_start: u64,
    selected: &HashSet<u64>,
    dist: &HashMap<u64, i32>,
    edges: &[LocalEdge],
    blocks_by_pc: &HashMap<u64, &tracemiku_core::cfg::Block>,
    base: u64,
    depth: usize,
    raw_edge_count: usize,
) -> String {
    let mut layers: Vec<(i32, Vec<u64>)> = Vec::new();
    let mut by_layer: HashMap<i32, Vec<u64>> = HashMap::new();
    for pc in selected {
        by_layer
            .entry(dist.get(pc).copied().unwrap_or(0))
            .or_default()
            .push(*pc);
    }
    for (layer, mut pcs) in by_layer {
        pcs.sort_by(|a, b| {
            let ea = blocks_by_pc.get(a).map_or(0, |b| b.executions);
            let eb = blocks_by_pc.get(b).map_or(0, |b| b.executions);
            eb.cmp(&ea).then_with(|| a.cmp(b))
        });
        layers.push((layer, pcs));
    }
    layers.sort_by_key(|(layer, _)| *layer);

    let node_w = 184.0f64;
    let node_h = 54.0f64;
    let gap_x = 28.0f64;
    let gap_y = 48.0f64;
    let margin = 28.0f64;
    let max_cols = layers.iter().map(|(_, pcs)| pcs.len()).max().unwrap_or(1);
    let width =
        (margin * 2.0 + max_cols as f64 * node_w + max_cols.saturating_sub(1) as f64 * gap_x)
            .max(820.0);
    let height = margin * 2.0
        + layers.len() as f64 * node_h
        + layers.len().saturating_sub(1) as f64 * gap_y
        + 26.0;
    let mut pos: HashMap<u64, (f64, f64)> = HashMap::new();
    for (row, (_layer, pcs)) in layers.iter().enumerate() {
        let row_w = pcs.len() as f64 * node_w + pcs.len().saturating_sub(1) as f64 * gap_x;
        let x0 = (width - row_w) / 2.0;
        let y = margin + row as f64 * (node_h + gap_y);
        for (col, pc) in pcs.iter().enumerate() {
            let x = x0 + col as f64 * (node_w + gap_x);
            pos.insert(*pc, (x, y));
        }
    }

    let mut out = String::new();
    out.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width:.0}\" height=\"{height:.0}\" \
         viewBox=\"0 0 {width:.0} {height:.0}\" data-layout=\"local-cfg\">"
    ));
    out.push_str(
        "<style>\
         .tm-bg{fill:#0e1117}.tm-local-edge{fill:none;stroke:#58a6ff;stroke-opacity:.32;stroke-width:1.15}\
         .tm-local-edge-focus{stroke:#f7b32b;stroke-opacity:.72;stroke-width:1.9}\
         .tm-local-edge-hot{stroke:#3fb950;stroke-opacity:.62;stroke-width:1.55}\
         .tm-local-edge-back{stroke:#ff7b72;stroke-opacity:.55;stroke-width:1.35}\
         .tm-local-edge-call{stroke:#bc8cff;stroke-opacity:.62;stroke-dasharray:5 3}\
         .tm-local-node rect{fill:#161b22;stroke:#30363d;stroke-width:1.1;rx:3}\
         .tm-local-node:hover rect{stroke:#58a6ff;stroke-width:2}.tm-local-current rect{stroke:#f7b32b;stroke-width:2.2}\
         .tm-title{fill:#d0d7de;font:11px JetBrainsMono,monospace}.tm-sub{fill:#8b949e;font:9px JetBrainsMono,monospace}\
         .tm-note{fill:#8b949e;font:10px JetBrainsMono,monospace}\
         </style><defs><marker id=\"tm-arrow\" viewBox=\"0 0 10 10\" refX=\"8\" refY=\"5\" markerWidth=\"5\" markerHeight=\"5\" orient=\"auto-start-reverse\"><path d=\"M 0 0 L 10 5 L 0 10 z\" fill=\"#58a6ff\" opacity=\".45\"/></marker></defs>",
    );
    out.push_str(&format!(
        "<rect class=\"tm-bg\" x=\"0\" y=\"0\" width=\"{width:.0}\" height=\"{height:.0}\"/>"
    ));
    out.push_str("<g class=\"tm-edges\">");
    for edge in edges {
        let (Some((sx, sy)), Some((dx, dy))) = (pos.get(&edge.src), pos.get(&edge.dst)) else {
            continue;
        };
        let start_x = sx + node_w / 2.0;
        let start_y = sy + node_h;
        let end_x = dx + node_w / 2.0;
        let end_y = *dy;
        let mid_y = (start_y + end_y) / 2.0;
        let title = html_esc(&format!(
            "{:#x} -> {:#x} · {} x{}",
            edge.src, edge.dst, edge.kind, edge.count
        ));
        let path = if (end_y - start_y).abs() < 8.0 {
            let loop_y = start_y + 20.0;
            format!(
                "M {start_x:.1} {start_y:.1} C {start_x:.1} {loop_y:.1}, {end_x:.1} {loop_y:.1}, {end_x:.1} {end_y:.1}"
            )
        } else {
            format!(
                "M {start_x:.1} {start_y:.1} C {start_x:.1} {mid_y:.1}, {end_x:.1} {mid_y:.1}, {end_x:.1} {end_y:.1}"
            )
        };
        out.push_str(&format!(
            "<path class=\"{}\" marker-end=\"url(#tm-arrow)\" d=\"{}\"><title>{}</title></path>",
            edge.class, path, title
        ));
    }
    out.push_str("</g><g class=\"tm-nodes\">");
    for (layer, pcs) in &layers {
        for pc in pcs {
            let Some(block) = blocks_by_pc.get(pc) else {
                continue;
            };
            let Some((x, y)) = pos.get(pc) else {
                continue;
            };
            let current = *pc == focus_start;
            let class = if current {
                "tm-local-node tm-local-current"
            } else {
                "tm-local-node"
            };
            let href = if current {
                format!("#insn_{focus_pc:x}")
            } else {
                format!("#hdr_b{pc:x}")
            };
            let title = html_esc(&format!(
                "block {:#x}..{:#x}, layer {}, {} executions",
                block.start_pc, block.end_pc, layer, block.executions
            ));
            let label = if current {
                format!("{}  CURRENT", rel_pc(*pc, base))
            } else {
                rel_pc(*pc, base)
            };
            let sub = format!(
                "x{} · scc {} · end {}",
                block.executions,
                block.scc_id,
                rel_pc(block.end_pc, base)
            );
            out.push_str(&format!(
                "<a href=\"{}\"><g class=\"{}\"><title>{}</title>\
                 <rect x=\"{:.1}\" y=\"{:.1}\" width=\"{node_w:.1}\" height=\"{node_h:.1}\"/>\
                 <text class=\"tm-title\" x=\"{:.1}\" y=\"{:.1}\">{}</text>\
                 <text class=\"tm-sub\" x=\"{:.1}\" y=\"{:.1}\">{}</text>\
                 </g></a>",
                href,
                class,
                title,
                x,
                y,
                x + 9.0,
                y + 19.0,
                html_esc(&label),
                x + 9.0,
                y + 38.0,
                html_esc(&sub)
            ));
        }
    }
    out.push_str(&format!(
        "<text class=\"tm-note\" x=\"{:.1}\" y=\"{:.1}\">local CFG around {:#x} · depth {} · blocks {}/{} · edges {}/{}{} </text>",
        margin,
        height - 10.0,
        focus_pc,
        depth,
        selected.len(),
        total_blocks,
        edges.len(),
        total_edges,
        if raw_edge_count > edges.len() { " · capped" } else { "" },
    ));
    out.push_str("</g></svg>");
    out
}

fn normalize_fn_filter(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn normalize_pc_filter(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    parse_hex_u64(s).or_else(|| s.parse::<u64>().ok())
}

fn included_blocks<'a>(
    cfg: &'a tracemiku_core::cfg::CFG,
    symbols: &tracemiku_core::symbols::SymbolMap,
    filter_fn: Option<&str>,
) -> Vec<&'a tracemiku_core::cfg::Block> {
    let mut out: Vec<&tracemiku_core::cfg::Block> = cfg
        .blocks()
        .into_iter()
        .filter(|b| {
            let (name, _) = symbols.lookup(b.start_pc);
            match filter_fn {
                Some(target) => name == target,
                None => true,
            }
        })
        .collect();
    out.sort_by_key(|b| b.start_pc);
    out
}

fn build_dot(
    inner: &crate::state::AppStateInner,
    included: &[&tracemiku_core::cfg::Block],
    included_starts: &HashSet<u64>,
) -> String {
    let base = inner
        .meta
        .module
        .as_ref()
        .and_then(|m| parse_hex_u64(&m.base))
        .unwrap_or(0);
    let block_insns = collect_first_block_insns(inner, included_starts);
    let loop_colors = loop_border_colors(&inner.cfg);

    let mut out = String::new();
    out.push_str("digraph CFG {\n");
    out.push_str(
        "  graph [bgcolor=\"#0e1117\", rankdir=TB, fontname=\"JetBrainsMono,monospace\", \
         fontcolor=\"#d0d7de\", splines=ortho, nodesep=0.45, ranksep=0.55, pad=0.3];\n",
    );
    out.push_str("  node [shape=plaintext, fontname=\"JetBrainsMono,monospace\", fontsize=10];\n");
    out.push_str(
        "  edge [arrowsize=0.8, penwidth=1.4, fontname=\"JetBrainsMono,monospace\", \
         fontsize=8, fontcolor=\"#6e7681\"];\n",
    );

    for block in included {
        let rows = block_rows(block, block_insns.get(&block.start_pc), base);
        let border = loop_colors
            .get(&block.start_pc)
            .cloned()
            .unwrap_or_else(|| exec_border_color(block.executions));
        let label = build_block_label(&rows, &border);
        out.push_str(&format!(
            "  \"b{:x}\" [label={}, id=\"b{:x}\"];\n",
            block.start_pc, label, block.start_pc
        ));
    }

    for edge in inner.cfg.graph.edge_indices() {
        let Some((src_node, dst_node)) = inner.cfg.graph.edge_endpoints(edge) else {
            continue;
        };
        let Some(src) = inner.cfg.graph.node_weight(src_node) else {
            continue;
        };
        let Some(dst) = inner.cfg.graph.node_weight(dst_node) else {
            continue;
        };
        let Some(meta) = inner.cfg.graph.edge_weight(edge) else {
            continue;
        };
        let src_in = included_starts.contains(&src.start_pc);
        let dst_in = included_starts.contains(&dst.start_pc);
        if !src_in && !dst_in {
            continue;
        }

        if !src_in && dst_in {
            write_ext_in_edge(
                &mut out,
                src.start_pc,
                dst.start_pc,
                base,
                &meta.kind,
                meta.count,
            );
            continue;
        }

        let (color, font_color, style) = edge_style(src, dst, meta, block_insns.get(&src.start_pc));
        let label = edge_label(&meta.kind, meta.count);
        let font_attr = font_color
            .map(|c| format!(", fontcolor=\"{c}\""))
            .unwrap_or_default();
        let style_attr = style.map(|s| format!(", style={s}")).unwrap_or_default();

        if dst_in {
            out.push_str(&format!(
                "  \"b{:x}\" -> \"b{:x}\" [color=\"{}\", label=\"{}\"{}{}];\n",
                src.start_pc,
                dst.start_pc,
                color,
                dot_escape(&label),
                font_attr,
                style_attr
            ));
        } else {
            let ext_id = format!("ext_{:x}_{:x}", src.start_pc, dst.start_pc);
            let ext_lbl = if base != 0 {
                format!("ext +{:x}", dst.start_pc.wrapping_sub(base))
            } else {
                format!("ext {:x}", dst.start_pc)
            };
            out.push_str(&format!(
                "  \"{}\" [shape=ellipse, fontsize=9, style=filled, fillcolor=\"#1f2630\", \
                 color=\"#6e7681\", fontcolor=\"#6e7681\", label=\"{}\", id=\"{}\"];\n",
                ext_id,
                dot_escape(&ext_lbl),
                ext_id
            ));
            out.push_str(&format!(
                "  \"b{:x}\" -> \"{}\" [color=\"{}\", label=\"{}\"{}{}];\n",
                src.start_pc,
                ext_id,
                color,
                dot_escape(&label),
                font_attr,
                style_attr
            ));
        }
    }
    out.push_str("}\n");
    out
}

fn included_edge_count(
    inner: &crate::state::AppStateInner,
    included_starts: &HashSet<u64>,
) -> usize {
    inner
        .cfg
        .graph
        .edge_indices()
        .filter(|edge| {
            let Some((src_node, dst_node)) = inner.cfg.graph.edge_endpoints(*edge) else {
                return false;
            };
            let Some(src) = inner.cfg.graph.node_weight(src_node) else {
                return false;
            };
            let Some(dst) = inner.cfg.graph.node_weight(dst_node) else {
                return false;
            };
            included_starts.contains(&src.start_pc) || included_starts.contains(&dst.start_pc)
        })
        .count()
}

fn write_ext_in_edge(
    out: &mut String,
    src_pc: u64,
    dst_pc: u64,
    base: u64,
    kind: &str,
    count: u64,
) {
    let ext_id = format!("ext_in_{src_pc:x}");
    let ext_lbl = if base != 0 {
        format!("from +{:x}", src_pc.wrapping_sub(base))
    } else {
        format!("from {src_pc:x}")
    };
    let label = edge_label(kind, count);
    out.push_str(&format!(
        "  \"{}\" [shape=ellipse, fontsize=9, style=filled, fillcolor=\"#1f2630\", \
         color=\"#bc8cff\", fontcolor=\"#bc8cff\", label=\"{}\", id=\"{}\"];\n",
        ext_id,
        dot_escape(&ext_lbl),
        ext_id
    ));
    out.push_str(&format!(
        "  \"{}\" -> \"b{:x}\" [color=\"#bc8cff\", label=\"{}\", style=dashed];\n",
        ext_id,
        dst_pc,
        dot_escape(&label)
    ));
}

fn block_rows(
    block: &tracemiku_core::cfg::Block,
    insns: Option<&Vec<(u64, u32)>>,
    base: u64,
) -> Vec<String> {
    let mut rows = Vec::new();
    let head_rel = rel_pc(block.start_pc, base);
    let head_lbl = html_esc(&format!("{head_rel}  x{}", block.executions));
    rows.push(format!(
        "<TR><TD ALIGN=\"LEFT\" BGCOLOR=\"#0e1117\" HREF=\"#hdr_b{:x}\" \
         TITLE=\"block {:#x}\"><FONT COLOR=\"#8b949e\" POINT-SIZE=\"9\">{}</FONT></TD></TR>",
        block.start_pc, block.start_pc, head_lbl
    ));

    if let Some(insns) = insns {
        for (pc, inst) in insns {
            let d = tracemiku_core::disasm::decode(*pc, *inst);
            let rel = rel_pc(*pc, base);
            let ops = truncate_ops(&d.op_str);
            let title = format!("{:#x}: {} {}", pc, d.mnemonic, d.op_str);
            rows.push(format_insn_row(&rel, &d.mnemonic, &ops, *pc, &title));
        }
    } else {
        let rel = rel_pc(block.start_pc, base);
        rows.push(format!(
            "<TR><TD ALIGN=\"LEFT\"><FONT COLOR=\"#6e7681\">{}:</FONT> \
             <FONT COLOR=\"#d0d7de\">&lt;missing insns&gt;</FONT></TD></TR>",
            html_esc(&rel)
        ));
    }
    rows
}

fn collect_first_block_insns(
    inner: &crate::state::AppStateInner,
    wanted_starts: &HashSet<u64>,
) -> HashMap<u64, Vec<(u64, u32)>> {
    let mut out: HashMap<u64, Vec<(u64, u32)>> = HashMap::new();

    for &start in wanted_starts {
        let Some(first_idx) = inner
            .index
            .pc_to_idxs
            .get(&start)
            .and_then(|idxs| idxs.first())
            .copied()
        else {
            continue;
        };
        let Some(block) = inner.cfg.block(start) else {
            continue;
        };

        let mut rows = Vec::new();
        for i in first_idx..inner.trace.len() {
            let pc = inner.trace.pc(i);
            if i != first_idx && inner.cfg.by_pc.contains_key(&pc) && pc != start {
                break;
            }
            if pc < block.start_pc || pc > block.end_pc {
                if !rows.is_empty() {
                    break;
                }
                continue;
            }

            let inst = inner.trace.inst(i);
            rows.push((pc, inst));
            let d = tracemiku_core::disasm::decode(pc, inst);
            if d.is_branch || pc == block.end_pc {
                break;
            }
        }
        if !rows.is_empty() {
            out.insert(start, rows);
        }
    }
    out
}

fn edge_style(
    src: &tracemiku_core::cfg::Block,
    dst: &tracemiku_core::cfg::Block,
    meta: &tracemiku_core::cfg::EdgeMeta,
    src_insns: Option<&Vec<(u64, u32)>>,
) -> (&'static str, Option<&'static str>, Option<&'static str>) {
    if meta.kind == "call-return" {
        return ("#bc8cff", Some("#bc8cff"), Some("dashed"));
    }
    if meta.kind == "fall" {
        return ("#444c56", None, None);
    }

    let term_mnem = src_insns
        .and_then(|v| v.last())
        .map(|(pc, inst)| tracemiku_core::disasm::decode(*pc, *inst).mnemonic);
    if term_mnem.as_deref().is_some_and(is_conditional_branch) {
        let last_pc = src_insns
            .and_then(|v| v.last())
            .map(|(pc, _)| *pc)
            .unwrap_or(src.end_pc);
        if dst.start_pc == last_pc.wrapping_add(4) {
            return ("#f85149", Some("#f85149"), None);
        }
        return ("#3fb950", Some("#3fb950"), None);
    }

    match meta.kind.as_str() {
        "ret" => ("#bc8cff", None, None),
        "bl" | "blr" => ("#bc8cff", None, None),
        _ => ("#58a6ff", None, None),
    }
}

fn is_conditional_branch(mnem: &str) -> bool {
    matches!(mnem, "cbz" | "cbnz" | "tbz" | "tbnz") || mnem.starts_with("b.")
}

fn loop_border_colors(cfg: &tracemiku_core::cfg::CFG) -> HashMap<u64, String> {
    let mut groups: HashMap<u32, Vec<u64>> = HashMap::new();
    for b in cfg.blocks() {
        groups.entry(b.scc_id).or_default().push(b.start_pc);
    }
    let mut loop_groups: Vec<Vec<u64>> = groups
        .into_values()
        .filter(|pcs| {
            pcs.len() > 1
                || pcs
                    .first()
                    .is_some_and(|pc| cfg.edges_from(*pc).iter().any(|(dst, _)| dst == pc))
        })
        .collect();
    loop_groups.sort_by_key(|pcs| pcs.iter().copied().min().unwrap_or(0));

    let palette = [
        "#d2a8ff", "#3fb950", "#f7b32b", "#58a6ff", "#ff7b72", "#56d4dd", "#f2cc60", "#a5d6ff",
    ];
    let mut out = HashMap::new();
    for (i, pcs) in loop_groups.into_iter().enumerate() {
        let color = palette[i % palette.len()].to_string();
        for pc in pcs {
            out.insert(pc, color.clone());
        }
    }
    out
}

fn exec_border_color(executions: u64) -> String {
    let intensity = (executions.min(50) as f64) / 50.0;
    if intensity <= 0.1 {
        return "#30363d".to_string();
    }
    let r = 0x30 + (intensity * 0x80 as f64) as u8;
    let g = 0x36 + (intensity * 0x60 as f64) as u8;
    let b = 0x3d + (intensity * 0x10 as f64) as u8;
    format!("#{r:02x}{g:02x}{b:02x}")
}

fn build_block_label(rows: &[String], border_color: &str) -> String {
    format!(
        "<<TABLE BORDER=\"1\" CELLBORDER=\"0\" CELLSPACING=\"0\" CELLPADDING=\"3\" \
         COLOR=\"{}\" BGCOLOR=\"#161b22\">{}</TABLE>>",
        border_color,
        rows.join("")
    )
}

fn format_insn_row(rel: &str, mnem: &str, ops: &str, pc: u64, title: &str) -> String {
    let mnem_color = mnem_color(mnem);
    let mut line = format!(
        "<FONT COLOR=\"#6e7681\">{}:</FONT> <FONT COLOR=\"{}\">{}</FONT>",
        html_esc(rel),
        mnem_color,
        html_esc(mnem)
    );
    if !ops.is_empty() {
        line.push_str(&format!(
            " <FONT COLOR=\"#d0d7de\">{}</FONT>",
            html_esc(ops)
        ));
    }
    format!(
        "<TR><TD ALIGN=\"LEFT\" HREF=\"#insn_{pc:x}\" TITLE=\"{}\">{line}</TD></TR>",
        html_esc(title)
    )
}

fn mnem_color(mnem: &str) -> &'static str {
    if mnem == "ret" {
        "#f85149"
    } else if matches!(mnem, "bl" | "blr") {
        "#bc8cff"
    } else if matches!(mnem, "b" | "br" | "cbz" | "cbnz" | "tbz" | "tbnz") || mnem.starts_with("b.")
    {
        "#f7b32b"
    } else {
        "#d0d7de"
    }
}

fn rel_pc(pc: u64, base: u64) -> String {
    if base != 0 {
        format!("+{:x}", pc.wrapping_sub(base))
    } else {
        format!("{pc:x}")
    }
}

fn truncate_ops(s: &str) -> String {
    if s.chars().count() > 50 {
        let mut out: String = s.chars().take(48).collect();
        out.push_str("..");
        out
    } else {
        s.to_string()
    }
}

fn edge_label(kind: &str, count: u64) -> String {
    if count > 1 {
        format!("{kind} x{count}")
    } else {
        kind.to_string()
    }
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

fn html_esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

async fn render_dot_to_svg(dot_text: String, timeout_secs: u64) -> Result<String, String> {
    let dot_bin = std::env::var("TRACEMIKU_DOT").unwrap_or_else(|_| "dot".to_string());
    let mut child = tokio::process::Command::new(&dot_bin)
        .arg("-Tsvg")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                format!("graphviz `{dot_bin}` not found")
            } else {
                format!("spawn graphviz `{dot_bin}` failed: {e}")
            }
        })?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(dot_text.as_bytes())
            .await
            .map_err(|e| format!("write graphviz stdin failed: {e}"))?;
    }

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "graphviz stdout missing".to_string())?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| "graphviz stderr missing".to_string())?;
    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        stdout.read_to_end(&mut buf).await.map(|_| buf)
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        stderr.read_to_end(&mut buf).await.map(|_| buf)
    });

    let status = match tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait()).await {
        Ok(waited) => waited.map_err(|e| format!("wait graphviz `{dot_bin}` failed: {e}"))?,
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(format!("dot timeout after {timeout_secs}s"));
        }
    };
    let stdout = stdout_task
        .await
        .map_err(|e| format!("join graphviz stdout failed: {e}"))?
        .map_err(|e| format!("read graphviz stdout failed: {e}"))?;
    let stderr = stderr_task
        .await
        .map_err(|e| format!("join graphviz stderr failed: {e}"))?
        .map_err(|e| format!("read graphviz stderr failed: {e}"))?;

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        let msg: String = stderr.chars().take(500).collect();
        return Err(if msg.is_empty() {
            format!("dot exited with {status}")
        } else {
            msg
        });
    }
    String::from_utf8(stdout).map_err(|e| format!("dot produced non-utf8 SVG: {e}"))
}
