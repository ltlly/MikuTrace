//! GET /api/cfg-svg
//!
//! Render the trace-derived CFG as Graphviz SVG. This is the Rust/Solid v2
//! replacement for Python webui/server.py::cfg_svg.

use std::collections::{HashMap, HashSet};
use std::process::Stdio;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::state::{AppState, CfgSvgCached};

#[derive(Debug, Deserialize)]
pub struct CfgSvgQuery {
    #[serde(default, rename = "fn")]
    pub fn_name: String,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub force: bool,
}

fn default_timeout() -> u64 {
    60
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
        block_count: usize,
        edge_count: usize,
        total_block_count: usize,
        dot_bytes: usize,
    },
    Error {
        err: String,
    },
}

const AUTO_DOT_MAX_BLOCKS: usize = 180;
const AUTO_DOT_MAX_EDGES: usize = 900;

pub async fn cfg_svg_handler(
    State(state): State<AppState>,
    Query(q): Query<CfgSvgQuery>,
) -> Json<CfgSvgResponse> {
    let filter_fn = normalize_fn_filter(&q.fn_name);
    let cache_key = filter_fn.as_deref().unwrap_or("<all>").to_string();

    if let Some(cached) = state
        .inner
        .cfg_svg_cache
        .lock()
        .expect("cfg svg cache poisoned")
        .get(&cache_key)
        .cloned()
    {
        return Json(CfgSvgResponse::Ready {
            svg: cached.svg,
            fn_name: filter_fn,
            block_count: cached.block_count,
            total_block_count: cached.total_block_count,
            cached: true,
        });
    }

    let inner = &state.inner;
    let included = included_blocks(&inner.cfg, &inner.symbols, filter_fn.as_deref());
    if included.is_empty() {
        return Json(CfgSvgResponse::Empty {
            fn_name: filter_fn,
            svg: None,
        });
    }

    let included_starts: HashSet<u64> = included.iter().map(|b| b.start_pc).collect();
    let edge_count = included_edge_count(inner, &included_starts);
    let dot = build_dot(inner, &included, &included_starts);
    if !q.force && (included.len() > AUTO_DOT_MAX_BLOCKS || edge_count > AUTO_DOT_MAX_EDGES) {
        let overview_svg = build_large_overview_svg(inner, &included, &included_starts);
        return Json(CfgSvgResponse::Large {
            fn_name: filter_fn,
            svg: Some(overview_svg),
            block_count: included.len(),
            edge_count,
            total_block_count: inner.cfg.block_count(),
            dot_bytes: dot.len(),
        });
    }
    let timeout = q.timeout.clamp(5, 300);
    match render_dot_to_svg(dot, timeout).await {
        Ok(svg) => {
            let cached = CfgSvgCached {
                svg: svg.clone(),
                block_count: included.len(),
                total_block_count: inner.cfg.block_count(),
            };
            state
                .inner
                .cfg_svg_cache
                .lock()
                .expect("cfg svg cache poisoned")
                .insert(cache_key, cached);
            Json(CfgSvgResponse::Ready {
                svg,
                fn_name: filter_fn,
                block_count: included.len(),
                total_block_count: inner.cfg.block_count(),
                cached: false,
            })
        }
        Err(err) => Json(CfgSvgResponse::Error { err }),
    }
}

fn build_large_overview_svg(
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
    for (i, block) in included.iter().enumerate() {
        let col = i % cols;
        let row = i / cols;
        let x = margin + col as f64 * (node_w + gap_x);
        let y = margin + row as f64 * (node_h + gap_y);
        positions.insert(block.start_pc, (x, y));
    }

    let mut out = String::new();
    out.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width:.0}\" height=\"{height:.0}\" \
         viewBox=\"0 0 {width:.0} {height:.0}\">"
    ));
    out.push_str(
        "<style>\
         .tm-bg{fill:#0e1117}.tm-edge{stroke:#58a6ff;stroke-opacity:.22;stroke-width:1.1}\
         .tm-node rect{fill:#161b22;stroke:#30363d;stroke-width:1.2;rx:3}\
         .tm-node:hover rect{stroke:#58a6ff;stroke-width:2}.tm-hot rect{stroke:#f7b32b}\
         .tm-title{fill:#d0d7de;font:11px JetBrainsMono,monospace}.tm-sub{fill:#8b949e;font:9px JetBrainsMono,monospace}\
         </style>",
    );
    out.push_str(&format!(
        "<rect class=\"tm-bg\" x=\"0\" y=\"0\" width=\"{width:.0}\" height=\"{height:.0}\"/>"
    ));
    out.push_str("<g class=\"tm-edges\">");
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
        let Some((sx, sy)) = positions.get(&src.start_pc) else {
            continue;
        };
        let Some((dx, dy)) = positions.get(&dst.start_pc) else {
            continue;
        };
        out.push_str(&format!(
            "<line class=\"tm-edge\" x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\"/>",
            sx + node_w / 2.0,
            sy + node_h / 2.0,
            dx + node_w / 2.0,
            dy + node_h / 2.0
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
    let block_insns = collect_first_block_insns(&inner.trace, &inner.cfg, included_starts);
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
    trace: &tracemiku_core::trace::Trace,
    cfg: &tracemiku_core::cfg::CFG,
    wanted_starts: &HashSet<u64>,
) -> HashMap<u64, Vec<(u64, u32)>> {
    let starts: HashSet<u64> = cfg.by_pc.keys().copied().collect();
    let mut out: HashMap<u64, Vec<(u64, u32)>> = HashMap::new();
    let mut done: HashSet<u64> = HashSet::new();
    let mut current: Option<u64> = None;

    for i in 0..trace.len() {
        let pc = trace.pc(i);
        if starts.contains(&pc) {
            current = Some(pc);
        }
        let Some(start) = current else {
            continue;
        };
        if !wanted_starts.contains(&start) {
            current = None;
            continue;
        }
        if done.contains(&start) {
            current = None;
            continue;
        }

        let inst = trace.inst(i);
        out.entry(start).or_default().push((pc, inst));
        let d = tracemiku_core::disasm::decode(pc, inst);
        let end_pc = cfg.block(start).map(|b| b.end_pc).unwrap_or(pc);
        if d.is_branch || pc == end_pc {
            done.insert(start);
            if done.len() >= wanted_starts.len() {
                break;
            }
            current = None;
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
