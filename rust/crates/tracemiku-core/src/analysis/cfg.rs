//! 运行时 CFG 的块与边。
//!
//! Returns CFG blocks + edges. Optional ?fn= filter limits blocks to those
//! whose start_pc resolves (via SymbolMap) to the named function.

use super::AnalysisError;
use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;

#[derive(Debug, Deserialize, Default)]
pub struct CfgQuery {
    #[serde(default, rename = "fn")]
    pub fn_name: String,
}

const MAX_CFG_BLOCKS: usize = 5_000;
const MAX_CFG_EDGES: usize = 10_000;

#[derive(Debug, Serialize)]
pub struct BlockJson {
    pub start_pc: String,
    pub end_pc: String,
    pub executions: u64,
    pub fn_name: Option<String>,
    pub scc_id: u32,
}

#[derive(Debug, Serialize)]
pub struct CfgResponse {
    pub status: &'static str,
    pub blocks: Vec<BlockJson>,
    pub edges: Vec<[String; 2]>,
    pub total_blocks: usize,
    pub total_edges: usize,
    pub returned_blocks: usize,
    pub returned_edges: usize,
    pub max_blocks_used: usize,
    pub max_edges_used: usize,
    pub truncated: bool,
}

pub fn cfg(state: &AnalysisContext, q: CfgQuery) -> Result<CfgResponse, AnalysisError> {
    let inner = state.inner.clone();
    let _ = inner.cfg()?;
    let response = cfg_response(&inner, q, None);
    Ok(response)
}

fn cfg_response(
    inner: &crate::analysis::context::AnalysisData,
    q: CfgQuery,
    selected: Option<u64>,
) -> CfgResponse {
    let cfg = inner.cfg().expect("CFG preloaded");
    let symbols = inner.symbols();

    let filter_fn = if q.fn_name.is_empty() {
        None
    } else {
        Some(q.fn_name.as_str())
    };

    let selected = selected.and_then(|pc| cfg.block_containing(pc).map(|b| b.start_pc));
    let mut blocks_out: Vec<BlockJson> = Vec::with_capacity(cfg.block_count().min(MAX_CFG_BLOCKS));
    let mut total_blocks = 0usize;
    for b in cfg.blocks() {
        if selected.is_some_and(|pc| b.start_pc != pc) {
            continue;
        }
        let (fn_name_str, _off) = symbols.lookup(b.start_pc);
        let fn_name = if fn_name_str.is_empty() {
            None
        } else {
            Some(fn_name_str)
        };

        if let Some(target) = filter_fn {
            match &fn_name {
                Some(n) if n == target => {}
                _ => continue,
            }
        }

        total_blocks += 1;
        if blocks_out.len() < MAX_CFG_BLOCKS {
            blocks_out.push(BlockJson {
                start_pc: format!("{:#x}", b.start_pc),
                end_pc: format!("{:#x}", b.end_pc),
                executions: b.executions,
                fn_name,
                scc_id: b.scc_id,
            });
        }
    }

    let returned_block_set = blocks_out
        .iter()
        .filter_map(|b| parse_hex(&b.start_pc))
        .collect::<std::collections::HashSet<_>>();
    let mut edges_out: Vec<[String; 2]> = Vec::with_capacity(cfg.edge_count().min(MAX_CFG_EDGES));
    let mut total_edges = 0usize;
    for edge in cfg.graph.edge_indices() {
        let Some((from_n, to_n)) = cfg.graph.edge_endpoints(edge) else {
            continue;
        };
        let from_b = cfg.graph.node_weight(from_n);
        let to_b = cfg.graph.node_weight(to_n);
        let (Some(f), Some(t)) = (from_b, to_b) else {
            continue;
        };
        if let Some(target) = filter_fn {
            let (f_name, _) = symbols.lookup(f.start_pc);
            let (t_name, _) = symbols.lookup(t.start_pc);
            if f_name != target && t_name != target {
                continue;
            }
        }
        if selected.is_some_and(|pc| f.start_pc != pc || t.start_pc != pc) {
            continue;
        }
        total_edges += 1;
        if edges_out.len() < MAX_CFG_EDGES
            && returned_block_set.contains(&f.start_pc)
            && returned_block_set.contains(&t.start_pc)
        {
            edges_out.push([format!("{:#x}", f.start_pc), format!("{:#x}", t.start_pc)]);
        }
    }

    let returned_blocks = blocks_out.len();
    let returned_edges = edges_out.len();
    CfgResponse {
        status: "ready",
        blocks: blocks_out,
        edges: edges_out,
        total_blocks,
        total_edges,
        returned_blocks,
        returned_edges,
        max_blocks_used: MAX_CFG_BLOCKS,
        max_edges_used: MAX_CFG_EDGES,
        truncated: total_blocks > returned_blocks || total_edges > returned_edges,
    }
}

fn parse_hex(s: &str) -> Option<u64> {
    let t = s.trim();
    let hex = t.strip_prefix("0x").unwrap_or(t);
    u64::from_str_radix(hex, 16).ok()
}

/// 公共 CFG 查询：块选择、执行位置和覆盖共享同一上下文。
#[derive(Debug, Deserialize, Default)]
pub struct CfgInspectQuery {
    pub fn_name: String,
    pub pc: Option<String>,
    pub hits: bool,
    pub coverage: bool,
    pub cursor: usize,
    pub limit: usize,
}
#[derive(Debug, Serialize)]
pub struct CfgInspection {
    #[serde(flatten)]
    pub cfg: CfgResponse,
    pub block: Option<super::navigation::BlockDetail>,
    pub hits: Option<BlockHits>,
    pub coverage: Option<serde_json::Value>,
}
#[derive(Debug, Serialize)]
pub struct BlockHits {
    pub indices: Vec<usize>,
    pub total: usize,
    pub returned: usize,
    pub truncated: bool,
    pub cursor: usize,
    pub next_cursor: Option<usize>,
}
pub fn inspect(
    state: &AnalysisContext,
    q: CfgInspectQuery,
) -> Result<CfgInspection, AnalysisError> {
    let selected =
        q.pc.as_deref()
            .map(crate::address_parse::parse_address)
            .transpose()
            .map_err(|e| AnalysisError::invalid(e.to_string()))?;
    if q.hits && selected.is_none() {
        return Err(AnalysisError::invalid("hits requires pc"));
    }
    if q.coverage && selected.is_none() && q.fn_name.is_empty() {
        return Err(AnalysisError::invalid(
            "coverage requires pc or function name",
        ));
    }
    let _ = state.inner.cfg()?;
    let block = q
        .pc
        .as_ref()
        .map(|pc| super::navigation::block(state, super::navigation::PcQuery { pc: pc.clone() }))
        .transpose()?;
    let cfg = cfg_response(
        &state.inner,
        CfgQuery {
            fn_name: q.fn_name.clone(),
        },
        selected,
    );
    let hits = if q.hits {
        let b = state
            .inner
            .cfg()
            .expect("CFG preloaded")
            .block_containing(selected.unwrap())
            .ok_or_else(|| AnalysisError::not_found("block not found"))?;
        let index = state.inner.index();
        // 合并已排序的各 PC 命中列表，只保留本页，不收集整个块的执行历史。
        let mut heap = std::collections::BinaryHeap::new();
        let mut total = 0;
        for (&pc, indices) in &index.pc_to_idxs {
            if pc < b.start_pc || pc > b.end_pc {
                continue;
            }
            let pos = indices.partition_point(|&idx| idx < q.cursor);
            total += indices.len() - pos;
            if pos < indices.len() {
                heap.push(std::cmp::Reverse((indices[pos], pc, pos)));
            }
        }
        let mut indices = Vec::new();
        while indices.len() < q.limit.clamp(1, 1000) {
            let Some(std::cmp::Reverse((idx, pc, pos))) = heap.pop() else {
                break;
            };
            indices.push(idx);
            let next = pos + 1;
            if let Some(&idx) = index.pc_to_idxs[&pc].get(next) {
                heap.push(std::cmp::Reverse((idx, pc, next)));
            }
        }
        let truncated = !heap.is_empty();
        Some(BlockHits {
            returned: indices.len(),
            total,
            cursor: q.cursor,
            next_cursor: truncated.then(|| indices.last().copied().unwrap() + 1),
            indices,
            truncated,
        })
    } else {
        None
    };
    let coverage = q
        .coverage
        .then(|| {
            super::coverage::coverage(
                state,
                super::coverage::CoverageQuery {
                    addr: q.pc,
                    fn_name: q.fn_name,
                    ..Default::default()
                },
            )
        })
        .transpose()?;
    Ok(CfgInspection {
        cfg,
        block,
        hits,
        coverage,
    })
}
