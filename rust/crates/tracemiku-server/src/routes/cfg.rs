//! GET /api/cfg
//!
//! Returns CFG blocks + edges. Optional ?fn= filter limits blocks to those
//! whose start_pc resolves (via SymbolMap) to the named function.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CfgQuery {
    #[serde(default, rename = "fn")]
    pub fn_name: String,
}

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
}

pub async fn cfg_handler(
    State(state): State<AppState>,
    Query(q): Query<CfgQuery>,
) -> Json<CfgResponse> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || cfg_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "cfg worker failed: {err}");
                CfgResponse {
                    status: "error",
                    blocks: Vec::new(),
                    edges: Vec::new(),
                }
            }),
    )
}

fn cfg_response(inner: &crate::state::AppStateInner, q: CfgQuery) -> CfgResponse {
    let cfg = &inner.cfg;
    let symbols = &inner.symbols;

    let filter_fn = if q.fn_name.is_empty() {
        None
    } else {
        Some(q.fn_name.as_str())
    };

    let mut blocks_out: Vec<BlockJson> = Vec::with_capacity(cfg.block_count());
    for b in cfg.blocks() {
        let (fn_name_str, _off) = symbols.lookup(b.start_pc);
        let fn_name = if fn_name_str == "?" {
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

        blocks_out.push(BlockJson {
            start_pc: format!("{:#x}", b.start_pc),
            end_pc: format!("{:#x}", b.end_pc),
            executions: b.executions,
            fn_name,
            scc_id: b.scc_id,
        });
    }

    let mut edges_out: Vec<[String; 2]> = Vec::with_capacity(cfg.edge_count());
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
        edges_out.push([format!("{:#x}", f.start_pc), format!("{:#x}", t.start_pc)]);
    }

    CfgResponse {
        status: "ready",
        blocks: blocks_out,
        edges: edges_out,
    }
}
