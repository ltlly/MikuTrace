//! GET /api/records?start=&count=&regs=
//!
//! Returns a window of decoded trace records. Wire-compatible subset of
//! Python `webui/server.py` /api/records — symbol-dependent fields
//! (func/off/annotation/exec_count) are emitted as `null` for M2-β;
//! M2-γ populates them after SymbolMap + CFG land.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::*;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RecordsQuery {
    #[serde(default = "default_start")]
    pub start: usize,
    #[serde(default = "default_count")]
    pub count: usize,
    /// Comma-separated reg names. Empty / absent → no `regs` field on rows.
    #[serde(default)]
    pub regs: String,
}

fn default_start() -> usize {
    0
}
fn default_count() -> usize {
    100
}

#[derive(Debug, Serialize)]
pub struct RecordRow {
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub module: Option<String>,
    /// M2-β: always None. M2-γ: function name from SymbolMap.
    pub func: Option<String>,
    /// M2-β: always None. M2-γ: hex offset from func base.
    pub off: Option<String>,
    pub asm: String,
    /// M2-β: always None. M2-γ: derived from CFG + SymbolMap.
    pub annotation: Option<String>,
    /// M2-β: always None. M2-γ: from CFG block.executions.
    pub exec_count: Option<u64>,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_ret: bool,
    /// Only emitted when ?regs=... is set. Otherwise omitted via skip_if.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regs: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Serialize)]
pub struct RecordsResponse {
    pub start: usize,
    pub end: usize,
    pub count: usize,
    pub records: Vec<RecordRow>,
}

pub async fn records_handler(
    State(state): State<AppState>,
    Query(q): Query<RecordsQuery>,
) -> Json<RecordsResponse> {
    let inner = &state.inner;
    let n = inner.trace.len();
    if q.start >= n {
        return Json(RecordsResponse {
            start: q.start,
            end: q.start,
            count: 0,
            records: vec![],
        });
    }
    let end = (q.start + q.count).min(n);

    let regs_filter: Option<Vec<String>> = if q.regs.is_empty() {
        None
    } else {
        let names: Vec<String> = q
            .regs
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        Some(names)
    };

    let base: Option<u64> = inner
        .meta
        .module
        .as_ref()
        .map(|m| u64::from_str_radix(m.base.trim_start_matches("0x"), 16).unwrap_or(0));
    let module_name: Option<&str> = inner.meta.module.as_ref().map(|m| m.name.as_str());

    let mut rows = Vec::with_capacity(end - q.start);
    for i in q.start..end {
        let r = inner.trace.record(i);
        let d = decode(r.pc, r.inst);
        let rel = base.map(|b| format!("{:#x}", r.pc.wrapping_sub(b)));
        let regs = regs_filter.as_ref().map(|fs| {
            let mut m = std::collections::BTreeMap::new();
            for nm in fs {
                if let Some(v) = r.reg(nm) {
                    m.insert(nm.clone(), format!("{v:#x}"));
                }
            }
            m
        });
        rows.push(RecordRow {
            idx: i,
            pc: format!("{:#x}", r.pc),
            rel,
            module: module_name.map(|s| s.to_string()),
            func: None,
            off: None,
            asm: format!("{} {}", d.mnemonic, d.op_str).trim().to_string(),
            annotation: None,
            exec_count: None,
            is_branch: d.is_branch,
            is_call: d.is_call,
            is_ret: d.is_ret,
            regs,
        });
    }

    Json(RecordsResponse {
        start: q.start,
        end,
        count: end - q.start,
        records: rows,
    })
}
