//! GET /api/records?start=&count=&regs=
//!
//! Returns a window of decoded trace records. Wire-compatible subset of
//! Python `webui/server.py` /api/records.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::*;

use crate::state::AppState;

const MAX_RECORD_COUNT: usize = 1_000;

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
    pub func: Option<String>,
    pub off: Option<String>,
    pub asm: String,
    pub annotation: Option<String>,
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
    pub returned: usize,
    pub requested_count: usize,
    pub max_count_used: usize,
    pub truncated: bool,
    pub records: Vec<RecordRow>,
}

pub async fn records_handler(
    State(state): State<AppState>,
    Query(q): Query<RecordsQuery>,
) -> Json<RecordsResponse> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || records_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "records worker failed: {err}");
                RecordsResponse {
                    start: 0,
                    end: 0,
                    count: 0,
                    returned: 0,
                    requested_count: 0,
                    max_count_used: 0,
                    truncated: false,
                    records: vec![],
                }
            }),
    )
}

fn records_response(inner: &crate::state::AppStateInner, q: RecordsQuery) -> RecordsResponse {
    let n = inner.trace.len();
    if q.start >= n {
        return RecordsResponse {
            start: q.start,
            end: q.start,
            count: 0,
            returned: 0,
            requested_count: q.count,
            max_count_used: q.count.min(MAX_RECORD_COUNT),
            truncated: false,
            records: vec![],
        };
    }
    let count = q.count.min(MAX_RECORD_COUNT);
    let end = q.start.saturating_add(count).min(n);
    let truncated = q.count > count && end < n;

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

    let mut rows = Vec::with_capacity(end - q.start);
    for i in q.start..end {
        let r = inner.trace.record(i);
        let d = decode(r.pc, r.inst);
        let rel = inner
            .modules
            .relative_offset(r.pc)
            .map(|off| format!("{off:#x}"));
        let regs = regs_filter.as_ref().map(|fs| {
            let mut m = std::collections::BTreeMap::new();
            for nm in fs {
                if let Some(v) = r.reg(nm) {
                    m.insert(nm.clone(), format!("{v:#x}"));
                }
            }
            m
        });

        // Symbol resolution (M2-γ): per-record func + off + module.
        let module = inner.modules.resolve_name(r.pc);
        let (func_name, func_off) = inner.symbols.lookup(r.pc);
        let annotation = if (d.is_call || d.is_branch) && i + 1 < n {
            let next_pc = inner.trace.pc(i + 1);
            let (target_name, target_off) = inner.symbols.lookup(next_pc);
            if target_name != "?" && target_name != func_name {
                Some(format!("→ {target_name}+{target_off:#x}"))
            } else {
                None
            }
        } else {
            None
        };
        let exec_count = inner
            .cfg
            .block_containing(r.pc)
            .map(|block| block.executions);
        let (func, off) = if func_name == "?" {
            (None, None)
        } else {
            (Some(func_name), Some(format!("{func_off:#x}")))
        };

        rows.push(RecordRow {
            idx: i,
            pc: format!("{:#x}", r.pc),
            rel,
            module,
            func,
            off,
            asm: format!("{} {}", d.mnemonic, d.op_str).trim().to_string(),
            annotation,
            exec_count,
            is_branch: d.is_branch,
            is_call: d.is_call,
            is_ret: d.is_ret,
            regs,
        });
    }

    RecordsResponse {
        start: q.start,
        end,
        count: end - q.start,
        returned: rows.len(),
        requested_count: q.count,
        max_count_used: count,
        truncated,
        records: rows,
    }
}
