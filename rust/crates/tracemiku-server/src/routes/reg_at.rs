//! GET /api/reg-at?reg=  &(addr= | so=&off=)  [&max=]
//!
//! "At `libfoo+0x57a30`, what was x0?" — the runtime value point-query keyed on
//! the tool-neutral `(SO, offset)` coordinate a reverse engineer reads straight
//! out of IDA/BN/Ghidra. A static tool shows a register's TYPE or initial value;
//! it cannot show what the register actually held. The trace can, at every one
//! of that PC's executions.
//!
//! The killer fact this surfaces: a single static offset usually holds MANY
//! different values across the run (loop iterations, repeated calls). So besides
//! the per-hit list this returns a distinct-value distribution with counts —
//! something no static analysis can produce.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::routes::resolve::parse_u64;
use crate::state::AppState;
use tracemiku_core::disasm::normalize_disasm_reg;

/// Cap on per-hit rows returned. The distinct-value distribution is always
/// computed over ALL hits regardless of this cap.
const MAX_HITS_RETURNED: usize = 2_000;

#[derive(Debug, Deserialize)]
pub struct RegAtQuery {
    pub reg: String,
    pub addr: Option<String>,
    pub so: Option<String>,
    pub off: Option<String>,
    #[serde(default = "default_max")]
    pub max: usize,
}

fn default_max() -> usize {
    100
}

#[derive(Debug, Serialize)]
pub struct Hit {
    pub idx: usize,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotation: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DistinctValue {
    pub value: String,
    pub count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotation: Option<String>,
}

pub async fn reg_at_handler(
    State(state): State<AppState>,
    Query(q): Query<RegAtQuery>,
) -> Json<Value> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || reg_at_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "reg-at worker failed: {err}");
                json!({ "status": "error", "error": "reg-at worker panicked" })
            }),
    )
}

fn resolve_pc(inner: &crate::state::AppStateInner, q: &RegAtQuery) -> Result<u64, Value> {
    if let Some(addr) = q.addr.as_ref() {
        return parse_u64(addr)
            .ok_or_else(|| json!({ "status": "error", "error": format!("invalid addr: {addr}") }));
    }
    if let (Some(so), Some(off_raw)) = (q.so.as_ref(), q.off.as_ref()) {
        let off = parse_u64(off_raw).ok_or_else(
            || json!({ "status": "error", "error": format!("invalid off: {off_raw}") }),
        )?;
        let candidates = inner.modules.resolve_offset_candidates(so, off);
        return match candidates.len() {
            0 => Err(json!({
                "status": "miss",
                "query": { "so": so, "off": format!("{off:#x}") },
                "reason": "no loaded module matched",
            })),
            1 => Ok(candidates[0].3),
            _ => Err(json!({
                "status": "ambiguous",
                "query": { "so": so, "off": format!("{off:#x}") },
                "candidates": candidates
                    .iter()
                    .map(|(name, base, _end, pc)| json!({
                        "module": name,
                        "module_base": format!("{base:#x}"),
                        "pc": format!("{pc:#x}"),
                    }))
                    .collect::<Vec<_>>(),
                "hint": "narrow `so` to a unique module name",
            })),
        };
    }
    Err(json!({
        "status": "error",
        "error": "provide reg= and (addr=0x... or so=<name>&off=0x...)",
    }))
}

fn reg_at_response(inner: &crate::state::AppStateInner, q: RegAtQuery) -> Value {
    let pc = match resolve_pc(inner, &q) {
        Ok(pc) => pc,
        Err(v) => return v,
    };
    let canon = normalize_disasm_reg(&q.reg);
    let reg = if canon.is_empty() {
        q.reg.clone()
    } else {
        canon
    };

    let idxs = inner.index.pc_to_idxs.get(&pc).cloned().unwrap_or_default();
    let rel = inner.modules.resolve_relative(pc);
    let source = json!({
        "pc": format!("{pc:#x}"),
        "module": rel.as_ref().map(|(n, _)| n.clone()),
        "offset": rel.as_ref().map(|(_, o)| format!("{o:#x}")),
    });

    if idxs.is_empty() {
        return json!({
            "status": "no_execution",
            "reg": reg,
            "source": source,
            "reason": "PC was never executed in this trace",
        });
    }

    let mem = inner.memshadow_if_ready();
    let max = q.max.min(MAX_HITS_RETURNED);

    // Distinct-value distribution over ALL hits; per-hit rows capped at `max`.
    let mut distinct: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    let mut hits: Vec<Hit> = Vec::with_capacity(max.min(idxs.len()));
    let mut unknown_reg = false;

    for (n, &idx) in idxs.iter().enumerate() {
        let record = inner.trace.record(idx);
        let Some(v) = record.reg_by_name(&reg) else {
            unknown_reg = true;
            break;
        };
        *distinct.entry(v).or_insert(0) += 1;
        if n < max {
            let annotation = if reg == "xzr" || reg == "wzr" {
                None
            } else {
                let a = crate::routes::record::classify_reg_value(
                    inner,
                    mem,
                    v,
                    idx,
                    record.reg_by_name("sp").unwrap_or(0),
                );
                (!a.is_empty()).then_some(a)
            };
            hits.push(Hit {
                idx,
                value: format!("{v:#x}"),
                annotation,
            });
        }
    }

    if unknown_reg {
        return json!({
            "status": "error",
            "reg": reg,
            "source": source,
            "error": "unknown register",
        });
    }

    // Distinct values, most frequent first.
    let mut distinct_vec: Vec<DistinctValue> = distinct
        .into_iter()
        .map(|(v, count)| {
            let annotation = if reg == "xzr" || reg == "wzr" || v == 0 {
                None
            } else {
                // annotate using the first hit's context (sp varies; good enough
                // for module/symbol classification of the value itself)
                let first_idx = *idxs.first().unwrap();
                let sp = inner.trace.record(first_idx).reg_by_name("sp").unwrap_or(0);
                let a = crate::routes::record::classify_reg_value(inner, mem, v, first_idx, sp);
                (!a.is_empty()).then_some(a)
            };
            DistinctValue {
                value: format!("{v:#x}"),
                count,
                annotation,
            }
        })
        .collect();
    distinct_vec.sort_by_key(|v| std::cmp::Reverse(v.count));

    json!({
        "status": "hit",
        "reg": reg,
        "source": source,
        "exec_count": idxs.len(),
        "distinct_value_count": distinct_vec.len(),
        "distinct_values": distinct_vec,
        "hits_returned": hits.len(),
        "hits_capped": idxs.len() > max,
        "hits": hits,
    })
}
