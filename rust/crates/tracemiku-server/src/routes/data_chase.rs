//! GET /api/data-chase?start=&reg=&max_steps=&exclude_regs=

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::disasm::addr_of;
use tracemiku_core::prelude::*;

use crate::state::AppState;

const MAX_DATA_CHASE_STEPS: usize = 1_000;

#[derive(Debug, Deserialize)]
pub struct DataChaseQuery {
    pub start: usize,
    pub reg: String,
    #[serde(default = "default_max_steps")]
    pub max_steps: usize,
    #[serde(default = "default_exclude_regs")]
    pub exclude_regs: String,
}

fn default_max_steps() -> usize {
    50
}

fn effective_max_steps(raw: usize) -> usize {
    raw.min(MAX_DATA_CHASE_STEPS)
}

fn default_exclude_regs() -> String {
    "sp,fp,lr".to_string()
}

#[derive(Debug, Serialize)]
pub struct DataChaseStep {
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub func: Option<String>,
    pub asm: String,
    pub via: String,
    pub src: String,
}

#[derive(Debug, Serialize)]
pub struct DataChaseResponse {
    #[serde(rename = "from")]
    pub from_idx: usize,
    pub reg: String,
    pub count: usize,
    pub steps: Vec<DataChaseStep>,
}

pub async fn data_chase_handler(
    State(state): State<AppState>,
    Query(q): Query<DataChaseQuery>,
) -> Json<DataChaseResponse> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || data_chase_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "data chase worker failed: {err}");
                DataChaseResponse {
                    from_idx: 0,
                    reg: String::new(),
                    count: 0,
                    steps: Vec::new(),
                }
            }),
    )
}

fn data_chase_response(
    inner: &crate::state::AppStateInner,
    q: DataChaseQuery,
) -> DataChaseResponse {
    let exclude = parse_exclude_regs(&q.exclude_regs);
    let base = primary_base(&inner.meta);
    let raw_steps = data_chase_core(
        inner,
        q.start,
        &q.reg,
        effective_max_steps(q.max_steps),
        &exclude,
    );
    let steps: Vec<DataChaseStep> = raw_steps
        .into_iter()
        .map(|raw| {
            let rec = inner.trace.record(raw.idx);
            let (func_name, _) = inner.symbols.lookup(rec.pc);
            DataChaseStep {
                idx: raw.idx,
                pc: format!("{:#x}", rec.pc),
                rel: base.map(|b| format!("{:#x}", rec.pc.wrapping_sub(b))),
                func: (func_name != "?").then_some(func_name),
                asm: raw.asm,
                via: raw.via,
                src: raw.src,
            }
        })
        .collect();
    DataChaseResponse {
        from_idx: q.start,
        reg: q.reg,
        count: steps.len(),
        steps,
    }
}

#[cfg(test)]
mod tests {
    use super::{effective_max_steps, MAX_DATA_CHASE_STEPS};

    #[test]
    fn effective_max_steps_caps_extreme_requests() {
        assert_eq!(effective_max_steps(0), 0);
        assert_eq!(effective_max_steps(50), 50);
        assert_eq!(effective_max_steps(usize::MAX), MAX_DATA_CHASE_STEPS);
    }
}

struct RawStep {
    idx: usize,
    asm: String,
    via: String,
    src: String,
}

fn data_chase_core(
    inner: &crate::state::AppStateInner,
    start_idx: usize,
    taint_reg: &str,
    max_steps: usize,
    exclude_regs: &std::collections::HashSet<String>,
) -> Vec<RawStep> {
    let mut cur_idx = start_idx.min(inner.trace.len());
    let mut cur_reg = taint_reg.to_string();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();

    while out.len() < max_steps {
        if exclude_regs.contains(&cur_reg) || !seen.insert((cur_idx, cur_reg.clone())) {
            break;
        }
        let Some(def_idx) = inner.index.last_def_before(&cur_reg, cur_idx) else {
            break;
        };
        let record = inner.trace.record(def_idx);
        let decoded = decode(record.pc, record.inst);
        let asm = format!("{} {}", decoded.mnemonic, decoded.op_str)
            .trim()
            .to_string();

        let is_load = !decoded.mem_op.is_empty() && decoded.mem_op.iter().all(|op| !op.is_write);
        if is_load {
            let op = &decoded.mem_op[0];
            let mem_addr = addr_of(&record, op);
            out.push(RawStep {
                idx: def_idx,
                asm,
                via: "mem-load".to_string(),
                src: format!("{mem_addr:#x}"),
            });
            let Some(write_idx) = latest_write_to_addr(&inner.index, mem_addr, def_idx) else {
                break;
            };
            let write_rec = inner.trace.record(write_idx);
            let write_dec = decode(write_rec.pc, write_rec.inst);
            let write_asm = format!("{} {}", write_dec.mnemonic, write_dec.op_str)
                .trim()
                .to_string();
            let src = source_reg_for_store(&write_dec, exclude_regs);
            out.push(RawStep {
                idx: write_idx,
                asm: write_asm,
                via: "mem-store-src".to_string(),
                src: src.clone().unwrap_or_else(|| "?".to_string()),
            });
            let Some(src) = src else {
                break;
            };
            cur_idx = write_idx;
            cur_reg = src;
            continue;
        }

        let candidates = non_addressing_reg_uses(&decoded, exclude_regs);
        if let Some(next_reg) = candidates.first() {
            out.push(RawStep {
                idx: def_idx,
                asm,
                via: "reg".to_string(),
                src: next_reg.clone(),
            });
            cur_idx = def_idx;
            cur_reg = next_reg.clone();
        } else {
            out.push(RawStep {
                idx: def_idx,
                asm,
                via: "terminal".to_string(),
                src: "(no data deps)".to_string(),
            });
            break;
        }
    }

    out
}

fn latest_write_to_addr(index: &Index, addr: u64, before_idx: usize) -> Option<usize> {
    let pos = index
        .mem_writes
        .partition_point(|write| write.idx < before_idx);
    for write in index.mem_writes[..pos].iter().rev() {
        if addr >= write.addr && addr < write.addr.saturating_add(write.size as u64) {
            return Some(write.idx);
        }
    }
    None
}

fn source_reg_for_store(
    decoded: &DecodedInsn,
    exclude_regs: &std::collections::HashSet<String>,
) -> Option<String> {
    let (base, idx) = decoded
        .mem_op
        .iter()
        .find(|op| op.is_write)
        .map(|op| (op.base.as_str(), op.idx.as_str()))
        .unwrap_or(("", ""));
    decoded
        .regs_use
        .iter()
        .find(|reg| reg.as_str() != base && reg.as_str() != idx && !exclude_regs.contains(*reg))
        .cloned()
}

fn non_addressing_reg_uses(
    decoded: &DecodedInsn,
    exclude_regs: &std::collections::HashSet<String>,
) -> Vec<String> {
    let mut addressing = std::collections::HashSet::new();
    for op in &decoded.mem_op {
        if !op.base.is_empty() {
            addressing.insert(op.base.clone());
        }
        if !op.idx.is_empty() {
            addressing.insert(op.idx.clone());
        }
    }
    decoded
        .regs_use
        .iter()
        .filter(|reg| !exclude_regs.contains(*reg) && !addressing.contains(*reg))
        .cloned()
        .collect()
}

fn parse_exclude_regs(s: &str) -> std::collections::HashSet<String> {
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn primary_base(meta: &TraceMeta) -> Option<u64> {
    meta.module
        .as_ref()
        .and_then(|m| u64::from_str_radix(m.base.trim_start_matches("0x"), 16).ok())
}
