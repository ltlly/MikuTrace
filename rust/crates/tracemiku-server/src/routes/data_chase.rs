//! GET /api/data-chase?start=&reg=&max_steps=&exclude_regs=

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::disasm::{addr_of, MemOp};
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
    pub requested_max_steps: usize,
    pub max_steps_used: usize,
    pub stopped_at_max: bool,
}

pub async fn data_chase_handler(
    State(state): State<AppState>,
    Query(q): Query<DataChaseQuery>,
) -> Result<Json<DataChaseResponse>, crate::routes::WorkerFailure> {
    let inner = state.inner.clone();
    let response = tokio::task::spawn_blocking(move || data_chase_response(&inner, q))
        .await
        .map_err(|err| crate::routes::worker_panic_response("data chase", &err))?;
    Ok(Json(response))
}

fn data_chase_response(
    inner: &crate::state::AppStateInner,
    q: DataChaseQuery,
) -> DataChaseResponse {
    let exclude = parse_exclude_regs(&q.exclude_regs);
    let max_steps_used = effective_max_steps(q.max_steps);
    let reg = normalize_disasm_reg(&q.reg);
    let raw_steps = data_chase_core(inner, q.start, &reg, max_steps_used, &exclude);
    let steps: Vec<DataChaseStep> = raw_steps
        .into_iter()
        .map(|raw| {
            let rec = inner.trace.record(raw.idx);
            let (func_name, _) = inner.symbols.lookup(rec.pc);
            DataChaseStep {
                idx: raw.idx,
                pc: format!("{:#x}", rec.pc),
                rel: inner
                    .modules
                    .relative_offset(rec.pc)
                    .map(|off| format!("{off:#x}")),
                func: (!func_name.is_empty()).then_some(func_name),
                asm: raw.asm,
                via: raw.via,
                src: raw.src,
            }
        })
        .collect();
    let count = steps.len();
    let stopped_at_max = max_steps_used > 0 && count >= max_steps_used;
    DataChaseResponse {
        from_idx: q.start,
        reg,
        count,
        steps,
        requested_max_steps: q.max_steps,
        max_steps_used,
        stopped_at_max,
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

        if let Some(op) = load_mem_op_for_reg(&decoded, &cur_reg) {
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
            let src = source_reg_for_store_addr(&write_dec, &write_rec, mem_addr, exclude_regs);
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
    let writes = index.mem_addr_to_writes.get(&addr)?;
    let pos = writes.partition_point(|&idx| idx < before_idx);
    if pos == 0 {
        None
    } else {
        Some(writes[pos - 1])
    }
}

fn load_mem_op_for_reg<'a>(decoded: &'a DecodedInsn, reg: &str) -> Option<&'a MemOp> {
    decoded
        .mem_op
        .iter()
        .filter(|op| !op.is_write)
        .find(|op| load_dest_regs(decoded, op).iter().any(|dst| dst == reg))
}

fn load_dest_regs(decoded: &DecodedInsn, op: &MemOp) -> Vec<String> {
    if !op.src_reg.is_empty() {
        return vec![op.src_reg.clone()];
    }
    let out = decoded
        .regs_def
        .iter()
        .filter(|reg| **reg != op.base)
        .take(1)
        .cloned()
        .collect::<Vec<_>>();
    if out.is_empty() {
        decoded.regs_def.iter().take(1).cloned().collect()
    } else {
        out
    }
}

fn source_reg_for_store_addr(
    decoded: &DecodedInsn,
    record: &Record,
    addr: u64,
    exclude_regs: &std::collections::HashSet<String>,
) -> Option<String> {
    for op in decoded.mem_op.iter().filter(|op| op.is_write) {
        let base_addr = addr_of(record, op);
        if addr < base_addr || addr >= base_addr.saturating_add(op.size as u64) {
            continue;
        }
        if !op.src_reg.is_empty() {
            return (!exclude_regs.contains(&op.src_reg)).then(|| op.src_reg.clone());
        }
        return decoded
            .regs_use
            .iter()
            .find(|reg| {
                reg.as_str() != op.base.as_str()
                    && reg.as_str() != op.idx.as_str()
                    && !exclude_regs.contains(*reg)
            })
            .cloned();
    }
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
