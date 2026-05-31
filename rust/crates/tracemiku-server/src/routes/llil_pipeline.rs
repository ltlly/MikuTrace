//! POST /api/llil/pipeline — full LLIL→MLIL→HLIL decompiler pipeline.
//!
//! Returns all three layers plus pipeline stats.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use tracemiku_core::decompiler::il_pipeline::{decompile_trace, TraceContext};
use tracemiku_core::function_index::parse_id;
use tracemiku_core::prelude::FuncIR;
use tracemiku_core::trace::Record;

use crate::state::AppState;

const MAX_PIPELINE_RECORDS: usize = 5_000;

#[derive(Debug, Deserialize)]
pub struct LlilPipelinePayload {
    #[serde(default = "default_fn_id")]
    pub fn_id: String,
    #[serde(default = "default_max_records")]
    pub max_records: usize,
    #[serde(default)]
    pub include_text: bool,
    #[serde(default)]
    pub include_call_analysis: bool,
}

fn default_fn_id() -> String {
    "trace:F0".to_string()
}

fn default_max_records() -> usize {
    500
}

fn effective_max_records(raw: usize) -> usize {
    raw.clamp(1, MAX_PIPELINE_RECORDS)
}

#[derive(Debug, Serialize)]
pub struct PipelineResponse {
    pub fn_id: String,
    pub name: String,
    pub records: usize,
    pub truncated: bool,
    pub unique_pcs: usize,
    // LLIL stats
    pub llil_count: usize,
    pub llil_coverage: f64,
    // MLIL stats
    pub mlil_count: usize,
    pub struct_loads: u64,
    pub struct_stores: u64,
    // HLIL stats
    pub hlil_count: usize,
    // Pass statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constfold_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dce_removed_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dce_iterations: Option<usize>,
    // Text output (only when include_text=true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llil_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mlil_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hlil_text: Option<String>,
    // Trace data consumed by the pipeline.
    pub total_exec_count: u64,
    pub trace_contexts: usize,
    // Call analysis (only when include_call_analysis=true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_analysis: Option<serde_json::Value>,
}

pub async fn llil_pipeline_handler(
    State(state): State<AppState>,
    Json(payload): Json<LlilPipelinePayload>,
) -> Result<Json<PipelineResponse>, (StatusCode, String)> {
    let response = tokio::task::spawn_blocking(move || pipeline_response(&state, payload))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "pipeline worker failed: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "pipeline worker failed".to_string(),
            )
        })??;
    Ok(Json(response))
}

fn pipeline_response(
    state: &AppState,
    payload: LlilPipelinePayload,
) -> Result<PipelineResponse, (StatusCode, String)> {
    let fn_ = resolve_fn(state, &payload.fn_id)?;
    let inner = &state.inner;
    let max_records = effective_max_records(payload.max_records);

    let trace_len = inner.trace.len();
    let start = fn_.entry_idx.min(trace_len);
    let end = fn_.exit_idx.min(trace_len.saturating_sub(1));

    // Collect unique (pc, inst) pairs + call-site register values
    let mut seen = BTreeSet::new();
    let mut insns: Vec<(u64, u32)> = Vec::new();
    let mut contexts: Vec<TraceContext> = Vec::new();
    let mut call_site_regs: BTreeMap<u64, Vec<(String, i64)>> = BTreeMap::new();
    let mut blr_resolutions: BTreeMap<String, u64> = BTreeMap::new();

    if start <= end {
        for idx in start..=end {
            if insns.len() >= max_records {
                break;
            }
            let rec = inner.trace.record(idx);
            let inst = rec.inst;

            // Function boundary: blr creates a new function context.
            // Stop collecting after blr — the following code is the callee's.
            let is_blr = (inst & 0xFFFFFC1F) == 0xD63F0000;
            if is_blr && !insns.is_empty() {
                // Record the call site args before stopping
                let caller_pc = rec.pc;
                let target = decode_call_target(caller_pc, inst, &rec);
                // Record blr register→target resolution for indirect call display
                let rn = (inst >> 5) & 0x1F;
                blr_resolutions.insert(reg_num_to_name(rn), target);
                let regs: Vec<(String, i64)> = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
                    .iter()
                    .filter_map(|r| rec.reg(r).map(|v| (r.to_string(), v as i64)))
                    .filter(|(_, v)| *v != 0)
                    .collect();
                if !regs.is_empty() {
                    call_site_regs.entry(target).or_insert(regs);
                }
                if seen.insert((rec.pc, inst)) {
                    insns.push((rec.pc, inst));
                    contexts.push(trace_context_for_idx(inner, idx));
                }
                break; // Stop at blr boundary
            }

            // Detect ret: the first meaningful ret generally ends the function
            let is_ret = (inst & 0xFFFFFC1F) == 0xD65F0000;
            if is_ret {
                if seen.insert((rec.pc, inst)) {
                    insns.push((rec.pc, inst));
                    contexts.push(trace_context_for_idx(inner, idx));
                }
                break; // Stop at ret
            }

            if seen.insert((rec.pc, rec.inst)) {
                insns.push((rec.pc, rec.inst));
                contexts.push(trace_context_for_idx(inner, idx));
            }

            // Collect register values for call instructions, keyed by TARGET
            if is_call(inst) {
                let caller_pc = rec.pc;
                let target = decode_call_target(caller_pc, inst, &rec);
                // Record blr register→target resolution for indirect call display
                if (inst & 0xFFFFFC1F) == 0xD63F0000 {
                    let rn = (inst >> 5) & 0x1F;
                    blr_resolutions.insert(reg_num_to_name(rn), target);
                }
                let regs: Vec<(String, i64)> = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
                    .iter()
                    .filter_map(|r| rec.reg(r).map(|v| (r.to_string(), v as i64)))
                    .filter(|(_, v)| *v != 0)
                    .collect();
                if !regs.is_empty() {
                    call_site_regs.entry(target).or_insert(regs);
                }
            }
        }
    }
    let unique_pcs = seen.len();
    let records_consumed = if start <= end {
        (end - start + 1).min(max_records)
    } else {
        0
    };
    let truncated = start <= end && (end - start + 1) > max_records;

    // Run the full three-layer pipeline
    let output = decompile_trace(&insns, &contexts, &fn_.name);

    let mlil_stats = output.mlil_lower_stats;

    // Post-process: annotate call targets with symbol names and args
    let symbols = &inner.symbols;
    let annotate = |text: String| -> String {
        annotate_calls_in_text(&text, symbols, &call_site_regs, &blr_resolutions)
    };

    // Optional: Call analysis
    let call_analysis = if payload.include_call_analysis {
        serde_json::to_value(inner.call_analysis()).ok()
    } else {
        None
    };

    Ok(PipelineResponse {
        fn_id: payload.fn_id,
        name: fn_.name,
        records: records_consumed,
        truncated,
        unique_pcs,
        llil_count: output.llil_count,
        llil_coverage: output.llil_coverage,
        mlil_count: output.mlil_count,
        struct_loads: mlil_stats.struct_loads as u64,
        struct_stores: mlil_stats.struct_stores as u64,
        hlil_count: output.hlil_count,
        constfold_count: Some(output.constfold_count),
        dce_removed_count: Some(output.dce_removed_count),
        dce_iterations: Some(output.dce_iterations),
        llil_text: if payload.include_text {
            Some(annotate(output.llil_ssa_text))
        } else {
            None
        },
        mlil_text: if payload.include_text {
            Some(annotate(output.mlil_text))
        } else {
            None
        },
        hlil_text: if payload.include_text {
            Some(annotate(output.hlil_text))
        } else {
            None
        },
        total_exec_count: output.total_exec_count,
        trace_contexts: output.trace_contexts.len(),
        call_analysis,
    })
}

fn trace_context_for_idx(inner: &crate::state::AppStateInner, idx: usize) -> TraceContext {
    let rec = inner.trace.record(idx);
    let next = (idx + 1 < inner.trace.len()).then(|| inner.trace.record(idx + 1));
    let regs_before = record_regs(&rec);
    let regs_after = next
        .as_ref()
        .map(record_regs)
        .unwrap_or_else(|| regs_before.clone());
    TraceContext {
        regs_before,
        regs_after,
        mem_reads: mem_values_for_idx(&inner.memshadow_if_ready().map(|m| &m.reads), idx),
        mem_writes: mem_values_for_idx(&inner.memshadow_if_ready().map(|m| &m.writes), idx),
        exec_count: inner
            .index
            .pc_to_idxs
            .get(&rec.pc)
            .map(|idxs| idxs.len() as u64)
            .unwrap_or(1),
        branch_taken: branch_taken_at(&rec, next.as_ref()),
    }
}

fn record_regs(rec: &Record) -> BTreeMap<String, i64> {
    let mut regs = BTreeMap::new();
    for i in 0..=28 {
        regs.insert(format!("x{i}"), rec.regs[i] as i64);
    }
    regs.insert("fp".to_string(), rec.regs[29] as i64);
    regs.insert("lr".to_string(), rec.regs[30] as i64);
    regs.insert("sp".to_string(), rec.sp as i64);
    regs.insert("pc".to_string(), rec.pc as i64);
    regs.insert("nzcv".to_string(), rec.nzcv as i64);
    regs
}

fn mem_values_for_idx(
    recs: &Option<&Vec<tracemiku_core::prelude::ShadowMemRec>>,
    idx: usize,
) -> BTreeMap<u64, Vec<u8>> {
    let Some(recs) = recs else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    let start = recs.partition_point(|rec| rec.idx < idx);
    for rec in recs[start..].iter().take_while(|rec| rec.idx == idx) {
        out.insert(rec.addr, mem_value_bytes(rec.value, rec.size));
    }
    out
}

fn mem_value_bytes(value: u64, size: u32) -> Vec<u8> {
    let bytes = value.to_le_bytes();
    bytes[..(size as usize).min(bytes.len())].to_vec()
}

fn branch_taken_at(rec: &Record, next: Option<&Record>) -> Option<bool> {
    let inst = rec.inst;
    if !is_conditional_branch(inst) {
        return None;
    }
    let next_pc = next?.pc;
    Some(next_pc != rec.pc.wrapping_add(4))
}

fn is_conditional_branch(inst: u32) -> bool {
    (inst & 0xff00_0010) == 0x5400_0000 || (inst & 0x7e00_0000) == 0x3400_0000
}

fn resolve_fn(state: &AppState, fn_id: &str) -> Result<FuncIR, (StatusCode, String)> {
    let inner = &state.inner;
    let (src, payload) =
        parse_id(fn_id).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid fn_id: {e}")))?;
    match src.as_str() {
        "trace" => inner
            .top_ir()
            .fn_by_id(&payload)
            .cloned()
            .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such fn {fn_id}"))),
        "sym" => tracemiku_core::prelude::build_symbol_func_ir_indexed(
            &inner.trace,
            &inner.symbols,
            &inner.cfg,
            &inner.index,
            &payload,
        )
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such sym fn {payload}"))),
        "symaddr" => {
            let pc = parse_u64(&payload)
                .ok_or_else(|| (StatusCode::BAD_REQUEST, format!("invalid symaddr {fn_id}")))?;
            tracemiku_core::prelude::build_symbol_func_ir_at_indexed(
                &inner.trace,
                &inner.symbols,
                &inner.cfg,
                &inner.index,
                pc,
            )
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("no such symaddr fn {payload}"),
                )
            })
        }
        "bn" => Err((
            StatusCode::NOT_FOUND,
            "bn:* pipeline is deferred until the Rust BN backend lands".into(),
        )),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported fn_id source {src}"),
        )),
    }
}

fn decode_call_target(pc: u64, inst: u32, rec: &tracemiku_core::trace::record::Record) -> u64 {
    let is_bl = (inst >> 26) == 0b100101;
    if is_bl {
        let offset = ((inst & 0x03FF_FFFF) as i32) << 2;
        pc.wrapping_add(offset as u64)
    } else {
        // blr: target is in the register
        let rn = (inst >> 5) & 0x1F;
        let reg_name = reg_num_to_name(rn);
        rec.reg(&reg_name).unwrap_or(pc)
    }
}

fn reg_num_to_name(rn: u32) -> String {
    match rn {
        0 => "x0",
        1 => "x1",
        2 => "x2",
        3 => "x3",
        4 => "x4",
        5 => "x5",
        6 => "x6",
        7 => "x7",
        8 => "x8",
        9 => "x9",
        10 => "x10",
        11 => "x11",
        12 => "x12",
        13 => "x13",
        14 => "x14",
        15 => "x15",
        16 => "x16",
        17 => "x17",
        18 => "x18",
        19 => "x19",
        20 => "x20",
        21 => "x21",
        22 => "x22",
        23 => "x23",
        24 => "x24",
        25 => "x25",
        26 => "x26",
        27 => "x27",
        28 => "x28",
        29 => "fp",
        30 => "lr",
        _ => "xzr",
    }
    .to_string()
}

/// Classify a call argument value with type hints for type recovery.
fn classify_arg(val: u64, symbols: &tracemiku_core::symbols::SymbolMap) -> String {
    if val == 0 {
        return "NULL".to_string();
    }
    let (name, off) = symbols.lookup(val);
    if !name.is_empty() {
        if off == 0 {
            return format!("&{name} /* 0x{val:x} */");
        }
        return format!("&{name}+0x{off:x} /* 0x{val:x} */");
    }
    // Check if value looks like a pointer (top 16 bits set, typical .so range)
    if val > 0x10000 && val < 0x7fffffffffff {
        return format!("(void*)0x{val:x}");
    }
    // Small integer / enum value
    if val < 0x10000 {
        return format!("0x{val:x}");
    }
    format!("0x{val:x}")
}

fn is_call(inst: u32) -> bool {
    let is_bl = (inst >> 26) == 0b100101;
    let is_blr = (inst & 0xFFFFFC1F) == 0xD63F0000;
    is_bl || is_blr
}

fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Annotate call targets with symbol names and call-site register values.
fn annotate_calls_in_text(
    text: &str,
    symbols: &tracemiku_core::symbols::SymbolMap,
    call_site_regs: &std::collections::BTreeMap<u64, Vec<(String, i64)>>,
    blr_resolutions: &std::collections::BTreeMap<String, u64>,
) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 10);
    for line in text.lines() {
        let mut result = String::new();
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            // match 0xHEX(...) — direct call target
            if chars[i] == '0' && i + 1 < chars.len() && chars[i + 1] == 'x' {
                i += 2; // skip "0x"
                let mut hex_str = String::new();
                while i < chars.len() && chars[i].is_ascii_hexdigit() {
                    hex_str.push(chars[i]);
                    i += 1;
                }
                if i < chars.len() && chars[i] == '(' {
                    if let Ok(addr) = u64::from_str_radix(&hex_str, 16) {
                        let (name, _) = symbols.lookup(addr);
                        let display = if name.is_empty() {
                            format!("sub_{addr:x}")
                        } else {
                            name
                        };
                        let args_str = call_site_regs
                            .get(&addr)
                            .map(|regs| {
                                regs.iter()
                                    .map(|(r, v)| {
                                        format!("{r}={}", classify_arg(*v as u64, symbols))
                                    })
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_default();
                        result.push_str(&format!("{display}({args_str})"));
                        while i < chars.len() && chars[i] != ')' {
                            i += 1;
                        }
                        if i < chars.len() {
                            i += 1;
                        }
                        continue;
                    }
                }
                // Non-call hex address — try global/data symbol resolution
                if let Ok(addr) = u64::from_str_radix(&hex_str, 16) {
                    let (name, off) = symbols.lookup(addr);
                    if !name.is_empty() && off > 0 {
                        result.push_str(&format!("(&{name}+0x{off:x})"));
                        continue;
                    } else if !name.is_empty() {
                        result.push_str(&format!("(&{name})"));
                        continue;
                    }
                }
                result.push_str(&format!("0x{hex_str}"));
                while i < chars.len() && chars[i].is_ascii_alphanumeric() {
                    result.push(chars[i]);
                    i += 1;
                }
                continue;
            }
            // match reg_name(...) — indirect call target (blr xN), e.g. "x8("
            if (chars[i] == 'x' || chars[i] == 'f' || chars[i] == 'l')
                && chars[i..]
                    .iter()
                    .take_while(|c| c.is_alphanumeric() || **c == '_')
                    .count()
                    > 0
            {
                let mut reg_name = String::new();
                let mut j = i;
                while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                    reg_name.push(chars[j]);
                    j += 1;
                }
                if j < chars.len() && chars[j] == '(' {
                    if let Some(&target) = blr_resolutions.get(&reg_name) {
                        let (name, _) = symbols.lookup(target);
                        let display = if name.is_empty() {
                            format!("sub_{target:x}")
                        } else {
                            name
                        };
                        let args_str = call_site_regs
                            .get(&target)
                            .map(|regs| {
                                regs.iter()
                                    .map(|(r, v)| {
                                        format!("{r}={}", classify_arg(*v as u64, symbols))
                                    })
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_default();
                        result.push_str(&format!("{display}({args_str})"));
                        i = j + 1;
                        while i < chars.len() && chars[i] != ')' {
                            i += 1;
                        }
                        if i < chars.len() {
                            i += 1;
                        }
                        continue;
                    }
                }
                // Not a known blr target call — emit the chars we consumed
                result.push_str(&reg_name);
                i = j;
                continue;
            }
            result.push(chars[i]);
            i += 1;
        }
        out.push_str(&result);
        out.push('\n');
    }
    out
}
