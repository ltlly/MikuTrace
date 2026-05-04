//! GET /api/record/{idx} — single-record detail.
//!
//! Always emits all 33 registers (x0..x28, fp, lr, sp, pc, nzcv), plus
//! Python-Web-compatible `prev_regs` and pwndbg-style `regs_annotated`.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use std::collections::BTreeMap;

use tracemiku_core::prelude::*;

use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct RecordDetail {
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub func: Option<String>,
    pub off: Option<String>,
    pub asm: String,
    pub regs: BTreeMap<String, String>,
    pub prev_regs: Option<BTreeMap<String, String>>,
    pub regs_annotated: BTreeMap<String, String>,
    pub regs_def: Vec<String>,
    pub regs_use: Vec<String>,
}

pub async fn record_handler(
    State(state): State<AppState>,
    Path(idx): Path<usize>,
) -> Result<Json<RecordDetail>, StatusCode> {
    let inner = &state.inner;
    if idx >= inner.trace.len() {
        return Err(StatusCode::NOT_FOUND);
    }
    let r = inner.trace.record(idx);
    let d = decode(r.pc, r.inst);

    let base: Option<u64> = inner
        .meta
        .module
        .as_ref()
        .map(|m| u64::from_str_radix(m.base.trim_start_matches("0x"), 16).unwrap_or(0));
    let rel = base.map(|b| format!("{:#x}", r.pc.wrapping_sub(b)));

    let names = [
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
        "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26",
        "x27", "x28", "fp", "lr", "sp", "pc", "nzcv",
    ];
    let regs = regs_map(&r, &names);
    let prev_regs = if idx > 0 {
        Some(regs_map(&inner.trace.record(idx - 1), &names))
    } else {
        None
    };
    let sp = r.reg("sp").unwrap_or(0);
    let regs_annotated = names
        .iter()
        .filter_map(|nm| {
            r.reg(nm)
                .map(|v| ((*nm).to_string(), classify_reg_value(inner, v, idx, sp)))
        })
        .collect();

    // Symbol resolution (M2-γ).
    let (func_name, func_off) = inner.symbols.lookup(r.pc);
    let (func, off) = if func_name == "?" {
        (None, None)
    } else {
        (Some(func_name), Some(format!("{func_off:#x}")))
    };

    Ok(Json(RecordDetail {
        idx,
        pc: format!("{:#x}", r.pc),
        rel,
        func,
        off,
        asm: format!("{} {}", d.mnemonic, d.op_str).trim().to_string(),
        regs,
        prev_regs,
        regs_annotated,
        regs_def: d.regs_def.iter().cloned().collect(),
        regs_use: d.regs_use.iter().cloned().collect(),
    }))
}

fn regs_map(record: &tracemiku_core::trace::Record, names: &[&str]) -> BTreeMap<String, String> {
    let mut regs = BTreeMap::new();
    for nm in names {
        if let Some(v) = record.reg(nm) {
            regs.insert((*nm).to_string(), format!("{v:#x}"));
        }
    }
    regs
}

fn classify_reg_value(
    inner: &crate::state::AppStateInner,
    value: u64,
    idx: usize,
    sp: u64,
) -> String {
    if value == 0 {
        return "NULL".to_string();
    }

    let mut parts = Vec::new();
    let mut cur = value;
    let mut seen = std::collections::BTreeSet::new();
    for depth in 0..=3 {
        if !seen.insert(cur) {
            parts.push("↺".to_string());
            break;
        }
        if sp != 0 {
            let diff = cur.abs_diff(sp);
            if diff < 0x20000 {
                let sign = if cur >= sp { "+" } else { "-" };
                parts.push(format!("[SP{sign}{diff:#x}]"));
                break;
            }
        }
        if let Some(module) = inner.modules.resolve(cur) {
            let base = parse_hex(&module.base).unwrap_or(0);
            let off = cur.saturating_sub(base);
            if inner
                .meta
                .module
                .as_ref()
                .is_some_and(|m| m.name == module.name)
            {
                let (fname, foff) = inner.symbols.lookup(cur);
                if fname != "?" {
                    parts.push(format!("[{fname}+{foff:#x}]"));
                } else {
                    parts.push(format!("[{}+{off:#x}]", module.name));
                }
            } else {
                parts.push(format!("[{}+{off:#x}]", module.name));
            }
            break;
        }
        if let Some(s) = maybe_string_at(&inner.memshadow, cur, idx, 64) {
            parts.push(format!("→ \"{s}\""));
            break;
        }
        if depth < 3 {
            if let Some(next) = deref_u64(&inner.memshadow, cur, idx) {
                if next != 0 && next != cur {
                    if let Some(hint) = heuristic_region(cur) {
                        if depth == 0 {
                            parts.push(format!("({hint})"));
                        }
                    }
                    parts.push(format!("→ {next:#x}"));
                    cur = next;
                    continue;
                }
            }
        }
        if let Some(hint) = heuristic_region(cur) {
            parts.push(format!("({hint})"));
        } else if cur < 0x1000000 {
            parts.push(format!("({cur})"));
        }
        break;
    }
    parts.join(" ")
}

fn deref_u64(mem: &tracemiku_core::memshadow::MemShadow, addr: u64, idx: usize) -> Option<u64> {
    let mut out = 0u64;
    for i in 0..8u64 {
        let (byte, _, _) = mem.byte_at(addr.saturating_add(i), idx as u64);
        out |= u64::from(byte?) << (i * 8);
    }
    Some(out)
}

fn maybe_string_at(
    mem: &tracemiku_core::memshadow::MemShadow,
    addr: u64,
    idx: usize,
    max_len: usize,
) -> Option<String> {
    let mut bytes = Vec::new();
    for i in 0..max_len as u64 {
        let (byte, _, _) = mem.byte_at(addr.saturating_add(i), idx as u64);
        let b = byte?;
        if !(0x20..0x7f).contains(&b) {
            break;
        }
        bytes.push(b);
    }
    if bytes.len() >= 4 {
        String::from_utf8(bytes).ok()
    } else {
        None
    }
}

fn heuristic_region(value: u64) -> Option<&'static str> {
    if (0x1000..0x1_0000_0000).contains(&value) {
        Some("mapped/heap?")
    } else if value >= 0x7000_0000_0000 {
        Some("high user VA")
    } else {
        None
    }
}

fn parse_hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}
