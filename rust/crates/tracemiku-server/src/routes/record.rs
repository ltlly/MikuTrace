//! GET /api/record/{idx} — single-record detail.
//!
//! Always emits all 33 registers (x0..x28, fp, lr, sp, pc, nzcv). For M2-β,
//! `prev_regs` and `regs_annotated` from the Python schema are omitted —
//! M2-γ adds them once display.py / pwndbg-style classifier lands.

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

    let mut regs = BTreeMap::new();
    let names = [
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
        "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26",
        "x27", "x28", "fp", "lr", "sp", "pc", "nzcv",
    ];
    for nm in names {
        if let Some(v) = r.reg(nm) {
            regs.insert(nm.to_string(), format!("{v:#x}"));
        }
    }

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
    }))
}
