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
    pub exec_count: Option<u64>,
    pub block_pc: Option<String>,
    pub cfg_status: &'static str,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_ret: bool,
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

    let rel = inner
        .modules
        .relative_offset(r.pc)
        .map(|off| format!("{off:#x}"));

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
    let memshadow = inner.memshadow_if_ready();
    let regs_annotated = names
        .iter()
        .filter_map(|nm| {
            r.reg(nm).map(|v| {
                (
                    (*nm).to_string(),
                    classify_reg_value(inner, memshadow, v, idx, sp),
                )
            })
        })
        .collect();

    // Symbol resolution (M2-γ).
    let (func_name, func_off) = inner.symbols.lookup(r.pc);
    let (func, off) = if func_name == "?" {
        (None, None)
    } else {
        (Some(func_name), Some(format!("{func_off:#x}")))
    };
    let block = inner.cfg.block_containing(r.pc);
    let exec_count = block.map(|b| b.executions);
    let block_pc = block.map(|b| format!("{:#x}", b.start_pc));

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
        exec_count,
        block_pc,
        cfg_status: "ready",
        is_branch: d.is_branch,
        is_call: d.is_call,
        is_ret: d.is_ret,
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

pub(crate) fn classify_reg_value(
    inner: &crate::state::AppStateInner,
    memshadow: Option<&tracemiku_core::memshadow::MemShadow>,
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
        if let Some(mem) = memshadow {
            if let Some(s) = maybe_string_at(mem, cur, idx, 64) {
                parts.push(format!("→ \"{s}\""));
                break;
            }
            if depth < 3 {
                if let Some(next) = deref_u64(mem, cur, idx) {
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
        let Some(b) = byte else {
            return ascii_preview(&bytes, false);
        };
        if b == 0 {
            return ascii_preview(&bytes, false);
        }
        bytes.push(b);
    }
    ascii_preview(&bytes, true)
}

fn ascii_preview(bytes: &[u8], truncated: bool) -> Option<String> {
    if bytes.len() < 4 || !looks_like_ascii(bytes) {
        return None;
    }
    let mut s = String::from_utf8_lossy(bytes).into_owned();
    if truncated {
        s.push_str("...");
    }
    Some(s)
}

fn looks_like_ascii(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let printable = bytes
        .iter()
        .filter(|&&b| (0x20..0x7f).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r'))
        .count();
    printable * 100 >= bytes.len() * 85
}

fn heuristic_region(value: u64) -> Option<&'static str> {
    if (value >> 56) == 0xb4 {
        Some("JavaHeap")
    } else if (0x6d_0000_0000..0x6e_0000_0000).contains(&value) {
        Some("libart?")
    } else if (0x70_0000_0000..0x80_0000_0000).contains(&value) {
        Some("libc?")
    } else {
        None
    }
}

fn parse_hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

#[cfg(test)]
mod tests {
    use super::{ascii_preview, heuristic_region, looks_like_ascii};

    #[test]
    fn heuristic_region_matches_python_web_labels() {
        assert_eq!(heuristic_region(0xb400_0000_0000_0001), Some("JavaHeap"));
        assert_eq!(heuristic_region(0x6d_1234_5678), Some("libart?"));
        assert_eq!(heuristic_region(0x70_1234_5678), Some("libc?"));
        assert_eq!(heuristic_region(0x5000), None);
        assert_eq!(heuristic_region(0x123), None);
    }

    #[test]
    fn ascii_preview_matches_python_web_string_rules() {
        assert_eq!(ascii_preview(b"test", false).as_deref(), Some("test"));
        assert_eq!(
            ascii_preview(b"abcdefghijklmnopqrstuvwxyz", true).as_deref(),
            Some("abcdefghijklmnopqrstuvwxyz...")
        );
        assert_eq!(ascii_preview(b"abc", false), None);
        assert!(looks_like_ascii(b"line\tone\n"));
        assert!(!looks_like_ascii(&[0, 1, 2, 3, b'A']));
    }
}
