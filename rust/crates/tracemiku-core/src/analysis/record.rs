//! 单条指令、寄存器和运行时注释。
//!
//! Always emits all 33 registers (x0..x28, fp, lr, sp, pc, nzcv), plus
//! Stable `prev_regs` and pwndbg-style `regs_annotated`.

use super::AnalysisError;
use serde::Serialize;
use std::collections::BTreeMap;

use crate::prelude::*;

use crate::analysis::context::AnalysisContext;

const MAX_DETAIL_MEMORY_EVENTS: usize = 256;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecordDetailOptions {
    pub pointers: bool,
    pub memory: bool,
    pub cfg: bool,
}

#[derive(Debug, Serialize)]
pub struct RecordMemoryEvent {
    pub idx: usize,
    pub kind: &'static str,
    pub byte: u8,
}

#[derive(Debug, Serialize)]
pub struct RecordMemoryByteHistory {
    pub addr: String,
    pub truncated: bool,
    pub events: Vec<RecordMemoryEvent>,
}

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
    pub pointer_status: &'static str,
    pub memory_status: &'static str,
    pub memory_history: Option<Vec<RecordMemoryByteHistory>>,
    pub memory_truncated: bool,
    pub exec_count: Option<u64>,
    pub block_pc: Option<String>,
    pub cfg_status: &'static str,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_ret: bool,
}

pub fn record(state: &AnalysisContext, idx: usize) -> Result<RecordDetail, AnalysisError> {
    record_with_options(state, idx, RecordDetailOptions::default())
}

pub fn record_with_options(
    state: &AnalysisContext,
    idx: usize,
    options: RecordDetailOptions,
) -> Result<RecordDetail, AnalysisError> {
    let inner = &state.inner;
    if idx >= inner.trace.len() {
        return Err(AnalysisError::not_found("trace record or value not found"));
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
    let memshadow = (options.pointers || options.memory)
        .then(|| inner.memshadow())
        .transpose()?;
    let cfg = options.cfg.then(|| inner.cfg()).transpose()?;
    let local_symbols = if options.cfg || idx == 0 {
        None
    } else {
        crate::symbols::auto_symbol_for_direct_call(&inner.trace, &inner.modules, idx - 1).map(
            |(target, name)| {
                let mut symbols = inner.record_symbols().clone();
                symbols.add_resolved(target, name, &inner.modules);
                symbols.freeze();
                symbols
            },
        )
    };
    let symbols = if options.cfg {
        inner.symbols()
    } else if let Some(symbols) = local_symbols.as_ref() {
        symbols
    } else {
        inner.record_symbols()
    };
    let regs_annotated = names
        .iter()
        .filter_map(|nm| {
            r.reg(nm).map(|v| {
                (
                    (*nm).to_string(),
                    classify_reg_value_with_symbols(
                        inner,
                        options.pointers.then_some(memshadow).flatten(),
                        symbols,
                        v,
                        idx,
                        sp,
                    ),
                )
            })
        })
        .collect();
    let (memory_history, memory_truncated) = if options.memory {
        let (history, truncated) =
            record_memory_history(&r, &d, memshadow.expect("enabled memory"));
        (Some(history), truncated)
    } else {
        (None, false)
    };

    // Symbol resolution (M2-γ).
    let (func_name, func_off) = symbols.lookup(r.pc);
    let (func, off) = if func_name.is_empty() {
        (None, None)
    } else {
        (Some(func_name), Some(format!("{func_off:#x}")))
    };
    let block = cfg.and_then(|cfg| cfg.block_containing(r.pc));
    let exec_count = block.map(|b| b.executions);
    let block_pc = block.map(|b| format!("{:#x}", b.start_pc));

    Ok(RecordDetail {
        idx,
        pc: format!("{:#x}", r.pc),
        rel,
        func,
        off,
        asm: format!("{} {}", d.mnemonic, d.op_str).trim().to_string(),
        regs,
        prev_regs,
        regs_annotated,
        regs_def: d.regs_def.to_vec(),
        regs_use: d.regs_use.to_vec(),
        pointer_status: if options.pointers {
            "ready"
        } else {
            "disabled"
        },
        memory_status: if !options.memory {
            "disabled"
        } else if memory_truncated {
            "truncated"
        } else {
            "ready"
        },
        memory_history,
        memory_truncated,
        exec_count,
        block_pc,
        cfg_status: if options.cfg { "ready" } else { "disabled" },
        is_branch: d.is_branch,
        is_call: d.is_call,
        is_ret: d.is_ret,
    })
}

fn record_memory_history(
    record: &crate::trace::Record,
    decoded: &crate::disasm::DecodedInsn,
    mem: &crate::memshadow::MemShadow,
) -> (Vec<RecordMemoryByteHistory>, bool) {
    let mut history = Vec::new();
    let mut remaining = MAX_DETAIL_MEMORY_EVENTS;
    let mut truncated = false;
    for op in decoded.mem_op.iter().filter(|op| !op.base.is_empty()) {
        let base = crate::disasm::addr_of(record, op);
        for offset in 0..u64::from(op.size) {
            let addr = base.wrapping_add(offset);
            let Some(events) = mem.bytes.get(&addr) else {
                continue;
            };
            let take = events.len().min(remaining);
            let event_truncated = take < events.len();
            truncated |= event_truncated;
            remaining = remaining.saturating_sub(take);
            history.push(RecordMemoryByteHistory {
                addr: format!("{addr:#x}"),
                truncated: event_truncated,
                events: events[events.len() - take..]
                    .iter()
                    .map(|event| RecordMemoryEvent {
                        idx: event.idx(),
                        kind: event.kind.as_str(),
                        byte: event.byte,
                    })
                    .collect(),
            });
        }
    }
    (history, truncated)
}

fn regs_map(record: &crate::trace::Record, names: &[&str]) -> BTreeMap<String, String> {
    let mut regs = BTreeMap::new();
    for nm in names {
        if let Some(v) = record.reg(nm) {
            regs.insert((*nm).to_string(), format!("{v:#x}"));
        }
    }
    regs
}

pub(crate) fn classify_reg_value(
    inner: &crate::analysis::context::AnalysisData,
    memshadow: Option<&crate::memshadow::MemShadow>,
    value: u64,
    idx: usize,
    sp: u64,
) -> String {
    classify_reg_value_with_symbols(inner, memshadow, inner.symbols(), value, idx, sp)
}

fn classify_reg_value_with_symbols(
    inner: &crate::analysis::context::AnalysisData,
    memshadow: Option<&crate::memshadow::MemShadow>,
    symbols: &SymbolMap,
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
                let (fname, foff) = symbols.lookup(cur);
                if !fname.is_empty() {
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

fn deref_u64(mem: &crate::memshadow::MemShadow, addr: u64, idx: usize) -> Option<u64> {
    let mut out = 0u64;
    for i in 0..8u64 {
        let (byte, _, _) = mem.byte_at(addr.saturating_add(i), idx as u64);
        out |= u64::from(byte?) << (i * 8);
    }
    Some(out)
}

fn maybe_string_at(
    mem: &crate::memshadow::MemShadow,
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
    fn heuristic_region_uses_stable_labels() {
        assert_eq!(heuristic_region(0xb400_0000_0000_0001), Some("JavaHeap"));
        assert_eq!(heuristic_region(0x6d_1234_5678), Some("libart?"));
        assert_eq!(heuristic_region(0x70_1234_5678), Some("libc?"));
        assert_eq!(heuristic_region(0x5000), None);
        assert_eq!(heuristic_region(0x123), None);
    }

    #[test]
    fn ascii_preview_uses_printable_string_rules() {
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
