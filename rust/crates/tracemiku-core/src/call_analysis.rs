//! Call-site parameter analysis from trace data.
// Called from tracemiku-server routes.
#![allow(dead_code, unused_variables)]
//!
//! For every call (bl/blr) in the trace, extracts x0-x7 register values
//! (AAPCS64 calling convention) and resolves the call target. Produces
//! both structured JSON (AI-friendly) and annotated pseudo-C output.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::symbols::SymbolMap;
use crate::trace::Trace;

/// One observed call in the trace.
#[derive(Debug, Clone, Serialize)]
pub struct CallSite {
    /// Trace record index of the call instruction.
    pub idx: usize,
    /// PC of the call instruction (bl/blr).
    pub caller_pc: u64,
    /// Target address of the call.
    pub target_pc: u64,
    /// Resolved name of the target function (if known from symbols).
    pub target_name: Option<String>,
    /// Register values at the call point (x0-x7 = AAPCS64 args).
    pub args: Vec<CallArg>,
    /// Return value in x0 (if return record is present).
    pub ret_val_x0: Option<i64>,
    /// Trace index of the return instruction (if observed).
    pub ret_idx: Option<usize>,
    /// Indicates whether this is an indirect call (blr) vs direct (bl).
    pub is_indirect: bool,
}

/// One call argument (register or stack value).
#[derive(Debug, Clone, Serialize)]
pub struct CallArg {
    /// Register name (x0-x7) or "stack".
    pub reg: String,
    /// Raw value from the register.
    pub value: i64,
    /// Size of the argument (inferred from usage).
    pub size: u8,
    /// Inferred type hint (from trace usage patterns).
    pub type_hint: Option<String>,
}

/// Summary of all calls in a trace.
#[derive(Debug, Clone, Serialize)]
pub struct CallAnalysis {
    /// All observed call sites.
    pub calls: Vec<CallSite>,
    /// Unique call targets (by PC).
    pub unique_targets: usize,
    /// Number of indirect calls (blr).
    pub indirect_calls: usize,
    /// Call sites grouped by target function.
    pub by_target: BTreeMap<u64, Vec<usize>>,
    /// Summary statistics.
    pub stats: CallStats,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CallStats {
    pub total_calls: usize,
    pub direct_calls: usize,
    pub indirect_calls: usize,
    pub resolved_names: usize,
    pub unresolved_names: usize,
}

/// AAPCS64 argument registers in calling order.
pub const ARG_REGS: [&str; 8] = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];

/// Analyze all call sites in a trace.
pub fn analyze_calls(trace: &Trace, symbols: &SymbolMap) -> CallAnalysis {
    let mut calls = Vec::new();
    let mut stats = CallStats::default();

    let total = trace.len();
    for idx in 0..total {
        let rec = trace.record(idx);
        let inst = rec.inst;

        // Detect bl / blr instructions
        let (is_bl, is_blr) = is_call_inst(inst);
        if !is_bl && !is_blr {
            continue;
        }

        stats.total_calls += 1;
        if is_blr {
            stats.indirect_calls += 1;
        } else {
            stats.direct_calls += 1;
        }

        // Get call target: for bl, decode from instruction; for blr, from register
        let target_pc = if is_bl {
            decode_bl_target(rec.pc, inst)
        } else {
            // For blr, read the target register's value
            let target_reg = decode_blr_target_reg(inst);
            rec.reg(target_reg).unwrap_or(0)
        };

        // Resolve target name from symbols
        let (target_name, _) = symbols.lookup(target_pc);
        let target_name = if target_name.is_empty() {
            None
        } else {
            Some(target_name)
        };

        if target_name.is_some() {
            stats.resolved_names += 1;
        } else {
            stats.unresolved_names += 1;
        }

        // Extract argument registers
        let args: Vec<CallArg> = ARG_REGS
            .iter()
            .map(|reg| CallArg {
                reg: reg.to_string(),
                value: rec.reg(reg).unwrap_or(0) as i64,
                size: 8,
                type_hint: None,
            })
            .collect();

        // Find return index (next record at caller_pc + 4)
        let ret_idx =
            (idx + 1..total.min(idx + 200)).find(|&i| trace.record(i).pc == rec.pc.wrapping_add(4));

        let ret_val_x0 = ret_idx.map(|ri| trace.record(ri).reg("x0").unwrap_or(0) as i64);

        calls.push(CallSite {
            idx,
            caller_pc: rec.pc,
            target_pc,
            target_name,
            args,
            ret_val_x0,
            ret_idx,
            is_indirect: is_blr,
        });
    }

    // Build by_target index
    let mut by_target: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (i, call) in calls.iter().enumerate() {
        by_target.entry(call.target_pc).or_default().push(i);
    }

    let unique_targets = by_target.len();

    CallAnalysis {
        calls,
        unique_targets,
        indirect_calls: stats.indirect_calls,
        by_target,
        stats,
    }
}

/// Render call analysis as AI-friendly JSON.
pub fn render_calls_json(analysis: &CallAnalysis) -> String {
    serde_json::to_string_pretty(analysis).unwrap_or_default()
}

/// Render call analysis as AI-friendly compact output (one line per call).
pub fn render_calls_compact(analysis: &CallAnalysis) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# Call Analysis: {} calls, {} unique targets\n",
        analysis.stats.total_calls, analysis.unique_targets
    ));
    for call in &analysis.calls {
        let name = call.target_name.as_deref().unwrap_or("?");
        let args_str: Vec<String> = call
            .args
            .iter()
            .map(|a| format!("{}={:#x}", a.reg, a.value))
            .collect();
        let ret_str = call
            .ret_val_x0
            .map(|v| format!(" -> x0={:#x}", v))
            .unwrap_or_default();
        out.push_str(&format!(
            "#{:06} @{:#x} {} {}({}){}\n",
            call.idx,
            call.caller_pc,
            if call.is_indirect { "blr" } else { "bl" },
            name,
            args_str.join(", "),
            ret_str,
        ));
    }
    out
}

/// Render call analysis as human-readable annotated pseudo-C.
pub fn render_calls_annotated(analysis: &CallAnalysis) -> String {
    let mut out = String::new();
    out.push_str("// === Call Analysis ===\n");
    out.push_str(&format!(
        "// {} calls, {} direct, {} indirect, {} unique targets\n",
        analysis.stats.total_calls,
        analysis.stats.direct_calls,
        analysis.stats.indirect_calls,
        analysis.unique_targets,
    ));
    out.push_str(&format!(
        "// named: {}, unnamed: {}\n",
        analysis.stats.resolved_names, analysis.stats.unresolved_names,
    ));
    out.push('\n');

    for call in &analysis.calls {
        let name = call.target_name.as_deref().unwrap_or("sub_???");
        let args_str: Vec<String> = call
            .args
            .iter()
            .map(|a| format!("/* {}= */ {:#x}", a.reg, a.value))
            .collect();
        out.push_str(&format!("// #{:06} @{:#x}\n", call.idx, call.caller_pc));
        out.push_str(&format!(
            "    {}({}); // {}",
            name,
            args_str.join(", "),
            if call.is_indirect { "blr" } else { "bl" }
        ));
        if let Some(ret) = call.ret_val_x0 {
            out.push_str(&format!(" -> x0={:#x}", ret));
        }
        out.push('\n');
    }
    out
}

/// Detect if an instruction is bl or blr.
fn is_call_inst(inst: u32) -> (bool, bool) {
    // bl:  100101xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    // blr: 1101011000111111000000xxxxx00000
    let is_bl = (inst >> 26) == 0b100101;
    let is_blr = (inst >> 10) == 0b1101011000111111000000 >> 10;
    let is_blr_exact = (inst & 0xFFFFFC1F) == 0xD63F0000;
    (is_bl, is_blr_exact)
}

/// Decode bl target address from instruction.
fn decode_bl_target(pc: u64, inst: u32) -> u64 {
    let offset = ((inst & 0x03FF_FFFF) as i32) << 2;
    pc.wrapping_add(offset as u64)
}

/// Decode the target register from a blr instruction.
fn decode_blr_target_reg(inst: u32) -> &'static str {
    let rn = (inst >> 5) & 0x1F;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_call_inst_bl() {
        // bl instruction: 0x94000002 -> bl 0x8 (from pc 0)
        let (is_bl, is_blr) = is_call_inst(0x94000002);
        assert!(is_bl);
        assert!(!is_blr);
    }

    #[test]
    fn test_is_call_inst_blr() {
        // blr x8: 0xD63F0100
        let (is_bl, is_blr) = is_call_inst(0xD63F0100);
        assert!(!is_bl);
        assert!(is_blr);
    }

    #[test]
    fn test_decode_bl_target() {
        // bl at pc=0x1000, offset=8 -> target=0x1008
        // offset = (imm26 << 2), so imm26=2 -> 0x94000002
        let target = decode_bl_target(0x1000, 0x94000002);
        assert_eq!(target, 0x1008);
    }

    #[test]
    fn test_decode_blr_target_reg() {
        assert_eq!(decode_blr_target_reg(0xD63F0100), "x8");
        assert_eq!(decode_blr_target_reg(0xD63F0000), "x0");
    }

    #[test]
    fn test_arg_regs_constant() {
        assert_eq!(ARG_REGS.len(), 8);
        assert_eq!(ARG_REGS[0], "x0");
        assert_eq!(ARG_REGS[7], "x7");
    }
}
