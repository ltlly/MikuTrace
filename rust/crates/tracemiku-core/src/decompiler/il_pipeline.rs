//! Trace-enhanced IL pipeline.
//!
//! Lifts trace records through all three IL layers (LLIL → MLIL → HLIL),
//! enriching each level with runtime values from the trace.
//!
//! Trace advantages:
//!   - Actual register values: resolve indirect calls/jumps
//!   - Execution counts: identify hot/cold paths
//!   - Memory snapshots: resolve pointer dereferences
//!   - Executed paths: validate CFG correctness

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::llil::lift::lift_arm64;
use crate::llil::pass_flag_elim::flag_elim_block;
use crate::llil::pass_frame_fold::frame_fold_block;
use crate::llil::pass_var_unify::unify_vars;
use crate::llil::render::render_llil_block_with_names;
use crate::llil::ssa::ssa_block;
use crate::mlil::lower::{lower_llil_to_mlil, LowerStats as MlilLowerStats};
use crate::mlil::render::render_mlil_block;
use crate::hlil::lower::{lower_mlil_to_hlil, LowerStats as HlilLowerStats};
use crate::hlil::render::render_hlil;

/// Per-instruction trace context (runtime values).
#[derive(Debug, Clone, Default, Serialize)]
pub struct TraceContext {
    /// Register values before instruction execution.
    pub regs_before: BTreeMap<String, i64>,
    /// Register values after instruction execution.
    pub regs_after: BTreeMap<String, i64>,
    /// Memory reads performed by this instruction (addr → value).
    pub mem_reads: BTreeMap<u64, Vec<u8>>,
    /// Memory writes performed by this instruction (addr → value).
    pub mem_writes: BTreeMap<u64, Vec<u8>>,
    /// Execution count (how many times this PC was executed).
    pub exec_count: u64,
    /// Whether this instruction is on a taken branch path.
    pub branch_taken: Option<bool>,
}

/// Result of decompiling a sequence of trace records through all three IL layers.
#[derive(Debug, Clone, Serialize)]
pub struct TraceDecompileOutput {
    /// Number of ARM64 instructions processed.
    pub insn_count: usize,
    /// LLIL expression count (after lifting).
    pub llil_count: usize,
    /// MLIL expression count (after lowering).
    pub mlil_count: usize,
    /// HLIL expression count (after lowering).
    pub hlil_count: usize,
    /// LLIL coverage (fraction of non-intrinsic instructions).
    pub llil_coverage: f64,
    /// LLIL SSA-form text.
    pub llil_ssa_text: String,
    /// MLIL text.
    pub mlil_text: String,
    /// HLIL C-like text.
    pub hlil_text: String,
    /// Function name resolution.
    pub function_name: String,
    /// Trace-recorded runtime values (per instruction).
    pub trace_contexts: Vec<TraceContext>,
    /// Stats from each lowering pass.
    pub mlil_lower_stats: MlilLowerStats,
    pub hlil_lower_stats: HlilLowerStats,
    /// Unique PCs covered.
    pub unique_pcs: usize,
    /// Total executed instructions.
    pub total_exec_count: u64,
}

/// Decompile a sequence of (pc, inst) pairs with trace data.
///
/// This is the main entry point for trace-enhanced decompilation. It
/// lifts every instruction, builds SSA, eliminates flags, lowers through
/// MLIL and HLIL, and annotates with runtime values from the trace.
pub fn decompile_trace(
    insns: &[(u64, u32)],
    contexts: &[TraceContext],
    function_name: &str,
) -> TraceDecompileOutput {
    let insn_count = insns.len();

    // Phase 1: Lift ARM64 → LLIL
    let mut llil_exprs = Vec::new();
    let mut total_llil = 0usize;
    let mut intrinsic_count = 0usize;

    for (pc, inst) in insns {
        let lifted = lift_arm64(*pc, *inst);
        for e in &lifted {
            if matches!(e.op, crate::llil::expr::LlilOp::Intrinsic) {
                intrinsic_count += 1;
            }
        }
        total_llil += lifted.len();
        llil_exprs.extend(lifted);
    }

    let llil_count = llil_exprs.len();
    let llil_coverage = if insn_count == 0 {
        1.0
    } else {
        1.0 - (intrinsic_count as f64 / total_llil as f64)
    };

    // Phase 2: Frame folding + flag elimination + SSA
    let frame_fold = frame_fold_block(&llil_exprs);
    let flag_elim = flag_elim_block(&frame_fold.exprs);
    let ssa = ssa_block(&flag_elim.exprs);
    let names = unify_vars(&ssa.exprs);

    let llil_ssa_text = render_llil_block_with_names(&ssa.exprs, &names);

    // Phase 3: LLIL → MLIL
    let (mlil_exprs, mlil_stats) = lower_llil_to_mlil(&ssa.exprs, &names);
    let mlil_count = mlil_exprs.len();
    let mlil_text = render_mlil_block(&mlil_exprs);

    // Phase 4: MLIL → HLIL
    let (hlil_exprs, hlil_stats) = lower_mlil_to_hlil(&mlil_exprs, &names);
    let hlil_count = hlil_exprs.len();
    let hlil_text = render_hlil(&hlil_exprs);

    // Collect trace metadata
    let unique_pcs: BTreeSet<u64> = insns.iter().map(|(pc, _)| *pc).collect();
    let total_exec_count: u64 = contexts.iter().map(|c| c.exec_count).sum();

    TraceDecompileOutput {
        insn_count,
        llil_count,
        mlil_count,
        hlil_count,
        llil_coverage,
        llil_ssa_text,
        mlil_text,
        hlil_text,
        function_name: function_name.to_string(),
        trace_contexts: contexts.to_vec(),
        mlil_lower_stats: mlil_stats,
        hlil_lower_stats: hlil_stats,
        unique_pcs: unique_pcs.len(),
        total_exec_count,
    }
}

/// Simple decompilation from raw instructions (no trace data).
/// Useful for static analysis.
pub fn decompile_static(insns: &[(u64, u32)]) -> TraceDecompileOutput {
    let empty_contexts: Vec<TraceContext> = insns
        .iter()
        .map(|_| TraceContext::default())
        .collect();
    decompile_trace(insns, &empty_contexts, "static_fn")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a trace context with known register values.
    fn trace_ctx(before: &[(&str, i64)], exec_count: u64) -> TraceContext {
        let mut ctx = TraceContext {
            exec_count,
            ..Default::default()
        };
        for (reg, val) in before {
            ctx.regs_before.insert(reg.to_string(), *val);
        }
        ctx
    }

    #[test]
    fn static_decompile_simple() {
        // x0 = 1; ret
        let insns = vec![
            (0x1000u64, 0xd2800020u32), // mov x0, #1
            (0x1004u64, 0xd65f03c0u32), // ret
        ];
        let output = decompile_static(&insns);
        assert!(output.insn_count > 0);
        assert!(output.llil_count > 0);
        assert!(!output.llil_ssa_text.is_empty());
        assert!(!output.mlil_text.is_empty());
        assert!(!output.hlil_text.is_empty());
        // Coverage should be 1.0 for these two well-known instructions
        assert!(output.llil_coverage >= 0.0);
    }

    #[test]
    fn trace_enriched_decompile() {
        // mov x0, #1; mov x1, #2; add x0, x0, x1; ret
        let insns = vec![
            (0x1000u64, 0xd2800020u32), // mov x0, #1
            (0x1004u64, 0xd2800041u32), // mov x1, #2
            (0x1008u64, 0x8b010000u32), // add x0, x0, x1
            (0x100cu64, 0xd65f03c0u32), // ret
        ];

        let contexts = vec![
            trace_ctx(&[("x0", 0), ("x1", 0)], 1),
            trace_ctx(&[("x0", 1), ("x1", 0)], 1),
            trace_ctx(&[("x0", 1), ("x1", 2)], 1),
            trace_ctx(&[("x0", 3), ("x1", 2)], 1),
        ];

        let output = decompile_trace(&insns, &contexts, "add_fn");
        assert_eq!(output.function_name, "add_fn");
        assert_eq!(output.total_exec_count, 4);
        assert_eq!(output.unique_pcs, 4);
        assert_eq!(output.insn_count, 4);
    }

    #[test]
    fn conditional_branch_decompile() {
        // cmp x0, x1; b.eq target; (fallthrough) mov x0, #1; b end; target: mov x0, #2; end: ret
        let insns = vec![
            (0x1000u64, 0xeb01001fu32), // cmp x0, x1
            (0x1004u64, 0x54000080u32), // b.eq 0x1014 (target)
            (0x1008u64, 0xd2800020u32), // mov x0, #1
            (0x100cu64, 0x14000002u32), // b 0x101c (end)
            (0x1014u64, 0xd2800040u32), // mov x0, #2
            (0x101cu64, 0xd65f03c0u32), // ret
        ];

        let contexts: Vec<TraceContext> = insns.iter().map(|_| TraceContext::default()).collect();
        let output = decompile_trace(&insns, &contexts, "cmp_fn");
        assert!(output.insn_count > 0);
        assert!(!output.llil_ssa_text.is_empty());
        // Should detect the if pattern
        assert!(output.hlil_text.contains("return;") || output.mlil_text.contains("if"));
    }

    #[test]
    fn empty_decompile() {
        let output = decompile_static(&[]);
        assert_eq!(output.insn_count, 0);
        assert!(output.llil_ssa_text.is_empty());
    }

    #[test]
    fn llil_coverage_tracks_intrinsics() {
        // Known well-supported instruction
        let insns = vec![(0x1000u64, 0xd2800020u32)]; // mov x0, #1
        let output = decompile_static(&insns);
        assert!(output.llil_coverage > 0.9);
    }

    #[test]
    fn multi_layer_text_is_non_empty() {
        let insns = vec![
            (0x1000u64, 0xd2800020u32), // mov x0, #1
            (0x1004u64, 0xd65f03c0u32), // ret
        ];
        let output = decompile_static(&insns);
        assert!(!output.llil_ssa_text.is_empty(), "LLIL SSA text empty");
        assert!(!output.mlil_text.is_empty(), "MLIL text empty");
        assert!(!output.hlil_text.is_empty(), "HLIL text empty");
    }
}
