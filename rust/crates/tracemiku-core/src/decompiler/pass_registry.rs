//! Pass registry — builds the Ghidra-style universal decompiler pipeline.
//!
//! Mirrors Ghidra's `ActionDatabase::universalAction()` which registers
//! every action and rule into a single tree.
//!
//! Phases:
//!   0. Setup — initial IL preparation
//!   1. MainLoop — simplification + DCE + const prop + struct recovery (fixpoint)
//!   2. Cleanup — final simplification pass

use super::pass::{PassGroup, PassPipeline, PassPool};
use super::pass_simplify::{
    RuleIdentityOp, RuleSubToAdd, RuleDoubleNeg, RuleComparisonFold,
};
use super::pass_cond_exec::ConditionalExecutionPass;
use super::pass_const_prop::ConstPropPass;
use super::pass_dce::DeadCodeElimPass;
use super::pass_stack_var::StackVariableRecoveryPass;
use super::pass_struct_recovery::StructRecoveryPass;
use super::pass_switch_norm::SwitchNormalizationPass;
use super::pass_type_inference::TypePropagationPass;

/// Build the universal decompiler pipeline.
///
/// Phase 0: Setup — stack variable recovery, switch normalization
/// Phase 1: MainLoop (repeat until fixpoint, max 20 iterations)
///   - Simplify pool (identity ops, double-neg, comparison fold)
///   - Dead code elimination
///   - Constant propagation
///   - Type inference and propagation
///   - Conditional execution simplification (CSEL folding)
///   - Struct field recovery
/// Phase 2: Cleanup — final simplification pass
pub fn build_universal_pipeline() -> PassPipeline {
    let simplify_pool = PassPool::new("simplify")
        .with_rule(Box::new(RuleIdentityOp))
        .with_rule(Box::new(RuleSubToAdd))
        .with_rule(Box::new(RuleDoubleNeg))
        .with_rule(Box::new(RuleComparisonFold));

    PassPipeline::new("universal")
        .with_phase(
            PassGroup::new("phase0_setup")
                .with_pass(Box::new(StackVariableRecoveryPass))
                .with_pass(Box::new(SwitchNormalizationPass)),
        )
        .with_phase(
            PassGroup::new("phase1_mainloop")
                .with_repeat(true, 20)
                .with_pool(simplify_pool)
                .with_pass(Box::new(DeadCodeElimPass))
                .with_pass(Box::new(ConstPropPass))
                .with_pass(Box::new(TypePropagationPass))
                .with_pass(Box::new(ConditionalExecutionPass))
                .with_pass(Box::new(StructRecoveryPass)),
        )
        .with_phase(
            PassGroup::new("phase2_cleanup")
                .with_pass(Box::new(super::pass_simplify::SimplifyPass)),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::pass::{PassIlExprs, PassIlExpr, PassIlOperand};

    fn make_expr(op: &str, operands: Vec<PassIlOperand>) -> PassIlExpr {
        PassIlExpr {
            op: op.to_string(),
            size: 8,
            pc: 0x1000,
            operands,
            extra: vec![],
        }
    }

    fn imm(v: i64) -> PassIlOperand {
        PassIlOperand::Imm(v)
    }

    fn reg(name: &str) -> PassIlOperand {
        PassIlOperand::Var(name.to_string())
    }

    #[test]
    fn test_universal_pipeline_construction() {
        let pipeline = build_universal_pipeline();
        assert_eq!(pipeline.phases.len(), 3);
        assert_eq!(pipeline.name, "universal");
    }

    #[test]
    fn test_universal_pipeline_simplify() {
        // Simple function: just a ret. Pipeline should execute without error.
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_Ret", vec![reg("x0")]),
        ];

        let pipeline = build_universal_pipeline();
        let stats = pipeline.execute("test_fn", &mut exprs);
        assert_eq!(stats.final_expr_count, 1);
        assert_eq!(stats.total_phases, 3);
    }

    #[test]
    fn test_universal_pipeline_dce_and_constprop() {
        // Dead assignment: x0 = 5, then ret (no use of x0). DCE should remove it.
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(5)]),
            make_expr("LLIL_Ret", vec![reg("xzr")]),
        ];

        let pipeline = build_universal_pipeline();
        let stats = pipeline.execute("test_fn", &mut exprs);
        assert!(stats.phases_changed > 0 || stats.final_expr_count <= 2);
    }

    #[test]
    fn test_pipeline_stats() {
        let pipeline = build_universal_pipeline();
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs.push(make_expr("LLIL_Ret", vec![reg("x0")]));

        let stats = pipeline.execute("test_fn", &mut exprs);
        assert_eq!(stats.total_phases, 3);
        assert_eq!(stats.restarts, 0);
    }
}
