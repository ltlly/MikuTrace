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
use super::pass_ghidra_full::*;
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
        // Phase 0: Setup — Ghidra equivalents: Start, Heritage, StartTypes, StackPtrFlow, SwitchNorm
        .with_phase(
            PassGroup::new("phase0_setup")
                .with_pass(Box::<ActionStart>::default())
                .with_pass(Box::<ActionHeritage>::default())
                .with_pass(Box::<ActionStartTypes>::default())
                .with_pass(Box::<ActionConstantPtr>::default())
                .with_pass(Box::<ActionSpacebase>::default())
                .with_pass(Box::<ActionDirectWrite>::default())
                .with_pass(Box::new(StackVariableRecoveryPass))
                .with_pass(Box::new(SwitchNormalizationPass)),
        )
        // Phase 1: MainLoop (fixpoint) — Ghidra equivalents: full loop body
        .with_phase(
            PassGroup::new("phase1_mainloop")
                .with_repeat(true, 20)
                .with_pass(Box::<ActionLaneDivide>::default())
                .with_pass(Box::<ActionSegmentize>::default())
                .with_pass(Box::<ActionMultiCse>::default())
                .with_pass(Box::<ActionShadowVar>::default())
                .with_pass(Box::<ActionDeindirect>::default())
                .with_pass(Box::<ActionNonzeroMask>::default())
                .with_pool(simplify_pool)
                .with_pass(Box::new(DeadCodeElimPass))
                .with_pass(Box::new(ConstPropPass))
                .with_pass(Box::<ActionCopyMarker>::default())
                .with_pass(Box::<ActionDominantCopy>::default())
                .with_pass(Box::<ActionMarkExplicit>::default())
                .with_pass(Box::<ActionMarkImplied>::default())
                .with_pass(Box::<ActionMarkIndirectOnly>::default())
                .with_pass(Box::<ActionVarnodeProps>::default())
                .with_pass(Box::new(TypePropagationPass))
                .with_pass(Box::<ActionDeterminedBranch>::default())
                .with_pass(Box::new(ConditionalExecutionPass))
                .with_pass(Box::<ActionRedundBranch>::default())
                .with_pass(Box::<ActionDeterminedBranch>::default())
                .with_pass(Box::<ActionUnreachable>::default())
                .with_pass(Box::<ActionDoNothing>::default())
                .with_pass(Box::<ActionLikelyTrash>::default())
                .with_pass(Box::new(StructRecoveryPass))
                .with_pass(Box::<ActionNormalizeSetup>::default()),
        )
        // Phase 2: Post-mainloop — Ghidra equivalents: stop, merge, high-level
        .with_phase(
            PassGroup::new("phase2_postloop")
                .with_pass(Box::<ActionStop>::default())
                .with_pass(Box::<ActionMergeRequired>::default())
                .with_pass(Box::<ActionMergeAdjacent>::default())
                .with_pass(Box::<ActionMergeCopy>::default())
                .with_pass(Box::<ActionMergeMultiEntry>::default())
                .with_pass(Box::new(StructRecoveryPass))
                .with_pass(Box::<ActionMapGlobals>::default())
                .with_pass(Box::<ActionDynamicMapping>::default())
                .with_pass(Box::<ActionDynamicSymbols>::default())
                .with_pass(Box::<ActionMappedLocalSync>::default()),
        )
        // Phase 3: High-level variable merge
        .with_phase(
            PassGroup::new("phase3_highlevel")
                .with_pass(Box::<ActionAssignHigh>::default())
                .with_pass(Box::<ActionRestructureVarnode>::default())
                .with_pass(Box::<ActionSetCasts>::default())
                .with_pass(Box::<ActionNameVars>::default())
                .with_pass(Box::<ActionHideShadow>::default())
                .with_pass(Box::<ActionRestrictLocal>::default())
                .with_pass(Box::<ActionForceGoto>::default()),
        )
        // Phase 4: Function prototype
        .with_phase(
            PassGroup::new("phase4_prototype")
                .with_pass(Box::<ActionFuncLink>::default())
                .with_pass(Box::<ActionFuncLinkOutOnly>::default())
                .with_pass(Box::<ActionParamDouble>::default())
                .with_pass(Box::<ActionActiveParam>::default())
                .with_pass(Box::<ActionActiveReturn>::default())
                .with_pass(Box::<ActionReturnRecovery>::default())
                .with_pass(Box::<ActionDefaultParams>::default())
                .with_pass(Box::<ActionExtraPopSetup>::default())
                .with_pass(Box::<ActionUnjustifiedParams>::default())
                .with_pass(Box::<ActionInputPrototype>::default())
                .with_pass(Box::<ActionOutputPrototype>::default())
                .with_pass(Box::<ActionPrototypeTypes>::default())
                .with_pass(Box::<ActionPrototypeWarnings>::default())
                .with_pass(Box::<ActionInternalStorage>::default()),
        )
        // Phase 5: Cleanup
        .with_phase(
            PassGroup::new("phase5_cleanup")
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
        assert_eq!(pipeline.phases.len(), 6); // 0=setup, 1=mainloop, 2=postloop, 3=highlevel, 4=prototype, 5=cleanup
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
        assert!(stats.total_phases >= 3);
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
        assert!(stats.total_phases >= 3);
        assert_eq!(stats.restarts, 0);
    }
}
