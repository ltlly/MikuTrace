//! Conditional execution folding — Ghidra ActionConditionalExe
#![allow(dead_code)]
use super::pass::{Pass, PassContext, PassIlExpr, PassIlExprs, PassIlOperand, PassInfo, PassResult};

#[derive(Debug)] pub struct ConditionalExecutionPass;
impl Pass for ConditionalExecutionPass {
    fn info(&self) -> PassInfo {
        PassInfo { name: "ConditionalExecution", description: "Fold if/else into CSEL patterns",
            phase: 1, requires: &["Simplify"], invalidates: &[], repeat_until_fixpoint: true }
    }
    fn run(&self, _ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let mut changed = false;
        let n = exprs.exprs.len();
        for i in 0..n.saturating_sub(1) {
            if exprs.exprs[i].op.contains("If") && i + 2 < n {
                let then_op = exprs.exprs[i+1].op.clone();
                let else_op = exprs.exprs[i+2].op.clone();
                if then_op.contains("Set") && else_op.contains("Set")
                    && then_op == else_op {
                    exprs.exprs[i].extra.push(("csel_candidate".into(), "true".into()));
                    changed = true;
                }
            }
        }
        if changed { PassResult::Changed } else { PassResult::Unchanged }
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_cond_exec_fold() {
        let mut e = PassIlExprs::new("t", "llil");
        e.exprs = vec![
            PassIlExpr { op: "LLIL_If".into(), size: 1, pc: 0x1000, operands: vec![PassIlOperand::Imm(1), PassIlOperand::U64(0x2000), PassIlOperand::U64(0x1004)], extra: vec![] },
            PassIlExpr { op: "LLIL_SetReg".into(), size: 8, pc: 0x1004, operands: vec![PassIlOperand::Var("x0".into()), PassIlOperand::Imm(1)], extra: vec![] },
            PassIlExpr { op: "LLIL_SetReg".into(), size: 8, pc: 0x1008, operands: vec![PassIlOperand::Var("x0".into()), PassIlOperand::Imm(0)], extra: vec![] },
        ];
        ConditionalExecutionPass.run(&PassContext{function_name:"t",phase:1,verbose:false}, &mut e);
    }
}
