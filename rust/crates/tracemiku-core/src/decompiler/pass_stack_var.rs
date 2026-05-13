//! Stack variable recovery — Ghidra ActionStackPtrFlow
#![allow(dead_code)]
use std::collections::BTreeMap;
use super::pass::{Pass, PassContext, PassIlExpr, PassIlExprs, PassIlOperand, PassInfo, PassResult};

#[derive(Debug)] pub struct StackVariableRecoveryPass;
impl Pass for StackVariableRecoveryPass {
    fn info(&self) -> PassInfo {
        PassInfo { name: "StackVariableRecovery", description: "Identify sp/fp-relative stack vars",
            phase: 0, requires: &[], invalidates: &[], repeat_until_fixpoint: false }
    }
    fn run(&self, _ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let mut changed = false;
        for e in &mut exprs.exprs {
            if let Some((base, offset)) = detect_stack_access(e) {
                if base.contains("sp") || base.contains("fp") {
                    e.extra.push(("stack_var".into(), format!("var_{:x}", offset.abs())));
                    e.extra.push(("stack_offset".into(), format!("0x{:x}", offset)));
                    changed = true;
                }
            }
        }
        if changed { PassResult::Changed } else { PassResult::Unchanged }
    }
}
fn detect_stack_access(e: &PassIlExpr) -> Option<(String, i64)> {
    match e.op.as_str() {
        "LLIL_Load" | "MLIL_Load" | "HLIL_Load" | "LLIL_Store" | "MLIL_Store" | "HLIL_Store" => {
            if let PassIlOperand::Expr(addr) = &e.operands[0] { extract_stack_offset(addr) } else { None }
        }
        _ => None,
    }
}
fn extract_stack_offset(e: &PassIlExpr) -> Option<(String, i64)> {
    if (e.op.contains("Add") || e.op.contains("Sub")) && e.operands.len() == 2 {
        for i in 0..2 {
            if let PassIlOperand::Var(ref base) = e.operands[i] {
                if base.contains("sp") || base.contains("fp") || base == "sp" || base == "fp" {
                    let off_i = 1 - i;
                    return match &e.operands[off_i] {
                        PassIlOperand::Imm(v) => Some((base.clone(), if e.op.contains("Sub") {-v} else {*v})),
                        _ => None,
                    };
                }
            }
        }
    }
    None
}
#[cfg(test)] mod tests {
    use super::*;
    fn m(op: &str, ops: Vec<PassIlOperand>) -> PassIlExpr { PassIlExpr { op: op.into(), size: 8, pc: 0x1000, operands: ops, extra: vec![] } }
    #[test] fn test_detect_sp_load() {
        let mut e = PassIlExprs::new("t", "llil");
        e.exprs = vec![m("LLIL_Load", vec![PassIlOperand::Expr(Box::new(m("LLIL_Add", vec![PassIlOperand::Var("sp".into()), PassIlOperand::Imm(0x10)])))])];
        StackVariableRecoveryPass.run(&PassContext{function_name:"t",phase:0,verbose:false}, &mut e);
    }
}
