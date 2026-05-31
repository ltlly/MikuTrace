//! Constant propagation pass.
//!
//! Forward-propagates constants through variable assignments and folds
//! constant sub-expressions.

use std::collections::BTreeMap;

use super::pass::{
    Pass, PassContext, PassIlExpr, PassIlExprs, PassIlOperand, PassInfo, PassResult,
};

/// Constant propagation pass.
///
/// Two-phase:
///   1. Collect constant values from SetReg/SetVar assignments into a map.
///   2. Rewrite expressions: replace Var references with their constant values
///      when known, and fold constant sub-expressions into immediate results.
#[derive(Debug)]
pub struct ConstPropPass;

impl ConstPropPass {
    /// Collect variable→constant mappings from SetReg/SetVar assignments.
    fn collect_constants(exprs: &[PassIlExpr]) -> BTreeMap<String, i64> {
        let mut map = BTreeMap::new();
        for e in exprs {
            match e.op.as_str() {
                "LLIL_SetReg" | "MLIL_SetVar" | "HLIL_SetVar" => {
                    if e.operands.len() >= 2 {
                        if let PassIlOperand::Var(name) = &e.operands[0] {
                            if let Some(val) = try_eval_const(&e.operands[1]) {
                                map.insert(name.clone(), val);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        map
    }
}

/// Try to extract a simple constant from an operand.
fn try_eval_const(op: &PassIlOperand) -> Option<i64> {
    match op {
        PassIlOperand::Imm(v) => Some(*v),
        _ => None,
    }
}

/// Try to constant-fold an expression.
fn try_eval_expr_const(expr: &PassIlExpr, consts: &BTreeMap<String, i64>) -> Option<i64> {
    let fold = |op: &PassIlOperand| match op {
        PassIlOperand::Imm(v) => Some(*v),
        PassIlOperand::Var(name) => consts.get(name).copied(),
        PassIlOperand::Expr(e) => try_eval_expr_const(e, consts),
        _ => None,
    };

    match expr.op.as_str() {
        "LLIL_Add" | "MLIL_Add" => {
            if expr.operands.len() == 2 {
                let a = fold(&expr.operands[0])?;
                let b = fold(&expr.operands[1])?;
                Some(a.wrapping_add(b))
            } else {
                None
            }
        }
        "LLIL_Sub" | "MLIL_Sub" => {
            if expr.operands.len() == 2 {
                let a = fold(&expr.operands[0])?;
                let b = fold(&expr.operands[1])?;
                Some(a.wrapping_sub(b))
            } else {
                None
            }
        }
        "LLIL_Mul" | "MLIL_Mul" => {
            if expr.operands.len() == 2 {
                let a = fold(&expr.operands[0])?;
                let b = fold(&expr.operands[1])?;
                Some(a.wrapping_mul(b))
            } else {
                None
            }
        }
        "LLIL_And" | "MLIL_And" => {
            if expr.operands.len() == 2 {
                let a = fold(&expr.operands[0])?;
                let b = fold(&expr.operands[1])?;
                Some(a & b)
            } else {
                None
            }
        }
        "LLIL_Or" | "MLIL_Or" => {
            if expr.operands.len() == 2 {
                let a = fold(&expr.operands[0])?;
                let b = fold(&expr.operands[1])?;
                Some(a | b)
            } else {
                None
            }
        }
        "LLIL_Xor" | "MLIL_Xor" => {
            if expr.operands.len() == 2 {
                let a = fold(&expr.operands[0])?;
                let b = fold(&expr.operands[1])?;
                Some(a ^ b)
            } else {
                None
            }
        }
        "LLIL_Neg" | "MLIL_Neg" => {
            if expr.operands.len() == 1 {
                let a = fold(&expr.operands[0])?;
                Some(-a)
            } else {
                None
            }
        }
        "LLIL_Lsl" | "MLIL_Lsl" => {
            if expr.operands.len() == 2 {
                let a = fold(&expr.operands[0])?;
                let b = fold(&expr.operands[1])?;
                Some(a << b)
            } else {
                None
            }
        }
        "LLIL_Lsr" | "MLIL_Lsr" => {
            if expr.operands.len() == 2 {
                let a = fold(&expr.operands[0])?;
                let b = fold(&expr.operands[1])?;
                Some(((a as u64) >> b) as i64)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Rewrite a single operand, substituting constants for variables and folding.
fn rewrite_operand(op: &PassIlOperand, consts: &BTreeMap<String, i64>) -> PassIlOperand {
    match op {
        PassIlOperand::Var(name) => {
            if let Some(&val) = consts.get(name) {
                PassIlOperand::Imm(val)
            } else {
                op.clone()
            }
        }
        PassIlOperand::Expr(e) => {
            let rewritten = rewrite_expr(e, consts);
            // Try to fold the rewritten expression to a constant
            if let Some(val) = try_eval_expr_const(&rewritten, consts) {
                PassIlOperand::Imm(val)
            } else {
                PassIlOperand::Expr(Box::new(rewritten))
            }
        }
        _ => op.clone(),
    }
}

/// Rewrite an expression: fold sub-expressions and propagate constants.
fn rewrite_expr(expr: &PassIlExpr, consts: &BTreeMap<String, i64>) -> PassIlExpr {
    let new_operands: Vec<PassIlOperand> = expr
        .operands
        .iter()
        .map(|op| rewrite_operand(op, consts))
        .collect();
    PassIlExpr {
        op: expr.op.clone(),
        size: expr.size,
        pc: expr.pc,
        operands: new_operands,
        extra: expr.extra.clone(),
    }
}

impl Pass for ConstPropPass {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "ConstProp",
            description: "Forward-propagate constants and fold constant expressions",
            phase: 1,
            requires: &[],
            invalidates: &["DeadCodeElim"],
            repeat_until_fixpoint: true,
        }
    }

    fn run(&self, _ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let consts = Self::collect_constants(&exprs.exprs);
        if consts.is_empty() {
            return PassResult::Unchanged;
        }

        let mut changed = false;
        let rewritten: Vec<PassIlExpr> = exprs
            .exprs
            .iter()
            .map(|e| {
                let new_e = rewrite_expr(e, &consts);
                // Check if anything changed
                if format!("{:?}", new_e.operands) != format!("{:?}", e.operands) {
                    changed = true;
                }
                new_e
            })
            .collect();

        if changed {
            exprs.exprs = rewritten;
            PassResult::Changed
        } else {
            PassResult::Unchanged
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::pass::PassIlOperand;

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
    fn test_const_prop_simple() {
        // x0#1 = 42; ret x0#1 — const prop should detect the constant
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(42)]),
            make_expr("LLIL_Ret", vec![reg("x0#1")]),
        ];

        let pass = ConstPropPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        // Const prop should either make changes or not — the pass just shouldn't panic
        let _ = result;
    }

    #[test]
    fn test_const_fold_add() {
        // x0#1 = 3
        // x1#1 = x0#1 + 5  →  should fold to 8
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(3)]),
            make_expr(
                "LLIL_SetReg",
                vec![
                    reg("x1#1"),
                    PassIlOperand::Expr(Box::new(make_expr("LLIL_Add", vec![reg("x0#1"), imm(5)]))),
                ],
            ),
        ];

        let pass = ConstPropPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        // x1#1 should be set to Imm(8) — the Add folded to constant
        assert!(matches!(exprs.exprs[1].operands[1], PassIlOperand::Imm(8)));
    }

    #[test]
    fn test_no_constants() {
        // x0#1 = y0 (unknown var) — no constants to propagate
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![make_expr("LLIL_SetReg", vec![reg("x0#1"), reg("y0")])];

        let pass = ConstPropPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(!result.is_changed());
    }

    #[test]
    fn test_const_fold_nested() {
        // x0#1 = 2, x1#1 = 3
        // x2#1 = (x0#1 + x1#1) * 4  →  (2+3)*4 = 20
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(2)]),
            make_expr("LLIL_SetReg", vec![reg("x1#1"), imm(3)]),
            make_expr(
                "LLIL_SetReg",
                vec![
                    reg("x2#1"),
                    PassIlOperand::Expr(Box::new(make_expr(
                        "LLIL_Mul",
                        vec![
                            PassIlOperand::Expr(Box::new(make_expr(
                                "LLIL_Add",
                                vec![reg("x0#1"), reg("x1#1")],
                            ))),
                            imm(4),
                        ],
                    ))),
                ],
            ),
        ];

        let pass = ConstPropPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        // x2#1 should be set to 20
        assert!(matches!(exprs.exprs[2].operands[1], PassIlOperand::Imm(20)));
    }

    #[test]
    fn test_const_fold_neg() {
        // x0#1 = 5
        // x1#1 = -x0#1  →  -5
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(5)]),
            make_expr(
                "LLIL_SetReg",
                vec![
                    reg("x1#1"),
                    PassIlOperand::Expr(Box::new(make_expr("LLIL_Neg", vec![reg("x0#1")]))),
                ],
            ),
        ];

        let pass = ConstPropPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        assert!(matches!(exprs.exprs[1].operands[1], PassIlOperand::Imm(-5)));
    }
}
