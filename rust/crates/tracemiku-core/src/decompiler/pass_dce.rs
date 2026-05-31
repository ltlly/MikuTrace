//! Dead code elimination pass.
//!
//! Removes variable assignments (SetReg / SetVar) whose result is never
//! consumed by any subsequent instruction.

use std::collections::BTreeSet;

use super::pass::{
    Pass, PassContext, PassIlExpr, PassIlExprs, PassIlOperand, PassInfo, PassResult,
};

/// DCE pass: removes unused SetReg/SetVar instructions.
///
/// Two-pass algorithm:
///   1. Collect all variable *uses* (Var operands anywhere except def position).
///   2. Remove SetReg/SetVar expressions where the defined variable has no uses.
#[derive(Debug)]
pub struct DeadCodeElimPass;

impl DeadCodeElimPass {
    fn collect_uses(exprs: &[PassIlExpr]) -> BTreeSet<String> {
        let mut uses = BTreeSet::new();
        for e in exprs {
            // For SetReg/SetVar, skip the first operand (the definition)
            let skip_first = matches!(e.op.as_str(), "LLIL_SetReg" | "MLIL_SetVar" | "HLIL_SetVar");
            for (i, op) in e.operands.iter().enumerate() {
                if skip_first && i == 0 {
                    continue;
                }
                collect_vars_from_operand(op, &mut uses);
            }
        }
        uses
    }

    fn is_dead_def(expr: &PassIlExpr, uses: &BTreeSet<String>) -> bool {
        match expr.op.as_str() {
            "LLIL_SetReg" | "MLIL_SetVar" | "HLIL_SetVar" => {
                if expr.operands.is_empty() {
                    return false;
                }
                if let PassIlOperand::Var(name) = &expr.operands[0] {
                    return !uses.contains(name);
                }
                false
            }
            _ => false,
        }
    }
}

fn collect_vars_from_operand(op: &PassIlOperand, vars: &mut BTreeSet<String>) {
    match op {
        PassIlOperand::Var(name) => {
            vars.insert(name.clone());
        }
        PassIlOperand::Expr(e) => {
            for operand in &e.operands {
                collect_vars_from_operand(operand, vars);
            }
        }
        _ => {}
    }
}

impl Pass for DeadCodeElimPass {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "DeadCodeElim",
            description: "Remove unused variable assignments (SetReg/SetVar with no live use)",
            phase: 1,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: true,
        }
    }

    fn run(&self, _ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let uses = Self::collect_uses(&exprs.exprs);
        let before = exprs.exprs.len();
        exprs.exprs.retain(|e| !Self::is_dead_def(e, &uses));
        let after = exprs.exprs.len();
        if after < before {
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
    fn test_dce_removes_dead_setreg() {
        // x0 = 42  — dead (no use)
        // x1 = x0 + 1 — x0 is used here, so x0=42 stays? No wait, uses are scanned first.
        // Actually: x0#1 = 42, then x1 = 5. No use of x0#1 → dead.
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(42)]),
            make_expr("LLIL_SetReg", vec![reg("x1#1"), imm(5)]),
        ];

        let pass = DeadCodeElimPass;
        // First pass: both x0#1 and x1#1 have no uses → both removed
        let result = pass.run(
            &PassContext {
                function_name: "test",
                phase: 1,
                verbose: false,
            },
            &mut exprs,
        );
        assert!(result.is_changed());
        assert!(exprs.exprs.is_empty());
    }

    #[test]
    fn test_dce_keeps_used_setreg() {
        // x0#1 = 42
        // x1#1 = x0#1 + 1   — uses x0#1
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(42)]),
            make_expr(
                "LLIL_SetReg",
                vec![
                    reg("x1#1"),
                    PassIlOperand::Expr(Box::new(make_expr("LLIL_Add", vec![reg("x0#1"), imm(1)]))),
                ],
            ),
        ];

        let pass = DeadCodeElimPass;
        let result = pass.run(
            &PassContext {
                function_name: "test",
                phase: 1,
                verbose: false,
            },
            &mut exprs,
        );
        // x0#1 is used by x1#1 so kept. x1#1 has no use → removed.
        assert!(result.is_changed());
        assert_eq!(exprs.exprs.len(), 1);
        assert_eq!(exprs.exprs[0].op, "LLIL_SetReg");
    }

    #[test]
    fn test_dce_no_change() {
        // x0#1 = 42
        // ret x0#1  — uses x0#1
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(42)]),
            make_expr("LLIL_Ret", vec![reg("x0#1")]),
        ];

        let pass = DeadCodeElimPass;
        let result = pass.run(
            &PassContext {
                function_name: "test",
                phase: 1,
                verbose: false,
            },
            &mut exprs,
        );
        assert!(!result.is_changed());
        assert_eq!(exprs.exprs.len(), 2);
    }

    #[test]
    fn test_dce_nested_use() {
        // x0#1 = 42
        // x1#1 = (x0#1 + 5) * 3  — x0#1 used inside nested expr
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(42)]),
            make_expr(
                "LLIL_SetReg",
                vec![
                    reg("x1#1"),
                    PassIlOperand::Expr(Box::new(make_expr(
                        "LLIL_Mul",
                        vec![
                            PassIlOperand::Expr(Box::new(make_expr(
                                "LLIL_Add",
                                vec![reg("x0#1"), imm(5)],
                            ))),
                            imm(3),
                        ],
                    ))),
                ],
            ),
        ];

        let pass = DeadCodeElimPass;
        let result = pass.run(
            &PassContext {
                function_name: "test",
                phase: 1,
                verbose: false,
            },
            &mut exprs,
        );
        // x0#1 used by inner Add → kept. x1#1 not used → removed.
        assert!(result.is_changed());
        assert_eq!(exprs.exprs.len(), 1);
    }

    #[test]
    fn test_dce_repeat_to_fixpoint() {
        // After first DCE removes x1#1, x0#1 may become dead if it was only used by x1#1.
        // But in a single pass, x0#1 was already counted as "used" by x1#1,
        // so it won't be removed. Running DCE again would remove it.
        // This is why repeat_until_fixpoint is true.
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(42)]),
            make_expr("LLIL_SetReg", vec![reg("x1#1"), reg("x0#1")]), // uses x0#1
        ];

        let pass = DeadCodeElimPass;
        // First run: x0#1 is used by x1#1, so stays. x1#1 is unused, removed.
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let r1 = pass.run(&ctx, &mut exprs);
        assert!(r1.is_changed());
        assert_eq!(exprs.exprs.len(), 1); // only x0#1 remains
                                          // Second run: now x0#1 has no use
        let r2 = pass.run(&ctx, &mut exprs);
        assert!(r2.is_changed());
        assert!(exprs.exprs.is_empty());
    }
}
