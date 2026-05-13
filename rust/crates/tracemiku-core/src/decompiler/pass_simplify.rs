//! Expression simplification passes (Ghidra oppool1-style Rules).
//!
//! Each rule is a micro-transform on a single IL expression.
//! Rules are pooled in PassPool and applied until fixpoint.

use std::fmt;

use super::pass::{Pass, PassContext, PassIlExpr, PassIlExprs, PassIlOperand, PassInfo, PassResult, Rule};

// ============================================================================
// RuleIdentityOp — identity element elimination
//   x + 0 → x
//   x - 0 → x
//   x * 1 → x
//   x | 0 → x
//   x ^ 0 → x
//   x & -1 → x
// ============================================================================

#[derive(Debug)]
pub struct RuleIdentityOp;

impl Rule for RuleIdentityOp {
    fn name(&self) -> &'static str {
        "IdentityOp"
    }

    fn applies_to(&self) -> &'static [&'static str] {
        &["LLIL_Add", "LLIL_Sub", "LLIL_Mul", "LLIL_Or", "LLIL_Xor", "LLIL_And"]
    }

    fn apply(&self, expr: &PassIlExpr) -> Option<PassIlExpr> {
        if expr.operands.len() != 2 {
            return None;
        }
        let (a, b) = (&expr.operands[0], &expr.operands[1]);
        match expr.op.as_str() {
            "LLIL_Add" | "LLIL_Sub" | "LLIL_Or" | "LLIL_Xor" => {
                // x + 0 → x, 0 + x → x
                if is_zero(b) {
                    return Some(unwrap_operand(a));
                }
                if is_zero(a) {
                    return Some(unwrap_operand(b));
                }
            }
            "LLIL_Mul" => {
                // x * 1 → x, 1 * x → x
                if is_one(b) {
                    return Some(unwrap_operand(a));
                }
                if is_one(a) {
                    return Some(unwrap_operand(b));
                }
            }
            "LLIL_And" => {
                // x & -1 → x, -1 & x → x
                if is_neg_one(b) {
                    return Some(unwrap_operand(a));
                }
                if is_neg_one(a) {
                    return Some(unwrap_operand(b));
                }
            }
            _ => {}
        }
        None
    }
}

// ============================================================================
// RuleSubToAdd — a - b → a + (-b)
// ============================================================================

#[derive(Debug)]
pub struct RuleSubToAdd;

impl Rule for RuleSubToAdd {
    fn name(&self) -> &'static str {
        "SubToAdd"
    }

    fn applies_to(&self) -> &'static [&'static str] {
        &["LLIL_Sub"]
    }

    fn apply(&self, expr: &PassIlExpr) -> Option<PassIlExpr> {
        if expr.operands.len() != 2 {
            return None;
        }
        let a = expr.operands[0].clone();
        let b = expr.operands[1].clone();

        // a - b → a + (-b)
        let neg_b = PassIlExpr {
            op: "LLIL_Neg".to_string(),
            size: expr.size,
            pc: expr.pc,
            operands: vec![b],
            extra: vec![],
        };

        Some(PassIlExpr {
            op: "LLIL_Add".to_string(),
            size: expr.size,
            pc: expr.pc,
            operands: vec![a, PassIlOperand::Expr(Box::new(neg_b))],
            extra: vec![],
        })
    }
}

// ============================================================================
// RuleDoubleNeg — -(-x) → x
// ============================================================================

#[derive(Debug)]
pub struct RuleDoubleNeg;

impl Rule for RuleDoubleNeg {
    fn name(&self) -> &'static str {
        "DoubleNeg"
    }

    fn applies_to(&self) -> &'static [&'static str] {
        &["LLIL_Neg"]
    }

    fn apply(&self, expr: &PassIlExpr) -> Option<PassIlExpr> {
        if expr.operands.len() != 1 {
            return None;
        }
        // If operand is itself a Neg, unwrap: -(-x) → x
        if let PassIlOperand::Expr(inner) = &expr.operands[0] {
            if inner.op == "LLIL_Neg" && inner.operands.len() == 1 {
                return Some(unwrap_operand(&inner.operands[0]));
            }
        }
        None
    }
}

// ============================================================================
// RuleComparisonFold — fold negated comparisons: (a==b)==0 → a!=b
// ============================================================================

#[derive(Debug)]
pub struct RuleComparisonFold;

impl Rule for RuleComparisonFold {
    fn name(&self) -> &'static str {
        "ComparisonFold"
    }

    fn applies_to(&self) -> &'static [&'static str] {
        &["LLIL_CmpE"]
    }

    fn apply(&self, expr: &PassIlExpr) -> Option<PassIlExpr> {
        if expr.operands.len() != 2 {
            return None;
        }
        // (a CmpE b) CmpE 0 → a CmpNe b
        if is_zero(&expr.operands[1]) {
            if let PassIlOperand::Expr(inner) = &expr.operands[0] {
                if inner.op == "LLIL_CmpE" && inner.operands.len() == 2 {
                    return Some(PassIlExpr {
                        op: "LLIL_CmpNe".to_string(),
                        size: expr.size,
                        pc: expr.pc,
                        operands: inner.operands.clone(),
                        extra: vec![],
                    });
                }
            }
        }
        None
    }
}

// ============================================================================
// SimplifyPass — wraps all simplification rules into a Pass
// ============================================================================

#[derive(Debug)]
pub struct SimplifyPass;

impl Pass for SimplifyPass {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "Simplify",
            description: "Apply algebraic simplification rules (identity, double-neg, comparison fold)",
            phase: 1,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: true,
        }
    }

    fn run(&self, _ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(RuleIdentityOp),
            Box::new(RuleSubToAdd),
            Box::new(RuleDoubleNeg),
            Box::new(RuleComparisonFold),
        ];

        let pool = super::pass::PassPool {
            name: "simplify",
            rules,
            max_iterations: 50,
        };

        let mut exprs_vec = std::mem::take(&mut exprs.exprs);
        let result = pool.execute(&mut exprs_vec);
        exprs.exprs = exprs_vec;
        result
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn is_zero(op: &PassIlOperand) -> bool {
    matches!(op, PassIlOperand::Imm(0) | PassIlOperand::U64(0))
}

fn is_one(op: &PassIlOperand) -> bool {
    matches!(op, PassIlOperand::Imm(1) | PassIlOperand::U64(1))
}

fn is_neg_one(op: &PassIlOperand) -> bool {
    matches!(op, PassIlOperand::Imm(-1))
}

fn unwrap_operand(op: &PassIlOperand) -> PassIlExpr {
    match op {
        PassIlOperand::Expr(e) => (**e).clone(),
        PassIlOperand::Var(v) => PassIlExpr {
            op: "LLIL_Reg".to_string(),
            size: 8,
            pc: 0,
            operands: vec![PassIlOperand::Str(v.clone())],
            extra: vec![],
        },
        PassIlOperand::Imm(v) => PassIlExpr {
            op: "LLIL_Const".to_string(),
            size: 8,
            pc: 0,
            operands: vec![PassIlOperand::Imm(*v)],
            extra: vec![],
        },
        PassIlOperand::U64(v) => PassIlExpr {
            op: "LLIL_Const".to_string(),
            size: 8,
            pc: 0,
            operands: vec![PassIlOperand::U64(*v)],
            extra: vec![],
        },
        PassIlOperand::Str(s) => PassIlExpr {
            op: "LLIL_Reg".to_string(),
            size: 8,
            pc: 0,
            operands: vec![PassIlOperand::Str(s.clone())],
            extra: vec![],
        },
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
    fn test_identity_add_zero() {
        let rule = RuleIdentityOp;
        let expr = make_expr("LLIL_Add", vec![reg("x0"), imm(0)]);
        let result = rule.apply(&expr);
        assert!(result.is_some());
        assert_eq!(result.unwrap().op, "LLIL_Reg");
    }

    #[test]
    fn test_identity_sub_zero() {
        let rule = RuleIdentityOp;
        let expr = make_expr("LLIL_Sub", vec![reg("x0"), imm(0)]);
        let result = rule.apply(&expr);
        assert!(result.is_some());
    }

    #[test]
    fn test_identity_mul_one() {
        let rule = RuleIdentityOp;
        let expr = make_expr("LLIL_Mul", vec![reg("x1"), imm(1)]);
        let result = rule.apply(&expr);
        assert!(result.is_some());
    }

    #[test]
    fn test_identity_no_match() {
        let rule = RuleIdentityOp;
        let expr = make_expr("LLIL_Add", vec![reg("x0"), imm(42)]);
        let result = rule.apply(&expr);
        assert!(result.is_none());
    }

    #[test]
    fn test_sub_to_add() {
        let rule = RuleSubToAdd;
        let expr = make_expr("LLIL_Sub", vec![reg("x0"), reg("x1")]);
        let result = rule.apply(&expr);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.op, "LLIL_Add");
        // Second operand should be Neg(x1)
        if let PassIlOperand::Expr(neg) = &r.operands[1] {
            assert_eq!(neg.op, "LLIL_Neg");
        } else {
            panic!("expected Neg expr as second operand");
        }
    }

    #[test]
    fn test_double_neg() {
        let rule = RuleDoubleNeg;
        let inner_neg = PassIlOperand::Expr(Box::new(make_expr("LLIL_Neg", vec![reg("x0")])));
        let expr = make_expr("LLIL_Neg", vec![inner_neg]);
        let result = rule.apply(&expr);
        assert!(result.is_some());
    }

    #[test]
    fn test_comparison_fold() {
        let rule = RuleComparisonFold;
        let inner = PassIlOperand::Expr(Box::new(make_expr(
            "LLIL_CmpE",
            vec![reg("x0"), reg("x1")],
        )));
        let expr = make_expr("LLIL_CmpE", vec![inner, imm(0)]);
        let result = rule.apply(&expr);
        assert!(result.is_some());
        assert_eq!(result.unwrap().op, "LLIL_CmpNe");
    }

    #[test]
    fn test_identity_add_zero_on_left() {
        let rule = RuleIdentityOp;
        let expr = make_expr("LLIL_Add", vec![imm(0), reg("x0")]);
        let result = rule.apply(&expr);
        assert!(result.is_some());
    }

    #[test]
    fn test_identity_or_zero() {
        let rule = RuleIdentityOp;
        let expr = make_expr("LLIL_Or", vec![reg("x0"), imm(0)]);
        let result = rule.apply(&expr);
        assert!(result.is_some());
    }

    #[test]
    fn test_identity_xor_zero() {
        let rule = RuleIdentityOp;
        let expr = make_expr("LLIL_Xor", vec![reg("x0"), imm(0)]);
        let result = rule.apply(&expr);
        assert!(result.is_some());
    }
}
