//! Conditional execution pass (Ghidra: ActionConditionalExe).
//!
//! Simplifies conditional execution patterns:
//!   - Detects LLIL_Csel / MLIL_Csel operations (conditional select)
//!   - Folds: if (cond) { x = a } else { x = b } → x = cond ? a : b
//!   - Annotates conditional expressions for downstream passes

use super::pass::{
    Pass, PassContext, PassIlExpr, PassIlExprs, PassIlOperand, PassInfo, PassResult,
};

#[derive(Debug)]
pub struct ConditionalExecutionPass;

impl ConditionalExecutionPass {
    fn is_csel(expr: &PassIlExpr) -> bool {
        expr.op == "LLIL_Csel" || expr.op == "MLIL_Csel"
    }

    fn annotate_csel(expr: &mut PassIlExpr) -> bool {
        let already = expr.extra.iter().any(|(k, _)| k == "cond_expr");
        if already {
            return false;
        }
        expr.extra
            .push(("cond_expr".to_string(), "csel".to_string()));
        if expr.operands.len() >= 3 {
            if let Some(cond_type) = Self::describe_condition(&expr.operands[0]) {
                expr.extra.push(("cond_type".to_string(), cond_type));
            }
        }
        true
    }

    fn describe_condition(cond_op: &PassIlOperand) -> Option<String> {
        match cond_op {
            PassIlOperand::Var(name) => {
                if name.contains("z") {
                    Some("eq".to_string())
                } else if name.contains("c") {
                    Some("cs".to_string())
                } else if name.contains("n") {
                    Some("mi".to_string())
                } else if name.contains("v") {
                    Some("vs".to_string())
                } else {
                    Some(format!("flag({})", name))
                }
            }
            PassIlOperand::Expr(e) => {
                let cond_name = match e.op.as_str() {
                    "LLIL_CmpE" | "MLIL_CmpE" => "eq",
                    "LLIL_CmpNe" | "MLIL_CmpNe" => "ne",
                    "LLIL_CmpSlt" | "MLIL_CmpSle" => "slt",
                    "LLIL_CmpSgt" | "MLIL_CmpSge" => "sgt",
                    "LLIL_CmpUlt" | "MLIL_CmpUle" => "ult",
                    "LLIL_CmpUgt" | "MLIL_CmpUge" => "ugt",
                    _ => return None,
                };
                Some(cond_name.to_string())
            }
            _ => None,
        }
    }

    fn annotate_csel_recursive(expr: &mut PassIlExpr) -> bool {
        let mut changed = false;
        if Self::is_csel(expr) {
            if Self::annotate_csel(expr) {
                changed = true;
            }
        }
        for op in &mut expr.operands {
            if let PassIlOperand::Expr(ref mut child) = op {
                if Self::annotate_csel_recursive(child) {
                    changed = true;
                }
            }
        }
        changed
    }

    fn fold_if_else_patterns(exprs: &mut Vec<PassIlExpr>) -> bool {
        let mut changed = false;
        let mut i = 0;
        while i < exprs.len() {
            let expr = &exprs[i];
            if expr.op == "LLIL_If" || expr.op == "MLIL_If" {
                if expr.operands.len() < 3 {
                    i += 1;
                    continue;
                }
                let cond = expr.operands[0].clone();
                let true_pc = match &expr.operands[1] {
                    PassIlOperand::U64(pc) => *pc,
                    _ => {
                        i += 1;
                        continue;
                    }
                };
                let false_pc = match &expr.operands[2] {
                    PassIlOperand::U64(pc) => *pc,
                    _ => {
                        i += 1;
                        continue;
                    }
                };
                let true_setreg = exprs.iter().position(|e| {
                    e.pc == true_pc
                        && (e.op == "LLIL_SetReg" || e.op == "MLIL_SetVar" || e.op == "HLIL_SetVar")
                });
                let false_setreg = exprs.iter().position(|e| {
                    e.pc == false_pc
                        && (e.op == "LLIL_SetReg" || e.op == "MLIL_SetVar" || e.op == "HLIL_SetVar")
                });
                if let (Some(t_idx), Some(f_idx)) = (true_setreg, false_setreg) {
                    let t_dest = match exprs[t_idx].operands.first() {
                        Some(PassIlOperand::Var(name)) => name.clone(),
                        _ => {
                            i += 1;
                            continue;
                        }
                    };
                    let f_dest = match exprs[f_idx].operands.first() {
                        Some(PassIlOperand::Var(name)) => name.clone(),
                        _ => {
                            i += 1;
                            continue;
                        }
                    };
                    if t_dest == f_dest {
                        let true_val = exprs[t_idx]
                            .operands
                            .get(1)
                            .cloned()
                            .unwrap_or(PassIlOperand::Var(t_dest.clone()));
                        let false_val = exprs[f_idx]
                            .operands
                            .get(1)
                            .cloned()
                            .unwrap_or(PassIlOperand::Var(t_dest.clone()));
                        let csel_expr = PassIlExpr {
                            op: "LLIL_Csel".to_string(),
                            size: exprs[t_idx].size,
                            pc: exprs[i].pc,
                            operands: vec![cond, true_val, false_val],
                            extra: vec![("cond_expr".to_string(), "ifelse_folded".to_string())],
                        };
                        exprs[i] = PassIlExpr {
                            op: "LLIL_SetReg".to_string(),
                            size: exprs[t_idx].size,
                            pc: exprs[i].pc,
                            operands: vec![
                                PassIlOperand::Var(t_dest),
                                PassIlOperand::Expr(Box::new(csel_expr)),
                            ],
                            extra: vec![("cond_expr".to_string(), "ifelse_folded".to_string())],
                        };
                        if t_idx > i {
                            exprs[t_idx]
                                .extra
                                .push(("folded_cond".to_string(), "dead".to_string()));
                        }
                        if f_idx > i {
                            exprs[f_idx]
                                .extra
                                .push(("folded_cond".to_string(), "dead".to_string()));
                        }
                        changed = true;
                    }
                }
            }
            i += 1;
        }
        if changed {
            exprs.retain(|e| {
                !e.extra
                    .iter()
                    .any(|(k, v)| k == "folded_cond" && v == "dead")
            });
        }
        changed
    }
}

impl Pass for ConditionalExecutionPass {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "ConditionalExecution",
            description: "Simplify conditional execution: detect CSEL ops, fold if/else to conditional select",
            phase: 1,
            requires: &[],
            invalidates: &["DeadCodeElim"],
            repeat_until_fixpoint: true,
        }
    }

    fn run(&self, _ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let mut changed = false;
        for e in &mut exprs.exprs {
            if Self::annotate_csel_recursive(e) {
                changed = true;
            }
        }
        if Self::fold_if_else_patterns(&mut exprs.exprs) {
            changed = true;
        }
        if changed {
            PassResult::Changed
        } else {
            PassResult::Unchanged
        }
    }
}

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
    fn make_expr_at(op: &str, operands: Vec<PassIlOperand>, pc: u64) -> PassIlExpr {
        PassIlExpr {
            op: op.to_string(),
            size: 8,
            pc,
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
    fn u64val(v: u64) -> PassIlOperand {
        PassIlOperand::U64(v)
    }

    #[test]
    fn test_annotate_csel() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![make_expr(
            "LLIL_SetReg",
            vec![
                reg("x0#1"),
                PassIlOperand::Expr(Box::new(make_expr(
                    "LLIL_Csel",
                    vec![reg("z"), reg("x1#1"), reg("x2#1")],
                ))),
            ],
        )];
        let pass = ConditionalExecutionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        if let PassIlOperand::Expr(ref csel) = exprs.exprs[0].operands[1] {
            assert!(
                csel.extra.iter().any(|(k, _)| k == "cond_expr"),
                "Csel should have cond_expr"
            );
        } else {
            panic!("expected Csel expr");
        }
    }

    #[test]
    fn test_fold_if_else_to_csel() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr_at(
                "LLIL_If",
                vec![reg("z"), u64val(0x2000), u64val(0x3000)],
                0x1000,
            ),
            make_expr_at("LLIL_SetReg", vec![reg("x0#1"), imm(1)], 0x2000),
            make_expr_at("LLIL_SetReg", vec![reg("x0#1"), imm(0)], 0x3000),
        ];
        let pass = ConditionalExecutionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        assert_eq!(exprs.exprs[0].op, "LLIL_SetReg");
        if let PassIlOperand::Expr(ref csel) = exprs.exprs[0].operands[1] {
            assert_eq!(csel.op, "LLIL_Csel");
        } else {
            panic!("expected Csel in folded result");
        }
    }

    #[test]
    fn test_no_fold_different_dest() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr_at(
                "LLIL_If",
                vec![reg("z"), u64val(0x2000), u64val(0x3000)],
                0x1000,
            ),
            make_expr_at("LLIL_SetReg", vec![reg("x0#1"), imm(1)], 0x2000),
            make_expr_at("LLIL_SetReg", vec![reg("x1#1"), imm(0)], 0x3000),
        ];
        let pass = ConditionalExecutionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(!result.is_changed());
    }

    #[test]
    fn test_no_csel_no_change() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(42)]),
            make_expr("LLIL_Ret", vec![reg("x0#1")]),
        ];
        let pass = ConditionalExecutionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(!result.is_changed());
    }

    #[test]
    fn test_csel_with_compare_condition() {
        let mut exprs = PassIlExprs::new("test", "llil");
        let cmp = PassIlOperand::Expr(Box::new(make_expr(
            "LLIL_CmpE",
            vec![reg("x0#1"), reg("x1#1")],
        )));
        exprs.exprs = vec![make_expr(
            "LLIL_SetReg",
            vec![
                reg("x2#1"),
                PassIlOperand::Expr(Box::new(make_expr(
                    "LLIL_Csel",
                    vec![cmp, reg("x3#1"), reg("x4#1")],
                ))),
            ],
        )];
        let pass = ConditionalExecutionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        if let PassIlOperand::Expr(ref csel) = exprs.exprs[0].operands[1] {
            let has_eq = csel
                .extra
                .iter()
                .any(|(k, v)| k == "cond_type" && v == "eq");
            assert!(
                has_eq,
                "Csel with CmpE should have cond_type=eq, got {:?}",
                csel.extra
            );
        }
    }
}
