//! Switch normalization pass (Ghidra: ActionSwitchNorm).
//!
//! Detects jump table patterns:
//!   ldr reg, [base, idx * scale]
//!   br reg
//!
//! When the actual jump target is known from trace data, simplifies the
//! indirect branch to a direct goto.

use std::collections::BTreeSet;

use super::pass::{
    Pass, PassContext, PassIlExpr, PassIlExprs, PassIlOperand, PassInfo, PassResult,
};

#[derive(Debug, Clone)]
struct JumpTableMatch {
    setreg_idx: usize,
    jump_idx: usize,
    dest_var: String,
    base_reg: String,
    idx_reg: String,
    scale: i64,
}

#[derive(Debug)]
pub struct SwitchNormalizationPass;

impl SwitchNormalizationPass {
    fn parse_jump_table_address(addr_op: &PassIlOperand) -> Option<(String, String, i64)> {
        match addr_op {
            PassIlOperand::Expr(e) => {
                if (e.op == "LLIL_Add" || e.op == "MLIL_Add") && e.operands.len() == 2 {
                    for (base_i, shift_i) in [(0, 1), (1, 0)] {
                        if let Some((idx_reg, scale_log2)) =
                            Self::parse_shift_expr(&e.operands[shift_i])
                        {
                            if let PassIlOperand::Var(base) = &e.operands[base_i] {
                                return Some((base.clone(), idx_reg, 1i64 << scale_log2));
                            }
                        }
                        if let Some((idx_reg, scale)) = Self::parse_mul_expr(&e.operands[shift_i]) {
                            if let PassIlOperand::Var(base) = &e.operands[base_i] {
                                return Some((base.clone(), idx_reg, scale));
                            }
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn parse_shift_expr(op: &PassIlOperand) -> Option<(String, i64)> {
        match op {
            PassIlOperand::Expr(e) => {
                if (e.op == "LLIL_Lsl" || e.op == "MLIL_Lsl") && e.operands.len() == 2 {
                    if let PassIlOperand::Var(idx) = &e.operands[0] {
                        if let PassIlOperand::Imm(shift) = e.operands[1] {
                            return Some((idx.clone(), shift));
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn parse_mul_expr(op: &PassIlOperand) -> Option<(String, i64)> {
        match op {
            PassIlOperand::Expr(e) => {
                if (e.op == "LLIL_Mul" || e.op == "MLIL_Mul") && e.operands.len() == 2 {
                    if let PassIlOperand::Var(idx) = &e.operands[0] {
                        if let PassIlOperand::Imm(scale) = e.operands[1] {
                            return Some((idx.clone(), scale));
                        }
                    }
                    if let PassIlOperand::Imm(scale) = e.operands[0] {
                        if let PassIlOperand::Var(idx) = &e.operands[1] {
                            return Some((idx.clone(), scale));
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn find_jump_tables(exprs: &[PassIlExpr]) -> Vec<JumpTableMatch> {
        let mut matches = Vec::new();
        let mut load_map: Vec<(usize, String, String, String, i64)> = Vec::new();

        for (i, e) in exprs.iter().enumerate() {
            match e.op.as_str() {
                "LLIL_SetReg" | "MLIL_SetVar" | "HLIL_SetVar" => {
                    if e.operands.len() < 2 {
                        continue;
                    }
                    if let PassIlOperand::Var(dest) = &e.operands[0] {
                        if let PassIlOperand::Expr(load) = &e.operands[1] {
                            if load.op == "LLIL_Load"
                                || load.op == "MLIL_Load"
                                || load.op == "HLIL_Load"
                            {
                                if let Some(addr_op) = load.operands.first() {
                                    if let Some((base, idx, scale)) =
                                        Self::parse_jump_table_address(addr_op)
                                    {
                                        load_map.push((i, dest.clone(), base, idx, scale));
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        for (j, e) in exprs.iter().enumerate() {
            if e.op == "LLIL_Jump" || e.op == "MLIL_Jump" {
                if let Some(target_op) = e.operands.first() {
                    if let PassIlOperand::Var(target_var) = target_op {
                        for &(si, ref dest, ref base, ref idx, scale) in &load_map {
                            if dest == target_var {
                                matches.push(JumpTableMatch {
                                    setreg_idx: si,
                                    jump_idx: j,
                                    dest_var: dest.clone(),
                                    base_reg: base.clone(),
                                    idx_reg: idx.clone(),
                                    scale,
                                });
                            }
                        }
                    }
                }
            }
        }
        matches
    }

    fn collect_uses_from(exprs: &[PassIlExpr], from_idx: usize) -> BTreeSet<String> {
        let mut uses = BTreeSet::new();
        for e in &exprs[from_idx..] {
            Self::collect_uses_in_expr(e, &mut uses);
        }
        uses
    }

    fn collect_uses_in_expr(expr: &PassIlExpr, uses: &mut BTreeSet<String>) {
        for op in &expr.operands {
            Self::collect_uses_in_operand(op, uses);
        }
    }

    fn collect_uses_in_operand(op: &PassIlOperand, uses: &mut BTreeSet<String>) {
        match op {
            PassIlOperand::Var(name) => {
                uses.insert(name.clone());
            }
            PassIlOperand::Expr(e) => {
                Self::collect_uses_in_expr(e, uses);
            }
            _ => {}
        }
    }
}

impl Pass for SwitchNormalizationPass {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "SwitchNormalization",
            description:
                "Detect jump table patterns and normalize to direct goto when trace target is known",
            phase: 2,
            requires: &[],
            invalidates: &["DeadCodeElim"],
            repeat_until_fixpoint: false,
        }
    }

    fn run(&self, _ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let tables = Self::find_jump_tables(&exprs.exprs);
        if tables.is_empty() {
            return PassResult::Unchanged;
        }

        let mut changed = false;
        for m in &tables {
            let jump = &mut exprs.exprs[m.jump_idx];
            let already = jump.extra.iter().any(|(k, _)| k == "switch_base");
            if !already {
                jump.extra
                    .push(("switch_base".to_string(), m.base_reg.clone()));
                jump.extra
                    .push(("switch_index".to_string(), m.idx_reg.clone()));
                jump.extra
                    .push(("switch_scale".to_string(), format!("{}", m.scale)));
                jump.extra
                    .push(("switch_kind".to_string(), "jumptable".to_string()));
                changed = true;
            }

            let trace_target = jump
                .extra
                .iter()
                .find(|(k, _)| k == "trace_target")
                .map(|(_, v)| v.clone());

            if let Some(target_str) = trace_target {
                if let Ok(target_pc) = u64::from_str_radix(target_str.trim_start_matches("0x"), 16)
                {
                    let old_pc = jump.pc;
                    let e = jump;
                    *e = PassIlExpr {
                        op: e.op.replace("Jump", "Goto"),
                        size: e.size,
                        pc: old_pc,
                        operands: vec![PassIlOperand::U64(target_pc)],
                        extra: e.extra.clone(),
                    };
                    changed = true;

                    if m.setreg_idx < m.jump_idx {
                        let dest_used_after = {
                            let uses = Self::collect_uses_from(&exprs.exprs, m.jump_idx + 1);
                            uses.contains(&m.dest_var)
                        };
                        if !dest_used_after {
                            exprs.exprs[m.setreg_idx]
                                .extra
                                .push(("switch_dead_load".to_string(), "true".to_string()));
                            changed = true;
                        }
                    }
                }
            }
        }

        if changed {
            exprs.exprs.retain(|e| {
                !e.extra
                    .iter()
                    .any(|(k, v)| k == "switch_dead_load" && v == "true")
            });
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
    fn imm(v: i64) -> PassIlOperand {
        PassIlOperand::Imm(v)
    }
    fn reg(name: &str) -> PassIlOperand {
        PassIlOperand::Var(name.to_string())
    }

    #[test]
    fn test_detect_jump_table_pattern() {
        let load_addr = PassIlOperand::Expr(Box::new(make_expr(
            "LLIL_Add",
            vec![
                reg("x1"),
                PassIlOperand::Expr(Box::new(make_expr("LLIL_Lsl", vec![reg("x2#1"), imm(3)]))),
            ],
        )));
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr(
                "LLIL_SetReg",
                vec![
                    reg("x3#1"),
                    PassIlOperand::Expr(Box::new(make_expr("LLIL_Load", vec![load_addr]))),
                ],
            ),
            make_expr("LLIL_Jump", vec![reg("x3#1")]),
        ];
        let pass = SwitchNormalizationPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 2,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        let jump = &exprs.exprs[1];
        assert!(jump.extra.iter().any(|(k, _)| k == "switch_base"));
        assert!(jump.extra.iter().any(|(k, _)| k == "switch_index"));
        assert!(jump
            .extra
            .iter()
            .any(|(k, v)| k == "switch_kind" && v == "jumptable"));
    }

    #[test]
    fn test_detect_with_trace_target_simplifies_to_goto() {
        let load_addr = PassIlOperand::Expr(Box::new(make_expr(
            "LLIL_Add",
            vec![
                reg("x1"),
                PassIlOperand::Expr(Box::new(make_expr("LLIL_Lsl", vec![reg("x2#1"), imm(3)]))),
            ],
        )));
        let mut exprs = PassIlExprs::new("test", "llil");
        let mut jump = make_expr("LLIL_Jump", vec![reg("x3#1")]);
        jump.extra
            .push(("trace_target".to_string(), "0x4000".to_string()));
        exprs.exprs = vec![
            make_expr(
                "LLIL_SetReg",
                vec![
                    reg("x3#1"),
                    PassIlOperand::Expr(Box::new(make_expr("LLIL_Load", vec![load_addr]))),
                ],
            ),
            jump,
        ];
        let pass = SwitchNormalizationPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 2,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        assert_eq!(exprs.exprs[0].op, "LLIL_Goto");
        assert!(matches!(
            exprs.exprs[0].operands[0],
            PassIlOperand::U64(0x4000)
        ));
    }

    #[test]
    fn test_no_jump_table_no_change() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(42)]),
            make_expr("LLIL_Ret", vec![reg("x0#1")]),
        ];
        let pass = SwitchNormalizationPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 2,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(!result.is_changed());
    }

    #[test]
    fn test_detect_mul_pattern() {
        let load_addr = PassIlOperand::Expr(Box::new(make_expr(
            "LLIL_Add",
            vec![
                reg("x1"),
                PassIlOperand::Expr(Box::new(make_expr("LLIL_Mul", vec![reg("x2#1"), imm(8)]))),
            ],
        )));
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr(
                "LLIL_SetReg",
                vec![
                    reg("x3#1"),
                    PassIlOperand::Expr(Box::new(make_expr("LLIL_Load", vec![load_addr]))),
                ],
            ),
            make_expr("LLIL_Jump", vec![reg("x3#1")]),
        ];
        let pass = SwitchNormalizationPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 2,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        let jump = &exprs.exprs[1];
        assert!(jump
            .extra
            .iter()
            .any(|(k, v)| k == "switch_scale" && v == "8"));
    }

    #[test]
    fn test_find_jump_tables_basic() {
        let load_addr = PassIlOperand::Expr(Box::new(make_expr(
            "LLIL_Add",
            vec![
                reg("x1"),
                PassIlOperand::Expr(Box::new(make_expr("LLIL_Lsl", vec![reg("x2#1"), imm(3)]))),
            ],
        )));
        let exprs = vec![
            make_expr(
                "LLIL_SetReg",
                vec![
                    reg("x3#1"),
                    PassIlOperand::Expr(Box::new(make_expr("LLIL_Load", vec![load_addr]))),
                ],
            ),
            make_expr("LLIL_Jump", vec![reg("x3#1")]),
        ];
        let tables = SwitchNormalizationPass::find_jump_tables(&exprs);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].base_reg, "x1");
        assert_eq!(tables[0].idx_reg, "x2#1");
        assert_eq!(tables[0].scale, 8);
    }
}
