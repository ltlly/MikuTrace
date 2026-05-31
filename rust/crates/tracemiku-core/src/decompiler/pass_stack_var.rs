//! Stack variable recovery pass (Ghidra: ActionStackPtrFlow).
//!
//! Tracks sp/fp-relative memory accesses and identifies stack variables:
//!   - *(sp + offset) → stack variable at offset
//!   - *(fp - offset) → local variable / saved register slot
//!
//! Groups accesses by offset, assigns named slots (var_0, var_8, ...),
//! and generates variable declarations at the function start.

use std::collections::{BTreeMap, BTreeSet};

use super::pass::{
    Pass, PassContext, PassIlExpr, PassIlExprs, PassIlOperand, PassInfo, PassResult,
};

#[derive(Debug, Clone)]
struct StackAccess {
    expr_index: usize,
    offset: i64,
    kind: String,
    size: u8,
}

#[derive(Debug)]
pub struct StackVariableRecoveryPass;

impl StackVariableRecoveryPass {
    fn is_stack_reg(name: &str) -> bool {
        let base = name.split('#').next().unwrap_or(name);
        matches!(
            base,
            "sp" | "xsp" | "wsp" | "fp" | "x29" | "w29" | "x31" | "w31" | "lr" | "x30"
        )
    }

    fn parse_stack_address(addr_op: &PassIlOperand) -> Option<(String, i64)> {
        match addr_op {
            PassIlOperand::Var(name) => {
                if Self::is_stack_reg(name) {
                    Some((name.clone(), 0))
                } else {
                    None
                }
            }
            PassIlOperand::Expr(e) => {
                if (e.op == "LLIL_Add" || e.op == "MLIL_Add") && e.operands.len() == 2 {
                    for (base_i, off_i) in [(0usize, 1usize), (1, 0)] {
                        if let PassIlOperand::Var(base) = &e.operands[base_i] {
                            if Self::is_stack_reg(base) {
                                if let PassIlOperand::Imm(off) = e.operands[off_i] {
                                    return Some((base.clone(), off));
                                }
                                if let PassIlOperand::U64(off) = e.operands[off_i] {
                                    return Some((base.clone(), off as i64));
                                }
                            }
                        }
                    }
                }
                if (e.op == "LLIL_Sub" || e.op == "MLIL_Sub") && e.operands.len() == 2 {
                    if let PassIlOperand::Var(base) = &e.operands[0] {
                        if Self::is_stack_reg(base) {
                            if let PassIlOperand::Imm(off) = e.operands[1] {
                                return Some((base.clone(), -off));
                            }
                            if let PassIlOperand::U64(off) = e.operands[1] {
                                return Some((base.clone(), -(off as i64)));
                            }
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn find_stack_accesses(exprs: &[PassIlExpr]) -> Vec<StackAccess> {
        let mut accesses = Vec::new();
        for (idx, e) in exprs.iter().enumerate() {
            match e.op.as_str() {
                "LLIL_Load" | "MLIL_Load" | "HLIL_Load" => {
                    if let Some(addr_op) = e.operands.first() {
                        if let Some((_base, offset)) = Self::parse_stack_address(addr_op) {
                            accesses.push(StackAccess {
                                expr_index: idx,
                                offset,
                                kind: "load".to_string(),
                                size: e.size,
                            });
                        }
                    }
                }
                "LLIL_Store" | "MLIL_Store" | "HLIL_Store" => {
                    if e.operands.len() >= 2 {
                        if let Some((_base, offset)) = Self::parse_stack_address(&e.operands[0]) {
                            accesses.push(StackAccess {
                                expr_index: idx,
                                offset,
                                kind: "store".to_string(),
                                size: e.size,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        accesses
    }

    fn var_name(offset: i64) -> String {
        if offset >= 0 {
            format!("var_{:x}", offset)
        } else {
            format!("var_m{:x}", -offset)
        }
    }

    /// Heuristic-based auto-naming: produces a semantically meaningful name
    /// based on stack slot usage patterns (size, read/write ratio, context).
    fn auto_name(offset: i64, group: &[&StackAccess]) -> String {
        let total = group.len();
        let reads = group.iter().filter(|a| a.kind == "load").count();
        let writes = group.iter().filter(|a| a.kind == "store").count();
        let max_size = group.iter().map(|a| a.size).max().unwrap_or(8);
        // Call-target heuristic: slot is only read at 8 bytes → fn ptr candidate
        if max_size == 8 && writes == 0 && reads > 0 && reads == total {
            return format!(
                "fn_ptr_{:x}",
                if offset >= 0 {
                    offset as u64
                } else {
                    (-offset) as u64
                }
            );
        }
        // Write-only of 8 bytes → saved register slot
        if max_size == 8 && reads == 0 && writes > 0 {
            return format!(
                "saved_{:x}",
                if offset >= 0 {
                    offset as u64
                } else {
                    (-offset) as u64
                }
            );
        }
        // Small read-write (1-4 bytes) → data field
        if max_size <= 4 && reads > 0 && writes > 0 {
            return format!(
                "field_{:x}",
                if offset >= 0 {
                    offset as u64
                } else {
                    (-offset) as u64
                }
            );
        }
        // 8-byte read-write → pointer/ref
        if max_size == 8 && reads > 0 && writes > 0 {
            return format!(
                "ptr_{:x}",
                if offset >= 0 {
                    offset as u64
                } else {
                    (-offset) as u64
                }
            );
        }
        Self::var_name(offset)
    }

    fn insert_declarations(
        exprs: &mut Vec<PassIlExpr>,
        offsets: &BTreeSet<i64>,
        base_reg: &str,
        offset_names: &BTreeMap<i64, String>,
    ) {
        let mut decls: Vec<PassIlExpr> = offsets
            .iter()
            .map(|&off| {
                let var = offset_names
                    .get(&off)
                    .cloned()
                    .unwrap_or_else(|| Self::var_name(off));
                let addr_op = if off >= 0 {
                    PassIlOperand::Expr(Box::new(PassIlExpr {
                        op: "LLIL_Add".to_string(),
                        size: 8,
                        pc: 0,
                        operands: vec![
                            PassIlOperand::Var(base_reg.to_string()),
                            PassIlOperand::Imm(off),
                        ],
                        extra: vec![],
                    }))
                } else {
                    PassIlOperand::Expr(Box::new(PassIlExpr {
                        op: "LLIL_Sub".to_string(),
                        size: 8,
                        pc: 0,
                        operands: vec![
                            PassIlOperand::Var(base_reg.to_string()),
                            PassIlOperand::Imm(-off),
                        ],
                        extra: vec![],
                    }))
                };
                PassIlExpr {
                    op: "LLIL_SetReg".to_string(),
                    size: 8,
                    pc: 0,
                    operands: vec![
                        PassIlOperand::Var(var.clone()),
                        PassIlOperand::Expr(Box::new(PassIlExpr {
                            op: "LLIL_Load".to_string(),
                            size: 8,
                            pc: 0,
                            operands: vec![addr_op],
                            extra: vec![("stack_var".to_string(), var.clone())],
                        })),
                    ],
                    extra: vec![
                        ("stack_decl".to_string(), var.clone()),
                        ("stack_offset".to_string(), format!("0x{:x}", off)),
                    ],
                }
            })
            .collect();

        let mut new_exprs = Vec::with_capacity(decls.len() + exprs.len());
        new_exprs.append(&mut decls);
        new_exprs.append(exprs);
        *exprs = new_exprs;
    }
}

impl Pass for StackVariableRecoveryPass {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "StackVariableRecovery",
            description: "Track sp/fp-relative accesses and identify named stack variable slots",
            phase: 1,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }

    fn run(&self, _ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let accesses = Self::find_stack_accesses(&exprs.exprs);
        if accesses.is_empty() {
            return PassResult::Unchanged;
        }

        let mut by_offset: BTreeMap<i64, Vec<&StackAccess>> = BTreeMap::new();
        for a in &accesses {
            by_offset.entry(a.offset).or_default().push(a);
        }

        let mut changed = false;
        let mut base_reg = "sp".to_string();
        let mut base_counts: BTreeMap<String, usize> = BTreeMap::new();
        for a in &accesses {
            let addr_idx = 0;
            if let Some(e) = exprs.exprs.get(a.expr_index) {
                if let Some(addr) = e.operands.get(addr_idx) {
                    if let Some((base, _)) = Self::parse_stack_address(addr) {
                        let b = base.split('#').next().unwrap_or(&base).to_string();
                        *base_counts.entry(b).or_insert(0) += 1;
                    }
                }
            }
        }
        if let Some((base, _)) = base_counts.into_iter().max_by_key(|(_, c)| *c) {
            base_reg = base;
        }

        // Compute names first so decls and annotations are consistent
        let mut offset_names: BTreeMap<i64, String> = BTreeMap::new();
        for (&offset, group) in &by_offset {
            offset_names.insert(offset, Self::auto_name(offset, group));
        }

        for (&offset, group) in &by_offset {
            let var_name = offset_names
                .get(&offset)
                .cloned()
                .unwrap_or_else(|| Self::var_name(offset));
            for access in group {
                let e = &mut exprs.exprs[access.expr_index];
                let already = e
                    .extra
                    .iter()
                    .any(|(k, v)| k == "stack_var" && v == &var_name);
                if !already {
                    e.extra.push(("stack_var".to_string(), var_name.clone()));
                    e.extra
                        .push(("stack_offset".to_string(), format!("0x{:x}", offset)));
                    e.extra.push(("stack_base".to_string(), base_reg.clone()));
                    e.extra
                        .push(("stack_kind".to_string(), access.kind.clone()));
                    e.extra
                        .push(("stack_size".to_string(), format!("{}", access.size)));
                    changed = true;
                }
            }
        }

        let offsets: BTreeSet<i64> = by_offset.keys().copied().collect();
        let has_existing_decls = exprs
            .exprs
            .iter()
            .any(|e| e.extra.iter().any(|(k, _)| k == "stack_decl"));
        if !has_existing_decls && !offsets.is_empty() {
            Self::insert_declarations(&mut exprs.exprs, &offsets, &base_reg, &offset_names);
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
    fn imm(v: i64) -> PassIlOperand {
        PassIlOperand::Imm(v)
    }
    fn reg(name: &str) -> PassIlOperand {
        PassIlOperand::Var(name.to_string())
    }
    fn sp_offset(off: i64) -> PassIlOperand {
        PassIlOperand::Expr(Box::new(make_expr("LLIL_Add", vec![reg("sp"), imm(off)])))
    }

    #[test]
    fn test_detect_sp_relative_load() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![make_expr("LLIL_Load", vec![sp_offset(0x10)])];
        let pass = StackVariableRecoveryPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let _ = pass.run(&ctx, &mut exprs);
        let has_var = exprs.exprs.iter().any(|e| {
            e.extra
                .iter()
                .any(|(k, v)| k == "stack_var" && v == "fn_ptr_10")
        });
        assert!(has_var, "should find fn_ptr_10 annotation");
    }

    #[test]
    fn test_detect_sp_relative_store() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![make_expr("LLIL_Store", vec![sp_offset(8), imm(42)])];
        let pass = StackVariableRecoveryPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let _ = pass.run(&ctx, &mut exprs);
        let has_var = exprs.exprs.iter().any(|e| {
            e.extra
                .iter()
                .any(|(k, v)| k == "stack_var" && v == "saved_8")
        });
        let has_store = exprs.exprs.iter().any(|e| {
            e.extra
                .iter()
                .any(|(k, v)| k == "stack_kind" && v == "store")
        });
        assert!(has_var, "should find saved_8 annotation");
        assert!(has_store, "should find store annotation");
    }

    #[test]
    fn test_group_multiple_accesses() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_Load", vec![sp_offset(0)]),
            make_expr("LLIL_Store", vec![sp_offset(8), imm(1)]),
            make_expr("LLIL_Load", vec![sp_offset(0)]),
        ];
        let pass = StackVariableRecoveryPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let _ = pass.run(&ctx, &mut exprs);
        let has_var0 = exprs.exprs.iter().any(|e| {
            e.extra
                .iter()
                .any(|(k, v)| k == "stack_var" && v == "fn_ptr_0")
        });
        let has_var8 = exprs.exprs.iter().any(|e| {
            e.extra
                .iter()
                .any(|(k, v)| k == "stack_var" && v == "saved_8")
        });
        assert!(has_var0, "should have fn_ptr_0 annotation");
        assert!(has_var8, "should have saved_8 annotation");
    }

    #[test]
    fn test_no_stack_access_no_change() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(42)]),
            make_expr("LLIL_Ret", vec![reg("x0#1")]),
        ];
        let pass = StackVariableRecoveryPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(!result.is_changed());
    }

    #[test]
    fn test_is_stack_reg() {
        assert!(StackVariableRecoveryPass::is_stack_reg("sp"));
        assert!(StackVariableRecoveryPass::is_stack_reg("fp"));
        assert!(StackVariableRecoveryPass::is_stack_reg("x29"));
        assert!(StackVariableRecoveryPass::is_stack_reg("lr"));
        assert!(StackVariableRecoveryPass::is_stack_reg("sp#1"));
        assert!(StackVariableRecoveryPass::is_stack_reg("fp#3"));
        assert!(!StackVariableRecoveryPass::is_stack_reg("x0"));
    }

    #[test]
    fn test_var_name_generation() {
        assert_eq!(StackVariableRecoveryPass::var_name(0), "var_0");
        assert_eq!(StackVariableRecoveryPass::var_name(0x10), "var_10");
        assert_eq!(StackVariableRecoveryPass::var_name(-8), "var_m8");
    }

    #[test]
    fn test_declarations_inserted() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_Load", vec![sp_offset(0x10)]),
            make_expr("LLIL_Store", vec![sp_offset(0x20), imm(42)]),
            make_expr("LLIL_Ret", vec![reg("x0#1")]),
        ];
        let pass = StackVariableRecoveryPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        let decl_count = exprs
            .exprs
            .iter()
            .filter(|e| e.extra.iter().any(|(k, _)| k == "stack_decl"))
            .count();
        assert!(
            decl_count >= 2,
            "should have at least 2 declarations, got {}",
            decl_count
        );
    }
}
