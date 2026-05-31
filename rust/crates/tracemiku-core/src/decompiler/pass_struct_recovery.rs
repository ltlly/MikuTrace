//! Struct field access recovery pass.
//!
//! Detects repeated offset-based Load/Store patterns from the same base
//! register and annotates them as struct field accesses.

use std::collections::{BTreeMap, BTreeSet};

use super::pass::{
    Pass, PassContext, PassIlExpr, PassIlExprs, PassIlOperand, PassInfo, PassResult,
};

/// Detected struct access pattern: base register + field offset.
#[derive(Debug, Clone)]
struct StructAccess {
    base_reg: String,
    offset: i64,
    /// Expression index in the list.
    expr_index: usize,
    /// "load" or "store"
    kind: String,
    /// Size in bytes.
    size: u8,
}

/// Struct recovery pass.
///
/// Scans Load/Store expressions for base+offset address patterns.
/// When the same base register is used with ≥2 different offsets,
/// annotates those expressions with struct field metadata.
#[derive(Debug)]
pub struct StructRecoveryPass;

impl StructRecoveryPass {
    /// Parse a base+offset pattern from an address operand.
    /// Returns (base_register_name, offset) if the address is base_reg + const.
    fn parse_base_offset(addr_op: &PassIlOperand) -> Option<(String, i64)> {
        match addr_op {
            PassIlOperand::Expr(e) => {
                // Match: Add(base_reg, const)  or  Add(const, base_reg)
                if (e.op == "LLIL_Add" || e.op == "MLIL_Add") && e.operands.len() == 2 {
                    if let PassIlOperand::Var(base) = &e.operands[0] {
                        if let PassIlOperand::Imm(off) = e.operands[1] {
                            return Some((base.clone(), off));
                        }
                    }
                    if let PassIlOperand::Var(base) = &e.operands[1] {
                        if let PassIlOperand::Imm(off) = e.operands[0] {
                            return Some((base.clone(), off));
                        }
                    }
                }
                // Match: ConstPtr(addr) — absolute address (no base reg, skip)
                None
            }
            PassIlOperand::U64(_addr) => {
                // Absolute address, not base+offset
                None
            }
            PassIlOperand::Var(base) => {
                // Direct register load: Load(x0) → base=x0, offset=0
                Some((base.clone(), 0))
            }
            _ => None,
        }
    }

    /// Find all struct-eligible accesses in the expression list.
    fn find_accesses(exprs: &[PassIlExpr]) -> Vec<StructAccess> {
        let mut accesses = Vec::new();
        for (idx, e) in exprs.iter().enumerate() {
            match e.op.as_str() {
                "LLIL_Load" | "MLIL_Load" => {
                    if let Some(addr_op) = e.operands.first() {
                        if let Some((base, offset)) = Self::parse_base_offset(addr_op) {
                            accesses.push(StructAccess {
                                base_reg: base,
                                offset,
                                expr_index: idx,
                                kind: "load".to_string(),
                                size: e.size,
                            });
                        }
                    }
                }
                "LLIL_Store" | "MLIL_Store" => {
                    if e.operands.len() >= 2 {
                        if let Some((base, offset)) = Self::parse_base_offset(&e.operands[0]) {
                            accesses.push(StructAccess {
                                base_reg: base,
                                offset,
                                expr_index: idx,
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
}

impl Pass for StructRecoveryPass {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "StructRecovery",
            description:
                "Detect repeated offset-based Load/Store patterns as struct field accesses",
            phase: 1,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }

    fn run(&self, _ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let accesses = Self::find_accesses(&exprs.exprs);
        if accesses.is_empty() {
            return PassResult::Unchanged;
        }

        // Group accesses by base register
        let mut by_base: BTreeMap<String, Vec<&StructAccess>> = BTreeMap::new();
        for a in &accesses {
            by_base.entry(a.base_reg.clone()).or_default().push(a);
        }

        let mut changed = false;

        // For bases with ≥2 distinct offsets, annotate as struct fields
        for (_base_reg, group) in &by_base {
            // Collect distinct offsets
            let offsets: BTreeSet<i64> = group.iter().map(|a| a.offset).collect();
            if offsets.len() < 2 {
                continue;
            }

            for access in group {
                let e = &mut exprs.exprs[access.expr_index];
                let field_name = format!("field_{:x}", access.offset);
                let field_type = match access.size {
                    1 => "uint8_t",
                    2 => "uint16_t",
                    4 => "uint32_t",
                    8 => "uint64_t",
                    _ => "uint8_t",
                };
                // Add struct field metadata as extra key-value pairs
                e.extra
                    .push(("struct_base".to_string(), access.base_reg.clone()));
                e.extra.push(("struct_field".to_string(), field_name));
                e.extra.push((
                    "struct_offset".to_string(),
                    format!("0x{:x}", access.offset),
                ));
                e.extra
                    .push(("struct_field_type".to_string(), field_type.to_string()));
                e.extra
                    .push(("access_kind".to_string(), access.kind.clone()));
                changed = true;
            }
        }

        if changed {
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
    fn test_detect_struct_fields() {
        // Load(x0 + 0)
        // Load(x0 + 8)
        // Load(x0 + 16)
        let mut exprs = PassIlExprs::new("test", "llil");
        let base_offset = |off: i64| -> PassIlOperand {
            PassIlOperand::Expr(Box::new(make_expr("LLIL_Add", vec![reg("x0"), imm(off)])))
        };
        exprs.exprs = vec![
            make_expr("LLIL_Load", vec![base_offset(0)]),
            make_expr("LLIL_Load", vec![base_offset(8)]),
            make_expr("LLIL_Load", vec![base_offset(16)]),
        ];

        let pass = StructRecoveryPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());

        // All three should have struct metadata
        for e in &exprs.exprs {
            let has_base = e.extra.iter().any(|(k, _)| k == "struct_base");
            let has_field = e.extra.iter().any(|(k, _)| k == "struct_field");
            assert!(has_base, "missing struct_base");
            assert!(has_field, "missing struct_field");
        }
    }

    #[test]
    fn test_single_offset_no_struct() {
        // Only one access from x0 → no struct
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![make_expr(
            "LLIL_Load",
            vec![PassIlOperand::Expr(Box::new(make_expr(
                "LLIL_Add",
                vec![reg("x0"), imm(0)],
            )))],
        )];

        let pass = StructRecoveryPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(!result.is_changed());
        assert!(exprs.exprs[0].extra.is_empty());
    }

    #[test]
    fn test_no_load_store() {
        // No Load/Store at all
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![make_expr("LLIL_Add", vec![reg("x0"), imm(5)])];

        let pass = StructRecoveryPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(!result.is_changed());
    }

    #[test]
    fn test_store_struct_fields() {
        // Store(x0+0, val1)
        // Store(x0+8, val2)
        let mut exprs = PassIlExprs::new("test", "llil");
        let base_offset = |off: i64| -> PassIlOperand {
            PassIlOperand::Expr(Box::new(make_expr("LLIL_Add", vec![reg("x0"), imm(off)])))
        };
        exprs.exprs = vec![
            make_expr("LLIL_Store", vec![base_offset(0), imm(42)]),
            make_expr("LLIL_Store", vec![base_offset(8), imm(99)]),
        ];

        let pass = StructRecoveryPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());

        for e in &exprs.exprs {
            assert!(e.extra.iter().any(|(k, _)| k == "access_kind"));
            assert!(e
                .extra
                .iter()
                .any(|(k, v)| k == "access_kind" && v == "store"));
        }
    }

    #[test]
    fn test_different_bases() {
        // Load(x0 + 0)
        // Load(x1 + 0)
        // Each base has only one access → no struct detected
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr(
                "LLIL_Load",
                vec![PassIlOperand::Expr(Box::new(make_expr(
                    "LLIL_Add",
                    vec![reg("x0"), imm(0)],
                )))],
            ),
            make_expr(
                "LLIL_Load",
                vec![PassIlOperand::Expr(Box::new(make_expr(
                    "LLIL_Add",
                    vec![reg("x1"), imm(0)],
                )))],
            ),
        ];

        let pass = StructRecoveryPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 1,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(!result.is_changed());
    }
}
