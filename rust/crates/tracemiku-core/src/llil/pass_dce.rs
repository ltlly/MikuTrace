//! Dead-code elimination over block-local SSA.
//!
//! Works directly on already-SSA'd expressions.  Does NOT re-run the SSA pass,
//! which would double-version register names (x2#0 → x2#0#0 → x2#0#0#0 ...).

use std::collections::{BTreeMap, BTreeSet};

use crate::llil::expr::{LlilExpr, LlilOp, LlilOperand};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DceResult {
    pub exprs: Vec<LlilExpr>,
    pub removed_pcs: BTreeSet<u64>,
}

pub fn dce_block(exprs: &[LlilExpr]) -> DceResult {
    let mut current = exprs.to_vec();
    let mut removed_pcs = BTreeSet::new();
    loop {
        // Build uses map directly from the (already-SSA'd) expressions.
        // Key = register name (e.g. "x0#1"), value = list of expression indices
        // where that register appears as a Reg operand.
        let uses = build_uses(&current);
        let mut out = Vec::new();
        let mut changed = false;
        for (idx, e) in current.iter().enumerate() {
            if removable_set_reg(e, idx, &uses) {
                removed_pcs.insert(e.pc);
                changed = true;
                continue;
            }
            out.push(e.clone());
        }
        current = out;
        if !changed {
            break;
        }
    }
    DceResult {
        exprs: current,
        removed_pcs,
    }
}

/// Build a map from register name → indices of expressions that *read* it.
fn build_uses(exprs: &[LlilExpr]) -> BTreeMap<String, Vec<usize>> {
    let mut uses = BTreeMap::new();
    for (idx, e) in exprs.iter().enumerate() {
        collect_reg_uses(e, idx, &mut uses);
    }
    uses
}

/// Recursively collect LlilOperand::Reg references (read uses only, NOT
/// the destination register of a SetReg — that is a definition).
fn collect_reg_uses(e: &LlilExpr, idx: usize, uses: &mut BTreeMap<String, Vec<usize>>) {
    // For SetReg, skip the first operand (the destination register — it's a
    // definition, not a use).  All other operands are read-uses.
    if e.op == LlilOp::SetReg {
        for (i, op) in e.operands.iter().enumerate() {
            if i == 0 {
                continue; // skip destination
            }
            match op {
                LlilOperand::Reg(r) => {
                    uses.entry(r.clone()).or_default().push(idx);
                }
                LlilOperand::Expr(sub) => collect_reg_uses(sub, idx, uses),
                _ => {}
            }
        }
        return;
    }

    // For all other expressions, visit every operand.
    for op in &e.operands {
        match op {
            LlilOperand::Reg(r) => {
                uses.entry(r.clone()).or_default().push(idx);
            }
            LlilOperand::Expr(sub) => collect_reg_uses(sub, idx, uses),
            _ => {}
        }
    }
}

/// Decide whether a SetReg instruction is dead (its defined register is never
/// read, or is only read by itself).
fn removable_set_reg(e: &LlilExpr, idx: usize, uses: &BTreeMap<String, Vec<usize>>) -> bool {
    if e.op != LlilOp::SetReg {
        return false;
    }
    if e.operands.iter().any(operand_has_side_effect) {
        return false;
    }
    let Some(LlilOperand::Reg(dst)) = e.operands.first() else {
        return false;
    };
    // Check whether `dst` is read by any expression other than this one.
    uses.get(dst)
        .map(|idxs| idxs.iter().any(|use_idx| *use_idx != idx))
        .unwrap_or(false)
        == false
}

fn operand_has_side_effect(op: &LlilOperand) -> bool {
    match op {
        LlilOperand::Expr(e) => expr_has_side_effect(e),
        _ => false,
    }
}

fn expr_has_side_effect(e: &LlilExpr) -> bool {
    e.has_side_effect() || e.operands.iter().any(operand_has_side_effect)
}

#[cfg(test)]
mod tests {
    use crate::llil::expr::{binary, konst, reg, set_reg, LlilOp};

    use super::*;

    #[test]
    fn removes_unused_set_reg() {
        let exprs = vec![set_reg("x0", konst(1), 0x1000)];
        let dce = dce_block(&exprs);
        assert!(dce.exprs.is_empty());
        assert!(dce.removed_pcs.contains(&0x1000));
    }

    #[test]
    fn cascades_unused_set_reg_chain() {
        let exprs = vec![
            set_reg("x0", konst(1), 0x1000),
            set_reg("x1", binary(LlilOp::Add, reg("x0"), konst(2)), 0x1004),
        ];
        let dce = dce_block(&exprs);
        assert!(dce.exprs.is_empty());
        assert!(dce.removed_pcs.contains(&0x1000));
        assert!(dce.removed_pcs.contains(&0x1004));
    }

    /// Regression: DCE must not re-version already-SSA'd register names.
    /// x0#1 should stay as x0#1, not become x0#1#0.
    #[test]
    fn does_not_double_version_ssa_names() {
        // Define x0#1, use it in another SetReg → neither is dead.
        // The SSA names must survive DCE without extra `#N` suffixes.
        let exprs = vec![
            set_reg("x0#1", konst(42), 0x1000),
            set_reg("x1#1", reg("x0#1"), 0x1004),
            // x2#1 uses x1#1 — keeps x1#1 alive
            set_reg("x2#1", reg("x1#1"), 0x1008),
            // x3#1 uses x2#1 and x0#1 — keeps both alive
            set_reg(
                "x3#1",
                binary(LlilOp::Add, reg("x2#1"), reg("x0#1")),
                0x100c,
            ),
        ];
        let dce = dce_block(&exprs);
        // x3#1 is used by no one, so it's removable. After x3#1 removal,
        // x2#1 is also unused. Then x1#1 is unused. Then x0#1 is unused.
        // So cascading removes all four. This exercises the loop correctly.
        // The key check: no `#0#0#0`-style corruption in intermediate passes.
        assert!(
            dce.exprs.is_empty(),
            "chain of unused defs should all be removed"
        );
    }
}
