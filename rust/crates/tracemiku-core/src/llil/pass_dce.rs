//! Dead-code elimination over block-local SSA.

use std::collections::BTreeSet;

use crate::llil::expr::{LlilExpr, LlilOp, LlilOperand};
use crate::llil::ssa::{ssa_block, SsaVar};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DceResult {
    pub exprs: Vec<LlilExpr>,
    pub removed_pcs: BTreeSet<u64>,
}

pub fn dce_block(exprs: &[LlilExpr]) -> DceResult {
    let mut current = exprs.to_vec();
    let mut removed_pcs = BTreeSet::new();
    loop {
        let ssa = ssa_block(&current);
        let mut out = Vec::new();
        let mut changed = false;
        for (idx, e) in ssa.exprs.iter().enumerate() {
            if removable_set_reg(e, idx, &ssa.uses) {
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

fn removable_set_reg(
    e: &LlilExpr,
    idx: usize,
    uses: &std::collections::BTreeMap<SsaVar, Vec<usize>>,
) -> bool {
    if e.op != LlilOp::SetReg {
        return false;
    }
    if e.operands.iter().any(operand_has_side_effect) {
        return false;
    }
    let Some(LlilOperand::Reg(dst)) = e.operands.first() else {
        return false;
    };
    let Some((name, version)) = parse_ssa_reg(dst) else {
        return false;
    };
    let var = SsaVar { name, version };
    uses.get(&var)
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

fn parse_ssa_reg(s: &str) -> Option<(String, u32)> {
    let (name, ver) = s.rsplit_once('#')?;
    Some((name.to_string(), ver.parse().ok()?))
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
}
