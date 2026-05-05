//! Fold flag-setting compare statements into following conditional branches.

use crate::llil::expr::{binary, expr, LlilExpr, LlilOp, LlilOperand};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagElimResult {
    pub exprs: Vec<LlilExpr>,
    pub folded_pairs: Vec<(u64, u64)>,
}

pub fn flag_elim_block(exprs: &[LlilExpr]) -> FlagElimResult {
    let mut out = Vec::new();
    let mut folded_pairs = Vec::new();
    let mut pending_cmp: Option<(u64, LlilExpr)> = None;

    for e in exprs {
        if let Some(cmp) = cmp_result_expr(e) {
            pending_cmp = Some((e.pc, cmp));
            continue;
        }
        if let Some((cmp_pc, cmp)) = pending_cmp.take() {
            if let Some(mut folded) = fold_if(e, &cmp) {
                folded_pairs.push((cmp_pc, e.pc));
                folded
                    .extra
                    .insert("flag_elim".to_string(), format!("{cmp_pc:#x}"));
                out.push(folded);
                continue;
            }
            out.push(set_flag_from_cmp(cmp_pc, cmp));
        }
        out.push(e.clone());
    }

    if let Some((cmp_pc, cmp)) = pending_cmp {
        out.push(set_flag_from_cmp(cmp_pc, cmp));
    }

    FlagElimResult {
        exprs: out,
        folded_pairs,
    }
}

fn cmp_result_expr(e: &LlilExpr) -> Option<LlilExpr> {
    if e.op != LlilOp::SetFlag {
        return None;
    }
    match (e.operands.first(), e.operands.get(1)) {
        (Some(LlilOperand::Flag(name)), Some(LlilOperand::Expr(value))) if name == "cmp_result" => {
            Some((**value).clone())
        }
        _ => None,
    }
}

fn fold_if(e: &LlilExpr, cmp: &LlilExpr) -> Option<LlilExpr> {
    if e.op != LlilOp::If {
        return None;
    }
    let cond = match e.operands.first() {
        Some(LlilOperand::Expr(cond)) if cond.op == LlilOp::FlagCond => {
            match cond.operands.first() {
                Some(LlilOperand::Str(s)) => s.as_str(),
                _ => return None,
            }
        }
        _ => return None,
    };
    let new_cond = cond_from_cmp_result(cond, cmp)?;
    let mut out = e.clone();
    out.operands[0] = expr(new_cond);
    Some(out)
}

fn cond_from_cmp_result(cond: &str, cmp: &LlilExpr) -> Option<LlilExpr> {
    let zero = LlilExpr::new(LlilOp::Const, cmp.size, vec![LlilOperand::Imm(0)], cmp.pc);
    let op = match cond {
        "eq" => LlilOp::CmpE,
        "ne" => LlilOp::CmpNe,
        "lt" => LlilOp::CmpSlt,
        "le" => LlilOp::CmpSle,
        "ge" => LlilOp::CmpSge,
        "gt" => LlilOp::CmpSgt,
        "lo" | "cc" => LlilOp::CmpUlt,
        "ls" => LlilOp::CmpUle,
        "hs" | "cs" => LlilOp::CmpUge,
        "hi" => LlilOp::CmpUgt,
        _ => return None,
    };
    Some(binary(op, cmp.clone(), zero))
}

fn set_flag_from_cmp(pc: u64, cmp: LlilExpr) -> LlilExpr {
    LlilExpr::new(
        LlilOp::SetFlag,
        1,
        vec![LlilOperand::Flag("cmp_result".to_string()), expr(cmp)],
        pc,
    )
}

#[cfg(test)]
mod tests {
    use crate::llil::expr::{binary, flag_cond, konst, reg, set_flag, LlilOp};

    use super::*;

    #[test]
    fn folds_cmp_result_into_if() {
        let cmp = set_flag(
            "cmp_result",
            binary(LlilOp::Sub, reg("x0"), konst(3)),
            0x1000,
        );
        let br = LlilExpr::new(
            LlilOp::If,
            1,
            vec![
                expr(flag_cond("eq")),
                LlilOperand::U64(0x2000),
                LlilOperand::U64(0x1008),
            ],
            0x1004,
        );
        let result = flag_elim_block(&[cmp, br]);
        assert_eq!(result.exprs.len(), 1);
        assert_eq!(result.folded_pairs, vec![(0x1000, 0x1004)]);
        assert!(result.exprs[0].short().contains("== 0"));
    }
}
