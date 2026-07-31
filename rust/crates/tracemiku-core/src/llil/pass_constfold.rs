//! LLIL constant folding.

use crate::llil::expr::{expr, LlilExpr, LlilOp, LlilOperand};

pub fn constfold_block(exprs: &[LlilExpr]) -> Vec<LlilExpr> {
    exprs.iter().map(constfold_expr).collect()
}

pub fn constfold_expr(e: &LlilExpr) -> LlilExpr {
    let mut out = e.clone();
    out.operands = e
        .operands
        .iter()
        .map(|op| match op {
            LlilOperand::Expr(sub) => expr(constfold_expr(sub)),
            other => other.clone(),
        })
        .collect();

    let Some(value) = fold_binary(&out).or_else(|| fold_unary(&out)) else {
        return out;
    };
    LlilExpr::new(
        LlilOp::Const,
        out.size,
        vec![LlilOperand::Imm(value)],
        out.pc,
    )
}

fn fold_binary(e: &LlilExpr) -> Option<i64> {
    let lhs = const_operand(e.operands.first()?)?;
    let rhs = const_operand(e.operands.get(1)?)?;
    match e.op {
        LlilOp::Add => Some(lhs.wrapping_add(rhs)),
        LlilOp::Sub => Some(lhs.wrapping_sub(rhs)),
        LlilOp::Mul => Some(lhs.wrapping_mul(rhs)),
        LlilOp::DivS if rhs != 0 => Some(lhs.wrapping_div(rhs)),
        LlilOp::DivU if rhs != 0 => Some(((lhs as u64) / (rhs as u64)) as i64),
        LlilOp::And => Some(lhs & rhs),
        LlilOp::Or => Some(lhs | rhs),
        LlilOp::Xor => Some(lhs ^ rhs),
        LlilOp::Lsl => Some(lhs.wrapping_shl((rhs & 63) as u32)),
        LlilOp::Lsr => Some(((lhs as u64).wrapping_shr((rhs & 63) as u32)) as i64),
        LlilOp::Asr => Some(lhs.wrapping_shr((rhs & 63) as u32)),
        LlilOp::CmpE => Some((lhs == rhs) as i64),
        LlilOp::CmpNe => Some((lhs != rhs) as i64),
        LlilOp::CmpSlt => Some((lhs < rhs) as i64),
        LlilOp::CmpSle => Some((lhs <= rhs) as i64),
        LlilOp::CmpSge => Some((lhs >= rhs) as i64),
        LlilOp::CmpSgt => Some((lhs > rhs) as i64),
        LlilOp::CmpUlt => Some(((lhs as u64) < (rhs as u64)) as i64),
        LlilOp::CmpUle => Some(((lhs as u64) <= (rhs as u64)) as i64),
        LlilOp::CmpUge => Some(((lhs as u64) >= (rhs as u64)) as i64),
        LlilOp::CmpUgt => Some(((lhs as u64) > (rhs as u64)) as i64),
        _ => None,
    }
}

fn fold_unary(e: &LlilExpr) -> Option<i64> {
    let v = const_operand(e.operands.first()?)?;
    match e.op {
        LlilOp::Neg => Some(v.wrapping_neg()),
        LlilOp::Not => Some(!v),
        LlilOp::Sx => {
            let bits = (e.size as u32) * 8;
            if bits >= 64 {
                Some(v)
            } else {
                let shift = 64 - bits;
                Some((v << shift) >> shift)
            }
        }
        LlilOp::Zx => {
            let bits = (e.size as u32) * 8;
            if bits >= 64 {
                Some(v)
            } else {
                let mask = (1_u64 << bits).wrapping_sub(1);
                Some((v as u64 & mask) as i64)
            }
        }
        LlilOp::LowPart => {
            let bits = (e.size as u32) * 8;
            if bits >= 64 {
                Some(v)
            } else {
                let mask = (1_u64 << bits).wrapping_sub(1);
                Some((v as u64 & mask) as i64)
            }
        }
        _ => None,
    }
}

fn const_operand(op: &LlilOperand) -> Option<i64> {
    match op {
        LlilOperand::Expr(e) if e.op == LlilOp::Const => match e.operands.first() {
            Some(LlilOperand::Imm(v)) => Some(*v),
            _ => None,
        },
        LlilOperand::Imm(v) => Some(*v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::llil::expr::{binary, konst, set_reg, LlilOp};

    use super::*;

    #[test]
    fn folds_nested_integer_exprs() {
        let e = binary(
            LlilOp::Mul,
            binary(LlilOp::Add, konst(2), konst(3)),
            konst(4),
        );
        assert_eq!(constfold_expr(&e).short(), "0x14");
    }

    #[test]
    fn folds_inside_set_reg() {
        let stmt = set_reg("x0", binary(LlilOp::Xor, konst(0xf0), konst(0x0f)), 0x1000);
        assert_eq!(constfold_expr(&stmt).short(), "x0 = 0xff");
    }
}
