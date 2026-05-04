use crate::llil::expr::{LlilExpr, LlilOp, LlilOperand};

pub fn parse_ssa_reg(s: &str) -> Option<(&str, u32)> {
    let (name, version) = s.rsplit_once('#')?;
    Some((name, version.parse().ok()?))
}

pub fn walk_expr<'a>(expr: &'a LlilExpr, out: &mut Vec<&'a LlilExpr>) {
    out.push(expr);
    for op in &expr.operands {
        if let LlilOperand::Expr(child) = op {
            walk_expr(child, out);
        }
    }
}

pub fn set_reg_dst(expr: &LlilExpr) -> Option<&str> {
    if expr.op != LlilOp::SetReg {
        return None;
    }
    match expr.operands.first() {
        Some(LlilOperand::Reg(r)) => Some(r.as_str()),
        _ => None,
    }
}
