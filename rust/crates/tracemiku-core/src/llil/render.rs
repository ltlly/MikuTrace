//! C-like rendering for LLIL.

use crate::llil::expr::{LlilExpr, LlilOp, LlilOperand};

pub fn render_llil_block(exprs: &[LlilExpr]) -> String {
    let mut out = String::new();
    for e in exprs {
        out.push_str(&render_stmt(e));
        out.push('\n');
    }
    out
}

pub fn render_stmt(e: &LlilExpr) -> String {
    match e.op {
        LlilOp::Nop => format!("/* {:#x}: nop */", e.pc),
        LlilOp::SetReg => format!(
            "{} = {};",
            render_operand(e.operands.first()),
            render_operand(e.operands.get(1))
        ),
        LlilOp::SetFlag => format!(
            "/* flag */ {} = {};",
            render_operand(e.operands.first()),
            render_operand(e.operands.get(1))
        ),
        LlilOp::Store => format!(
            "*({} *)({}) = {};",
            c_type(e.size),
            render_operand(e.operands.first()),
            render_operand(e.operands.get(1))
        ),
        LlilOp::Goto => format!("goto loc_{};", render_target(e.operands.first())),
        LlilOp::Jump => format!("goto *{};", render_operand(e.operands.first())),
        LlilOp::If => format!(
            "if ({}) goto loc_{}; else goto loc_{};",
            render_operand(e.operands.first()),
            render_target(e.operands.get(1)),
            render_target(e.operands.get(2))
        ),
        LlilOp::Call => format!("{};", render_call(e)),
        LlilOp::Ret => "return;".to_string(),
        LlilOp::Intrinsic => format!(
            "/* intrinsic {} {} */",
            e.extra.get("mnem").map(String::as_str).unwrap_or("?"),
            e.operands
                .iter()
                .map(|o| render_operand(Some(o)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        _ => format!("{};", render_expr(e)),
    }
}

pub fn render_expr(e: &LlilExpr) -> String {
    match e.op {
        LlilOp::Reg | LlilOp::Flag | LlilOp::Const | LlilOp::ConstPtr | LlilOp::FlagCond => {
            render_operand(e.operands.first())
        }
        LlilOp::Load => format!(
            "*({} *)({})",
            c_type(e.size),
            render_operand(e.operands.first())
        ),
        LlilOp::Neg => format!("-{}", render_operand(e.operands.first())),
        LlilOp::Not => format!("~{}", render_operand(e.operands.first())),
        op if binary_symbol(op).is_some() => format!(
            "({} {} {})",
            render_operand(e.operands.first()),
            binary_symbol(op).unwrap(),
            render_operand(e.operands.get(1))
        ),
        LlilOp::Intrinsic => format!(
            "{}({})",
            e.extra
                .get("mnem")
                .map(String::as_str)
                .unwrap_or("_intrinsic"),
            e.operands
                .iter()
                .map(|o| render_operand(Some(o)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        _ => e.short(),
    }
}

fn render_call(e: &LlilExpr) -> String {
    format!("{}()", render_operand(e.operands.first()))
}

fn render_operand(op: Option<&LlilOperand>) -> String {
    match op {
        Some(LlilOperand::Expr(e)) => render_expr(e),
        Some(LlilOperand::Reg(r)) | Some(LlilOperand::Flag(r)) => sanitize_ident(r),
        Some(LlilOperand::Str(s)) => s.clone(),
        Some(LlilOperand::Imm(v)) => {
            if v.abs() >= 10 {
                format!("{v:#x}")
            } else {
                v.to_string()
            }
        }
        Some(LlilOperand::U64(v)) => format!("{v:#x}"),
        None => "?".to_string(),
    }
}

fn render_target(op: Option<&LlilOperand>) -> String {
    render_operand(op)
        .trim_start_matches("0x")
        .replace('-', "neg_")
}

fn sanitize_ident(s: &str) -> String {
    s.replace('#', "_")
}

fn binary_symbol(op: LlilOp) -> Option<&'static str> {
    Some(match op {
        LlilOp::Add => "+",
        LlilOp::Sub => "-",
        LlilOp::Mul => "*",
        LlilOp::DivS | LlilOp::DivU => "/",
        LlilOp::And => "&",
        LlilOp::Or => "|",
        LlilOp::Xor => "^",
        LlilOp::Lsl => "<<",
        LlilOp::Lsr | LlilOp::Asr => ">>",
        LlilOp::Rol => "rol",
        LlilOp::Ror => "ror",
        LlilOp::CmpE => "==",
        LlilOp::CmpNe => "!=",
        LlilOp::CmpSlt | LlilOp::CmpUlt => "<",
        LlilOp::CmpSle | LlilOp::CmpUle => "<=",
        LlilOp::CmpSge | LlilOp::CmpUge => ">=",
        LlilOp::CmpSgt | LlilOp::CmpUgt => ">",
        _ => return None,
    })
}

fn c_type(size: u8) -> &'static str {
    match size {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        _ => "uint64_t",
    }
}

#[cfg(test)]
mod tests {
    use crate::llil::expr::{binary, konst, reg, set_reg, LlilOp};

    use super::*;

    #[test]
    fn renders_set_reg_and_expr() {
        let stmt = set_reg("x0#1", binary(LlilOp::Add, reg("x1#0"), konst(2)), 0x1000);
        assert_eq!(render_stmt(&stmt), "x0_1 = (x1_0 + 2);");
    }

    #[test]
    fn renders_block_lines() {
        let block = vec![
            set_reg("x0#1", konst(1), 0x1000),
            LlilExpr::new(LlilOp::Ret, 8, Vec::new(), 0x1004),
        ];
        assert_eq!(render_llil_block(&block), "x0_1 = 1;\nreturn;\n");
    }
}
