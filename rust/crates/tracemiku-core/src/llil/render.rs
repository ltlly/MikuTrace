//! C-like rendering for LLIL.

use crate::llil::expr::{LlilExpr, LlilOp, LlilOperand};
use crate::llil::VarNameMap;

pub fn render_llil_block(exprs: &[LlilExpr]) -> String {
    render_llil_block_with_names(exprs, &VarNameMap::new())
}

pub fn render_llil_block_with_names(exprs: &[LlilExpr], names: &VarNameMap) -> String {
    let mut out = String::new();
    for e in exprs {
        out.push_str(&render_stmt_with_names(e, names));
        out.push('\n');
    }
    out
}

pub fn render_stmt(e: &LlilExpr) -> String {
    render_stmt_with_names(e, &VarNameMap::new())
}

fn render_stmt_with_names(e: &LlilExpr, names: &VarNameMap) -> String {
    match e.op {
        LlilOp::Nop => format!("/* {:#x}: nop */", e.pc),
        LlilOp::SetReg => format!(
            "{} = {};",
            render_operand(e.operands.first(), names),
            render_operand(e.operands.get(1), names)
        ),
        LlilOp::SetFlag => format!(
            "/* flag */ {} = {};",
            render_operand(e.operands.first(), names),
            render_operand(e.operands.get(1), names)
        ),
        LlilOp::Store => format!(
            "*({} *)({}) = {};",
            c_type(e.size),
            render_operand(e.operands.first(), names),
            render_operand(e.operands.get(1), names)
        ),
        LlilOp::Goto => format!("goto loc_{};", render_target(e.operands.first(), names)),
        LlilOp::Jump => format!("goto *{};", render_operand(e.operands.first(), names)),
        LlilOp::If => format!(
            "if ({}) goto loc_{}; else goto loc_{};",
            render_operand(e.operands.first(), names),
            render_target(e.operands.get(1), names),
            render_target(e.operands.get(2), names)
        ),
        LlilOp::Call => format!("{};", render_call(e, names)),
        LlilOp::Ret => "return;".to_string(),
        LlilOp::Intrinsic => format!(
            "/* intrinsic {} {} */",
            e.extra.get("mnem").map(String::as_str).unwrap_or("?"),
            e.operands
                .iter()
                .map(|o| render_operand(Some(o), names))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        _ => format!("{};", render_expr_with_names(e, names)),
    }
}

pub fn render_expr(e: &LlilExpr) -> String {
    render_expr_with_names(e, &VarNameMap::new())
}

fn render_expr_with_names(e: &LlilExpr, names: &VarNameMap) -> String {
    match e.op {
        LlilOp::Reg | LlilOp::Flag | LlilOp::Const | LlilOp::ConstPtr | LlilOp::FlagCond => {
            render_operand(e.operands.first(), names)
        }
        LlilOp::Load => format!(
            "*({} *)({})",
            c_type(e.size),
            render_operand(e.operands.first(), names)
        ),
        LlilOp::Neg => format!("-{}", render_operand(e.operands.first(), names)),
        LlilOp::Not => format!("~{}", render_operand(e.operands.first(), names)),
        op if binary_symbol(op).is_some() => format!(
            "({} {} {})",
            render_operand(e.operands.first(), names),
            binary_symbol(op).unwrap(),
            render_operand(e.operands.get(1), names)
        ),
        LlilOp::Intrinsic => format!(
            "{}({})",
            e.extra
                .get("mnem")
                .map(String::as_str)
                .unwrap_or("_intrinsic"),
            e.operands
                .iter()
                .map(|o| render_operand(Some(o), names))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        _ => e.short(),
    }
}

fn render_call(e: &LlilExpr, names: &VarNameMap) -> String {
    format!("{}()", render_operand(e.operands.first(), names))
}

fn render_operand(op: Option<&LlilOperand>, names: &VarNameMap) -> String {
    match op {
        Some(LlilOperand::Expr(e)) => render_expr_with_names(e, names),
        Some(LlilOperand::Reg(r)) | Some(LlilOperand::Flag(r)) => render_ident(r, names),
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

fn render_target(op: Option<&LlilOperand>, names: &VarNameMap) -> String {
    render_operand(op, names)
        .trim_start_matches("0x")
        .replace('-', "neg_")
}

fn render_ident(s: &str, names: &VarNameMap) -> String {
    names.get(s).cloned().unwrap_or_else(|| sanitize_ident(s))
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

    #[test]
    fn renders_block_with_unified_names() {
        let block = vec![set_reg(
            "x0#0",
            binary(LlilOp::Add, reg("x1#0"), konst(2)),
            0x1000,
        )];
        let mut names = VarNameMap::new();
        names.insert("x0#0".to_string(), "arg_0".to_string());
        names.insert("x1#0".to_string(), "arg_1".to_string());
        assert_eq!(
            render_llil_block_with_names(&block, &names),
            "arg_0 = (arg_1 + 2);\n"
        );
    }
}
