//! Structured token rendering for LLIL.

use crate::hlil::token::{CToken, CTokenLine};
use crate::llil::expr::{LlilExpr, LlilOp, LlilOperand};
use crate::llil::pass_var_unify::VarNameMap;

/// Render LLIL expressions into structured token lines.
pub fn render_llil_tokens(exprs: &[LlilExpr], names: &VarNameMap) -> Vec<CTokenLine> {
    exprs.iter().map(|e| render_stmt_tokens(e, names)).collect()
}

fn render_stmt_tokens(e: &LlilExpr, names: &VarNameMap) -> CTokenLine {
    let mut toks = Vec::new();
    match e.op {
        LlilOp::Nop => {
            toks.push(CToken::comment(&format!("/* {:#x}: nop */", e.pc)));
        }
        LlilOp::SetReg => {
            render_operand(&mut toks, e.operands.first(), names);
            toks.push(CToken::op(" = "));
            render_operand(&mut toks, e.operands.get(1), names);
            toks.push(CToken::punct(";"));
        }
        LlilOp::SetFlag => {
            render_operand(&mut toks, e.operands.first(), names);
            toks.push(CToken::op(" = "));
            render_operand(&mut toks, e.operands.get(1), names);
            toks.push(CToken::punct(";"));
        }
        LlilOp::Store => {
            toks.push(CToken::op("*("));
            toks.push(CToken::type_token(c_type(e.size)));
            toks.push(CToken::ws(" "));
            toks.push(CToken::op("*)("));
            render_operand(&mut toks, e.operands.first(), names);
            toks.push(CToken::punct(")"));
            toks.push(CToken::op(" = "));
            render_operand(&mut toks, e.operands.get(1), names);
            toks.push(CToken::punct(";"));
        }
        LlilOp::Goto => {
            toks.push(CToken::keyword("goto"));
            toks.push(CToken::ws(" "));
            if let Some(LlilOperand::U64(addr)) = e.operands.first() {
                toks.push(CToken::label(&format!("loc_{addr:x}"), Some(*addr)));
            } else {
                render_operand(&mut toks, e.operands.first(), names);
            }
            toks.push(CToken::punct(";"));
        }
        LlilOp::Jump => {
            toks.push(CToken::keyword("goto"));
            toks.push(CToken::ws(" "));
            toks.push(CToken::op("*"));
            render_operand(&mut toks, e.operands.first(), names);
            toks.push(CToken::punct(";"));
        }
        LlilOp::If => {
            toks.push(CToken::keyword("if"));
            toks.push(CToken::punct(" ("));
            render_operand(&mut toks, e.operands.first(), names);
            toks.push(CToken::punct(") "));
            toks.push(CToken::keyword("goto"));
            toks.push(CToken::ws(" "));
            if let Some(LlilOperand::U64(addr)) = e.operands.get(1) {
                toks.push(CToken::label(&format!("loc_{addr:x}"), Some(*addr)));
            } else {
                render_operand(&mut toks, e.operands.get(1), names);
            }
            toks.push(CToken::punct("; "));
            toks.push(CToken::keyword("else"));
            toks.push(CToken::ws(" "));
            toks.push(CToken::keyword("goto"));
            toks.push(CToken::ws(" "));
            if let Some(LlilOperand::U64(addr)) = e.operands.get(2) {
                toks.push(CToken::label(&format!("loc_{addr:x}"), Some(*addr)));
            } else {
                render_operand(&mut toks, e.operands.get(2), names);
            }
            toks.push(CToken::punct(";"));
        }
        LlilOp::Call => {
            match e.operands.first() {
                Some(LlilOperand::Reg(name)) => {
                    toks.push(CToken::func(&resolve_name(name, names), None))
                }
                Some(LlilOperand::U64(addr)) => {
                    toks.push(CToken::func(&format!("sub_{addr:x}"), Some(*addr)))
                }
                Some(LlilOperand::Expr(inner)) => render_expr_to(&mut toks, inner, names),
                other => render_operand(&mut toks, other, names),
            }
            toks.push(CToken::punct("();"));
        }
        LlilOp::Ret => {
            toks.push(CToken::keyword("return"));
            toks.push(CToken::punct(";"));
        }
        LlilOp::Intrinsic => {
            let mnem = e.extra.get("mnem").map(String::as_str).unwrap_or("?");
            toks.push(CToken::func(mnem, None));
            toks.push(CToken::punct("("));
            for (i, op) in e.operands.iter().enumerate() {
                if i > 0 {
                    toks.push(CToken::punct(", "));
                }
                render_operand(&mut toks, Some(op), names);
            }
            toks.push(CToken::punct(");"));
        }
        _ => {
            render_expr_to(&mut toks, e, names);
            toks.push(CToken::punct(";"));
        }
    }
    CTokenLine::new(toks, e.pc)
}

fn render_expr_to(toks: &mut Vec<CToken>, e: &LlilExpr, names: &VarNameMap) {
    match e.op {
        LlilOp::Reg | LlilOp::Flag | LlilOp::Const | LlilOp::ConstPtr | LlilOp::FlagCond => {
            render_operand(toks, e.operands.first(), names);
        }
        LlilOp::Load => {
            toks.push(CToken::op("*("));
            toks.push(CToken::type_token(c_type(e.size)));
            toks.push(CToken::ws(" "));
            toks.push(CToken::op("*)("));
            render_operand(toks, e.operands.first(), names);
            toks.push(CToken::punct(")"));
        }
        LlilOp::Neg => {
            toks.push(CToken::op("-"));
            render_operand(toks, e.operands.first(), names);
        }
        LlilOp::Not => {
            toks.push(CToken::op("~"));
            render_operand(toks, e.operands.first(), names);
        }
        LlilOp::Sx => {
            toks.push(CToken::punct("(("));
            toks.push(CToken::type_token(&format!("int{}_t", e.size * 8)));
            toks.push(CToken::punct(")("));
            render_operand(toks, e.operands.first(), names);
            toks.push(CToken::punct("))"));
        }
        LlilOp::Zx | LlilOp::LowPart => {
            toks.push(CToken::punct("(("));
            toks.push(CToken::type_token(&format!("uint{}_t", e.size * 8)));
            toks.push(CToken::punct(")("));
            render_operand(toks, e.operands.first(), names);
            toks.push(CToken::punct("))"));
        }
        LlilOp::Csel => {
            toks.push(CToken::punct("("));
            render_operand(toks, e.operands.first(), names);
            toks.push(CToken::op(" ? "));
            render_operand(toks, e.operands.get(1), names);
            toks.push(CToken::op(" : "));
            render_operand(toks, e.operands.get(2), names);
            toks.push(CToken::punct(")"));
        }
        LlilOp::Intrinsic => {
            let mnem = e.extra.get("mnem").map(String::as_str).unwrap_or("?");
            toks.push(CToken::func(mnem, None));
            toks.push(CToken::punct("("));
            for (i, op) in e.operands.iter().enumerate() {
                if i > 0 {
                    toks.push(CToken::punct(", "));
                }
                render_operand(toks, Some(op), names);
            }
            toks.push(CToken::punct(")"));
        }
        op if binary_symbol(op).is_some() => {
            let sym = binary_symbol(op).unwrap();
            toks.push(CToken::punct("("));
            render_operand(toks, e.operands.first(), names);
            toks.push(CToken::op(&format!(" {sym} ")));
            render_operand(toks, e.operands.get(1), names);
            toks.push(CToken::punct(")"));
        }
        _ => {
            toks.push(CToken::comment(&format!("/* ? {:#x} */", e.pc)));
        }
    }
}

fn render_operand(toks: &mut Vec<CToken>, op: Option<&LlilOperand>, names: &VarNameMap) {
    match op {
        Some(LlilOperand::Expr(e)) => render_expr_to(toks, e, names),
        Some(LlilOperand::Reg(r)) | Some(LlilOperand::Flag(r)) => {
            toks.push(CToken::var(&resolve_name(r, names)));
        }
        Some(LlilOperand::Str(s)) => toks.push(CToken::literal(s)),
        Some(LlilOperand::Imm(v)) => toks.push(CToken::literal(&format_signed(*v))),
        Some(LlilOperand::U64(v)) => toks.push(CToken::literal(&format!("0x{v:x}"))),
        None => toks.push(CToken::punct("?")),
    }
}

fn resolve_name(raw: &str, names: &VarNameMap) -> String {
    names.get(raw).cloned().unwrap_or_else(|| raw.to_string())
}

fn format_signed(v: i64) -> String {
    if v < 0 {
        let mag = v.unsigned_abs();
        if mag >= 10 {
            format!("-0x{mag:x}")
        } else {
            format!("-{mag}")
        }
    } else {
        let u = v as u64;
        if u >= 10 {
            format!("0x{u:x}")
        } else {
            format!("{u}")
        }
    }
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
