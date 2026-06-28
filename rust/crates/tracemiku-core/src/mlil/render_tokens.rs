//! Structured token rendering for MLIL.

use crate::hlil::token::{CToken, CTokenLine};
use crate::mlil::expr::{MlilExpr, MlilOp, MlilOperand};

/// Render MLIL expressions into structured token lines (one line per statement).
pub fn render_mlil_tokens(exprs: &[MlilExpr]) -> Vec<CTokenLine> {
    exprs.iter().map(render_stmt_tokens).collect()
}

fn render_stmt_tokens(e: &MlilExpr) -> CTokenLine {
    let mut toks = Vec::new();
    match e.op {
        MlilOp::Nop => {
            toks.push(CToken::comment(&format!("/* {:#x}: nop */", e.pc)));
        }
        MlilOp::SetVar => {
            render_operand(&mut toks, e.operands.first());
            toks.push(CToken::op(" = "));
            render_operand(&mut toks, e.operands.get(1));
            toks.push(CToken::punct(";"));
        }
        MlilOp::SetVarField => {
            render_operand(&mut toks, e.operands.first());
            toks.push(CToken::punct("."));
            render_operand(&mut toks, e.operands.get(1));
            toks.push(CToken::op(" = "));
            render_operand(&mut toks, e.operands.get(2));
            toks.push(CToken::punct(";"));
        }
        MlilOp::Store => {
            toks.push(CToken::op("*("));
            toks.push(CToken::type_token(c_type(e.size)));
            toks.push(CToken::ws(" "));
            toks.push(CToken::op("*)("));
            render_operand(&mut toks, e.operands.first());
            toks.push(CToken::punct(")"));
            toks.push(CToken::op(" = "));
            render_operand(&mut toks, e.operands.get(1));
            toks.push(CToken::punct(";"));
        }
        MlilOp::StoreStruct => {
            toks.push(CToken::op("*("));
            toks.push(CToken::type_token(c_type(e.size)));
            toks.push(CToken::ws(" "));
            toks.push(CToken::op("*)(("));
            render_operand(&mut toks, e.operands.first());
            toks.push(CToken::punct(")"));
            toks.push(CToken::op(" + "));
            render_operand(&mut toks, e.operands.get(1));
            toks.push(CToken::punct(")"));
            toks.push(CToken::op(" = "));
            render_operand(&mut toks, e.operands.get(2));
            toks.push(CToken::punct(";"));
        }
        MlilOp::Goto => {
            toks.push(CToken::keyword("goto"));
            toks.push(CToken::ws(" "));
            if let Some(MlilOperand::U64(addr)) = e.operands.first() {
                toks.push(CToken::label(&format!("loc_{addr:x}"), Some(*addr)));
            } else {
                render_operand(&mut toks, e.operands.first());
            }
            toks.push(CToken::punct(";"));
        }
        MlilOp::Jump => {
            toks.push(CToken::keyword("goto"));
            toks.push(CToken::ws(" "));
            toks.push(CToken::op("*"));
            render_operand(&mut toks, e.operands.first());
            toks.push(CToken::punct(";"));
        }
        MlilOp::If => {
            toks.push(CToken::keyword("if"));
            toks.push(CToken::punct(" ("));
            render_operand(&mut toks, e.operands.first());
            toks.push(CToken::punct(") "));
            toks.push(CToken::keyword("goto"));
            toks.push(CToken::ws(" "));
            if let Some(MlilOperand::U64(addr)) = e.operands.get(1) {
                toks.push(CToken::label(&format!("loc_{addr:x}"), Some(*addr)));
            } else {
                render_operand(&mut toks, e.operands.get(1));
            }
            toks.push(CToken::punct("; "));
            toks.push(CToken::keyword("else"));
            toks.push(CToken::ws(" "));
            toks.push(CToken::keyword("goto"));
            toks.push(CToken::ws(" "));
            if let Some(MlilOperand::U64(addr)) = e.operands.get(2) {
                toks.push(CToken::label(&format!("loc_{addr:x}"), Some(*addr)));
            } else {
                render_operand(&mut toks, e.operands.get(2));
            }
            toks.push(CToken::punct(";"));
        }
        MlilOp::Call => {
            match e.operands.first() {
                Some(MlilOperand::Var(name)) => toks.push(CToken::func(name, None)),
                Some(MlilOperand::U64(addr)) => {
                    toks.push(CToken::func(&format!("sub_{addr:x}"), Some(*addr)))
                }
                other => render_operand(&mut toks, other),
            }
            toks.push(CToken::punct("();"));
        }
        MlilOp::Tailcall => {
            toks.push(CToken::keyword("tailcall"));
            toks.push(CToken::ws(" "));
            match e.operands.first() {
                Some(MlilOperand::Var(name)) => toks.push(CToken::func(name, None)),
                Some(MlilOperand::U64(addr)) => {
                    toks.push(CToken::func(&format!("sub_{addr:x}"), Some(*addr)))
                }
                other => render_operand(&mut toks, other),
            }
            toks.push(CToken::punct("();"));
        }
        MlilOp::Ret => {
            toks.push(CToken::keyword("return"));
            toks.push(CToken::punct(";"));
        }
        MlilOp::Noret => {
            toks.push(CToken::func("__noreturn", None));
            toks.push(CToken::punct("();"));
        }
        MlilOp::Intrinsic => {
            let mnem = e.extra.get("mnem").map(String::as_str).unwrap_or("?");
            toks.push(CToken::comment(&format!("/* intrinsic {mnem}(")));
            for (i, op) in e.operands.iter().enumerate() {
                if i > 0 {
                    toks.push(CToken::comment(", "));
                }
                toks.push(CToken::comment(&operand_text(Some(op))));
            }
            toks.push(CToken::comment(") */"));
        }
        MlilOp::Unimpl => {
            toks.push(CToken::comment(&format!("/* UNIMPL at {:#x} */", e.pc)));
        }
        _ => {
            // Render as expression statement
            render_expr_to(&mut toks, e);
            toks.push(CToken::punct(";"));
        }
    }
    CTokenLine::new(toks, e.pc)
}

fn render_expr_to(toks: &mut Vec<CToken>, e: &MlilExpr) {
    match e.op {
        MlilOp::Var | MlilOp::Const | MlilOp::ConstPtr | MlilOp::ConstData => {
            render_operand(toks, e.operands.first());
        }
        MlilOp::VarField => {
            render_operand(toks, e.operands.first());
            toks.push(CToken::punct("."));
            render_operand(toks, e.operands.get(1));
        }
        MlilOp::Load => {
            toks.push(CToken::op("*("));
            toks.push(CToken::type_token(c_type(e.size)));
            toks.push(CToken::ws(" "));
            toks.push(CToken::op("*)("));
            render_operand(toks, e.operands.first());
            toks.push(CToken::punct(")"));
        }
        MlilOp::LoadStruct => {
            toks.push(CToken::op("*("));
            toks.push(CToken::type_token(c_type(e.size)));
            toks.push(CToken::ws(" "));
            toks.push(CToken::op("*)(("));
            render_operand(toks, e.operands.first());
            toks.push(CToken::punct(")"));
            toks.push(CToken::op(" + "));
            render_operand(toks, e.operands.get(1));
            toks.push(CToken::punct(")"));
        }
        MlilOp::AddressOf => {
            toks.push(CToken::op("&"));
            render_operand(toks, e.operands.first());
        }
        MlilOp::AddressOfField => {
            toks.push(CToken::op("&"));
            render_operand(toks, e.operands.first());
            toks.push(CToken::punct("."));
            render_operand(toks, e.operands.get(1));
        }
        MlilOp::Neg => {
            toks.push(CToken::op("-"));
            render_operand(toks, e.operands.first());
        }
        MlilOp::Not => {
            toks.push(CToken::op("~"));
            render_operand(toks, e.operands.first());
        }
        MlilOp::Sx => {
            toks.push(CToken::punct("(("));
            toks.push(CToken::type_token(&format!("int{}_t", e.size * 8)));
            toks.push(CToken::punct(")("));
            render_operand(toks, e.operands.first());
            toks.push(CToken::punct("))"));
        }
        MlilOp::Zx | MlilOp::LowPart => {
            toks.push(CToken::punct("(("));
            toks.push(CToken::type_token(&format!("uint{}_t", e.size * 8)));
            toks.push(CToken::punct(")("));
            render_operand(toks, e.operands.first());
            toks.push(CToken::punct("))"));
        }
        MlilOp::Csel => {
            toks.push(CToken::punct("("));
            render_operand(toks, e.operands.first());
            toks.push(CToken::op(" ? "));
            render_operand(toks, e.operands.get(1));
            toks.push(CToken::op(" : "));
            render_operand(toks, e.operands.get(2));
            toks.push(CToken::punct(")"));
        }
        MlilOp::Intrinsic => {
            let mnem = e.extra.get("mnem").map(String::as_str).unwrap_or("?");
            toks.push(CToken::func(mnem, None));
            toks.push(CToken::punct("("));
            for (i, op) in e.operands.iter().enumerate() {
                if i > 0 {
                    toks.push(CToken::punct(", "));
                }
                render_operand(toks, Some(op));
            }
            toks.push(CToken::punct(")"));
        }
        op if binary_symbol(op).is_some() => {
            let sym = binary_symbol(op).unwrap();
            toks.push(CToken::punct("("));
            render_operand(toks, e.operands.first());
            toks.push(CToken::op(&format!(" {sym} ")));
            render_operand(toks, e.operands.get(1));
            toks.push(CToken::punct(")"));
        }
        _ => {
            toks.push(CToken::comment(&format!("/* ? {:#x} */", e.pc)));
        }
    }
}

fn render_operand(toks: &mut Vec<CToken>, op: Option<&MlilOperand>) {
    match op {
        Some(MlilOperand::Expr(e)) => render_expr_to(toks, e),
        Some(MlilOperand::Var(v)) => toks.push(CToken::var(v)),
        Some(MlilOperand::Str(s)) => toks.push(CToken::literal(s)),
        Some(MlilOperand::Imm(v)) => toks.push(CToken::literal(&format_signed(*v))),
        Some(MlilOperand::U64(v)) => toks.push(CToken::literal(&format!("0x{v:x}"))),
        None => toks.push(CToken::punct("?")),
    }
}

fn operand_text(op: Option<&MlilOperand>) -> String {
    match op {
        Some(MlilOperand::Var(v)) => v.clone(),
        Some(MlilOperand::Str(s)) => s.clone(),
        Some(MlilOperand::Imm(v)) => format_signed(*v),
        Some(MlilOperand::U64(v)) => format!("0x{v:x}"),
        _ => "...".into(),
    }
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

fn binary_symbol(op: MlilOp) -> Option<&'static str> {
    Some(match op {
        MlilOp::Add => "+",
        MlilOp::Sub => "-",
        MlilOp::Mul => "*",
        MlilOp::DivS | MlilOp::DivU => "/",
        MlilOp::ModS | MlilOp::ModU => "%",
        MlilOp::And => "&",
        MlilOp::Or => "|",
        MlilOp::Xor => "^",
        MlilOp::Lsl => "<<",
        MlilOp::Lsr | MlilOp::Asr => ">>",
        MlilOp::Rol => "<<<",
        MlilOp::Ror => ">>>",
        MlilOp::CmpE => "==",
        MlilOp::CmpNe => "!=",
        MlilOp::CmpSlt | MlilOp::CmpUlt => "<",
        MlilOp::CmpSle | MlilOp::CmpUle => "<=",
        MlilOp::CmpSge | MlilOp::CmpUge => ">=",
        MlilOp::CmpSgt | MlilOp::CmpUgt => ">",
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
