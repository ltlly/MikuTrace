//! Structured token rendering for HLIL — emits `CTokenLine` instead of strings.
//!
//! Parallel to `render.rs` but preserves semantic information in each token
//! for direct frontend rendering without regex re-tokenization.

use super::expr::{HlilExpr, HlilOp, HlilOperand};
use super::token::{CToken, CTokenKind, CTokenLine};

/// Render HLIL expressions into structured token lines.
pub fn render_hlil_tokens(exprs: &[HlilExpr]) -> Vec<CTokenLine> {
    let mut out = Vec::new();
    for e in exprs {
        render_stmt(&mut out, e, 0);
    }
    out
}

// ─── Statement-level rendering ──────────────────────────────────────────

fn render_stmt(out: &mut Vec<CTokenLine>, e: &HlilExpr, indent: usize) {
    match e.op {
        HlilOp::Nop => {
            let mut b = LineBuilder::new(indent, e.pc);
            b.comment(&format!("/* {:#x}: nop */", e.pc));
            out.push(b.finish());
        }
        HlilOp::Assign => {
            let mut b = LineBuilder::new(indent, e.pc);
            render_operand_to(&mut b, e.operands.first());
            b.op(" = ");
            render_operand_to(&mut b, e.operands.get(1));
            b.punct(";");
            out.push(b.finish());
        }
        HlilOp::VarDeclare => {
            let mut b = LineBuilder::new(indent, e.pc);
            let ty = e.extra.get("type").map(String::as_str).unwrap_or("int64_t");
            b.type_tok(ty);
            b.ws(" ");
            render_operand_to(&mut b, e.operands.first());
            b.punct(";");
            out.push(b.finish());
        }
        HlilOp::VarInit => {
            let mut b = LineBuilder::new(indent, e.pc);
            b.type_tok("int64_t");
            b.ws(" ");
            render_operand_to(&mut b, e.operands.first());
            b.op(" = ");
            render_operand_to(&mut b, e.operands.get(1));
            b.punct(";");
            out.push(b.finish());
        }
        HlilOp::Block => {
            push_line_kw(out, indent, e.pc, "{", "");
            for child in &e.operands {
                if let HlilOperand::Expr(child_e) = child {
                    render_stmt(out, child_e, indent + 1);
                }
            }
            push_line_kw(out, indent, e.pc, "}", "");
        }
        HlilOp::If => {
            let cond = e.operands.first();
            let then_body = match e.operands.get(1) {
                Some(HlilOperand::Expr(ee)) => ee,
                _ => {
                    let mut b = LineBuilder::new(indent, e.pc);
                    b.kw("if");
                    b.punct(" (");
                    render_operand_to(&mut b, cond);
                    b.punct(") { }");
                    out.push(b.finish());
                    return;
                }
            };
            let else_body = match e.operands.get(2) {
                Some(HlilOperand::Expr(ee)) => Some(ee),
                _ => None,
            };

            // if (cond)
            let mut b = LineBuilder::new(indent, e.pc);
            b.kw("if");
            b.punct(" (");
            render_operand_to(&mut b, cond);
            b.punct(")");
            out.push(b.finish());

            // then body
            render_block_body(out, then_body, indent);

            // else
            if let Some(else_e) = else_body {
                if else_e.op == HlilOp::If {
                    // else if — render on same line concept
                    let mut eb = LineBuilder::new(indent, else_e.pc);
                    eb.kw("else");
                    eb.ws(" ");
                    out.push(eb.finish());
                    render_stmt(out, else_e, indent);
                } else {
                    push_line_kw(out, indent, else_e.pc, "else", "");
                    render_block_body(out, else_e, indent);
                }
            }
        }
        HlilOp::While => {
            let mut b = LineBuilder::new(indent, e.pc);
            b.kw("while");
            b.punct(" (");
            render_operand_to(&mut b, e.operands.first());
            b.punct(")");
            out.push(b.finish());

            if let Some(HlilOperand::Expr(body)) = e.operands.get(1) {
                render_block_body(out, body, indent);
            }
        }
        HlilOp::DoWhile => {
            push_line_kw(out, indent, e.pc, "do", "");
            if let Some(HlilOperand::Expr(body)) = e.operands.first() {
                render_block_body(out, body, indent);
            }
            let mut b = LineBuilder::new(indent, e.pc);
            b.kw("while");
            b.punct(" (");
            render_operand_to(&mut b, e.operands.get(1));
            b.punct(");");
            out.push(b.finish());
        }
        HlilOp::For => {
            let mut b = LineBuilder::new(indent, e.pc);
            b.kw("for");
            b.punct(" (");
            render_for_clause_to(&mut b, e.operands.first());
            b.punct("; ");
            render_for_clause_to(&mut b, e.operands.get(1));
            b.punct("; ");
            render_for_clause_to(&mut b, e.operands.get(2));
            b.punct(")");
            out.push(b.finish());
            if let Some(HlilOperand::Expr(body)) = e.operands.get(3) {
                render_block_body(out, body, indent);
            }
        }
        HlilOp::Switch => {
            let mut b = LineBuilder::new(indent, e.pc);
            b.kw("switch");
            b.punct(" (");
            render_operand_to(&mut b, e.operands.first());
            b.punct(")");
            out.push(b.finish());
            push_line_kw(out, indent, e.pc, "{", "");
            for op in e.operands.iter().skip(1) {
                if let HlilOperand::Expr(case_e) = op {
                    render_stmt(out, case_e, indent + 1);
                }
            }
            push_line_kw(out, indent, e.pc, "}", "");
        }
        HlilOp::Case => {
            let mut b = LineBuilder::new(indent, e.pc);
            match e.operands.first() {
                Some(HlilOperand::Str(s)) if s == "default" => b.kw("default"),
                other => {
                    b.kw("case");
                    b.ws(" ");
                    render_operand_to(&mut b, other);
                }
            };
            b.punct(":");
            out.push(b.finish());
            if let Some(HlilOperand::Expr(body)) = e.operands.get(1) {
                render_case_body(out, body, indent + 1);
            }
        }
        HlilOp::Break => {
            let mut b = LineBuilder::new(indent, e.pc);
            b.kw("break");
            b.punct(";");
            out.push(b.finish());
        }
        HlilOp::Continue => {
            let mut b = LineBuilder::new(indent, e.pc);
            b.kw("continue");
            b.punct(";");
            out.push(b.finish());
        }
        HlilOp::Goto => {
            let mut b = LineBuilder::new(indent, e.pc);
            b.kw("goto");
            b.ws(" ");
            // Target is a U64 address — render as label
            if let Some(HlilOperand::U64(addr)) = e.operands.first() {
                b.push(CToken::label(&format!("loc_{addr:x}"), Some(*addr)));
            } else {
                render_operand_to(&mut b, e.operands.first());
            }
            b.punct(";");
            out.push(b.finish());
        }
        HlilOp::Label => {
            let mut b = LineBuilder::new(0, e.pc); // labels have no indent
            if let Some(HlilOperand::Str(name)) = e.operands.first() {
                b.push(CToken::label(name, Some(e.pc)));
            } else {
                render_operand_to(&mut b, e.operands.first());
            }
            b.punct(":");
            out.push(b.finish());
        }
        HlilOp::Call => {
            let mut b = LineBuilder::new(indent, e.pc);
            // Call target → func token
            match e.operands.first() {
                Some(HlilOperand::Var(name)) => {
                    b.push(CToken::func(name, None));
                }
                Some(HlilOperand::U64(addr)) => {
                    b.push(CToken::func(&format!("sub_{addr:x}"), Some(*addr)));
                }
                Some(HlilOperand::Expr(inner)) => render_expr_to(&mut b, inner),
                _ => b.punct("?"),
            }
            b.punct("();");
            out.push(b.finish());
        }
        HlilOp::Ret => {
            let mut b = LineBuilder::new(indent, e.pc);
            b.kw("return");
            b.punct(";");
            out.push(b.finish());
        }
        HlilOp::Noret => {
            let mut b = LineBuilder::new(indent, e.pc);
            b.push(CToken::func("__noreturn", None));
            b.punct("();");
            out.push(b.finish());
        }
        HlilOp::Unreachable => {
            let mut b = LineBuilder::new(indent, e.pc);
            b.push(CToken::func("__builtin_unreachable", None));
            b.punct("();");
            out.push(b.finish());
        }
        HlilOp::Intrinsic => {
            let mnem = e.extra.get("mnem").map(String::as_str).unwrap_or("?");
            let mut b = LineBuilder::new(indent, e.pc);
            b.comment(&format!("/* intrinsic {}(", mnem));
            for (i, op) in e.operands.iter().enumerate() {
                if i > 0 {
                    b.comment(", ");
                }
                // Inline the operand text into the comment
                let text = render_operand_text(Some(op));
                b.comment(&text);
            }
            b.comment(") */");
            out.push(b.finish());
        }
        HlilOp::Jump => {
            let mut b = LineBuilder::new(indent, e.pc);
            b.kw("goto");
            b.ws(" ");
            b.op("*");
            render_operand_to(&mut b, e.operands.first());
            b.punct(";");
            out.push(b.finish());
        }
        HlilOp::Trap => {
            let mut b = LineBuilder::new(indent, e.pc);
            b.push(CToken::func("__builtin_trap", None));
            b.punct("();");
            out.push(b.finish());
        }
        HlilOp::Bp => {
            let mut b = LineBuilder::new(indent, e.pc);
            b.push(CToken::func("__breakpoint", None));
            b.punct("();");
            out.push(b.finish());
        }
        HlilOp::Unimpl | HlilOp::Undef => {
            let mut b = LineBuilder::new(indent, e.pc);
            b.comment(&format!("/* unimpl at {:#x} */", e.pc));
            out.push(b.finish());
        }
        // Standalone expression statements (Deref, DerefField, Csel as stmts are rare)
        _ => {
            let mut b = LineBuilder::new(indent, e.pc);
            render_expr_to(&mut b, e);
            b.punct(";");
            out.push(b.finish());
        }
    }
}

// ─── Expression-level rendering (inline, no semicolons) ─────────────────

fn render_expr_to(b: &mut LineBuilder, e: &HlilExpr) {
    match e.op {
        HlilOp::Var | HlilOp::Const | HlilOp::ConstPtr | HlilOp::ConstData => {
            render_operand_to(b, e.operands.first());
        }
        HlilOp::Deref => {
            b.op("*(");
            b.type_tok(c_type(e.size));
            b.ws(" ");
            b.op("*)(");
            render_operand_to(b, e.operands.first());
            b.punct(")");
        }
        HlilOp::DerefField => {
            b.op("*(");
            b.type_tok(c_type(e.size));
            b.ws(" ");
            b.op("*)((");
            render_operand_to(b, e.operands.first());
            b.punct(")");
            b.op(" + ");
            render_operand_to(b, e.operands.get(1));
            b.punct(")");
        }
        HlilOp::StructField => {
            render_operand_to(b, e.operands.first());
            b.punct(".");
            render_operand_to(b, e.operands.get(1));
        }
        HlilOp::ArrayIndex => {
            render_operand_to(b, e.operands.first());
            b.punct("[");
            render_operand_to(b, e.operands.get(1));
            b.punct("]");
        }
        HlilOp::AddressOf => {
            b.op("&");
            render_operand_to(b, e.operands.first());
        }
        HlilOp::AddressOfField => {
            b.op("&");
            render_operand_to(b, e.operands.first());
            b.punct(".");
            render_operand_to(b, e.operands.get(1));
        }
        HlilOp::Neg => {
            b.op("-");
            render_operand_to(b, e.operands.first());
        }
        HlilOp::Not => {
            b.op("~");
            render_operand_to(b, e.operands.first());
        }
        HlilOp::Sx => {
            b.punct("((");
            b.type_tok(&format!("int{}_t", e.size * 8));
            b.punct(")(");
            render_operand_to(b, e.operands.first());
            b.punct("))");
        }
        HlilOp::Zx | HlilOp::LowPart => {
            b.punct("((");
            b.type_tok(&format!("uint{}_t", e.size * 8));
            b.punct(")(");
            render_operand_to(b, e.operands.first());
            b.punct("))");
        }
        HlilOp::Csel => {
            b.punct("(");
            render_operand_to(b, e.operands.first());
            b.op(" ? ");
            render_operand_to(b, e.operands.get(1));
            b.op(" : ");
            render_operand_to(b, e.operands.get(2));
            b.punct(")");
        }
        HlilOp::Call => {
            match e.operands.first() {
                Some(HlilOperand::Var(name)) => b.push(CToken::func(name, None)),
                Some(HlilOperand::U64(addr)) => {
                    b.push(CToken::func(&format!("sub_{addr:x}"), Some(*addr)))
                }
                Some(HlilOperand::Expr(inner)) => render_expr_to(b, inner),
                _ => b.punct("?"),
            }
            b.punct("()");
        }
        op if binary_symbol(op).is_some() => {
            let sym = binary_symbol(op).unwrap();
            b.punct("(");
            render_operand_to(b, e.operands.first());
            b.op(&format!(" {sym} "));
            render_operand_to(b, e.operands.get(1));
            b.punct(")");
        }
        HlilOp::Intrinsic => {
            let mnem = e.extra.get("mnem").map(String::as_str).unwrap_or("?");
            b.push(CToken::func(mnem, None));
            b.punct("(");
            for (i, op) in e.operands.iter().enumerate() {
                if i > 0 {
                    b.punct(", ");
                }
                render_operand_to(b, Some(op));
            }
            b.punct(")");
        }
        _ => {
            b.comment(&format!("/* ? {:#x} */", e.pc));
        }
    }
}

// ─── Operand rendering ──────────────────────────────────────────────────

fn render_operand_to(b: &mut LineBuilder, op: Option<&HlilOperand>) {
    match op {
        Some(HlilOperand::Expr(e)) => render_expr_to(b, e),
        Some(HlilOperand::Var(name)) => b.push(CToken::var(name)),
        Some(HlilOperand::Str(s)) => b.push(CToken::literal(s)),
        Some(HlilOperand::Imm(v)) => b.push(CToken::literal(&format_signed(*v))),
        Some(HlilOperand::U64(v)) => b.push(CToken::literal(&format!("0x{v:x}"))),
        None => b.punct("?"),
    }
}

/// Fallback: render operand to plain text (for embedding in comments).
fn render_operand_text(op: Option<&HlilOperand>) -> String {
    match op {
        Some(HlilOperand::Var(name)) => name.clone(),
        Some(HlilOperand::Str(s)) => s.clone(),
        Some(HlilOperand::Imm(v)) => format_signed(*v),
        Some(HlilOperand::U64(v)) => format!("0x{v:x}"),
        Some(HlilOperand::Expr(_)) => "...".into(),
        None => "?".into(),
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────

fn render_block_body(out: &mut Vec<CTokenLine>, body: &HlilExpr, indent: usize) {
    push_line_kw(out, indent, body.pc, "{", "");
    if body.op == HlilOp::Block {
        for child in &body.operands {
            if let HlilOperand::Expr(ee) = child {
                render_stmt(out, ee, indent + 1);
            }
        }
    } else {
        render_stmt(out, body, indent + 1);
    }
    push_line_kw(out, indent, body.pc, "}", "");
}

fn render_case_body(out: &mut Vec<CTokenLine>, body: &HlilExpr, indent: usize) {
    if body.op == HlilOp::Block {
        for child in &body.operands {
            if let HlilOperand::Expr(ee) = child {
                render_stmt(out, ee, indent);
            }
        }
    } else {
        render_stmt(out, body, indent);
    }
}

fn render_for_clause_to(b: &mut LineBuilder, op: Option<&HlilOperand>) {
    match op {
        Some(HlilOperand::Expr(e)) if e.op == HlilOp::Nop => {}
        Some(HlilOperand::Expr(e)) if e.op == HlilOp::Assign => {
            render_operand_to(b, e.operands.first());
            b.op(" = ");
            render_operand_to(b, e.operands.get(1));
        }
        other => render_operand_to(b, other),
    }
}

fn push_line_kw(out: &mut Vec<CTokenLine>, indent: usize, pc: u64, text: &str, _suffix: &str) {
    let mut b = LineBuilder::new(indent, pc);
    // Determine if it's a keyword or punctuation
    if text == "{" || text == "}" {
        b.punct(text);
    } else {
        b.kw(text);
    }
    out.push(b.finish());
}

fn binary_symbol(op: HlilOp) -> Option<&'static str> {
    Some(match op {
        HlilOp::Add => "+",
        HlilOp::Sub => "-",
        HlilOp::Mul => "*",
        HlilOp::DivS | HlilOp::DivU => "/",
        HlilOp::ModS | HlilOp::ModU => "%",
        HlilOp::And => "&",
        HlilOp::Or => "|",
        HlilOp::Xor => "^",
        HlilOp::Lsl => "<<",
        HlilOp::Lsr | HlilOp::Asr => ">>",
        HlilOp::Rol => "<<<",
        HlilOp::Ror => ">>>",
        HlilOp::CmpE => "==",
        HlilOp::CmpNe => "!=",
        HlilOp::CmpSlt | HlilOp::CmpUlt => "<",
        HlilOp::CmpSle | HlilOp::CmpUle => "<=",
        HlilOp::CmpSge | HlilOp::CmpUge => ">=",
        HlilOp::CmpSgt | HlilOp::CmpUgt => ">",
        _ => return None,
    })
}

fn c_type(size: u8) -> &'static str {
    match size {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        _ => "uint64_t",
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

// ─── LineBuilder ────────────────────────────────────────────────────────

struct LineBuilder {
    tokens: Vec<CToken>,
    pc: u64,
}

impl LineBuilder {
    fn new(indent: usize, pc: u64) -> Self {
        let mut tokens = Vec::new();
        if indent > 0 {
            tokens.push(CToken::ws(&"    ".repeat(indent)));
        }
        Self { tokens, pc }
    }

    fn push(&mut self, tok: CToken) {
        self.tokens.push(tok);
    }

    fn kw(&mut self, text: &str) {
        self.tokens.push(CToken::keyword(text));
    }

    fn type_tok(&mut self, text: &str) {
        self.tokens.push(CToken::type_token(text));
    }

    fn op(&mut self, text: &str) {
        self.tokens.push(CToken::op(text));
    }

    fn punct(&mut self, text: &str) {
        self.tokens.push(CToken::punct(text));
    }

    fn ws(&mut self, text: &str) {
        self.tokens.push(CToken::ws(text));
    }

    fn comment(&mut self, text: &str) {
        self.tokens.push(CToken::comment(text));
    }

    fn finish(self) -> CTokenLine {
        CTokenLine::new(self.tokens, self.pc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlil::expr::{assign, binary, konst, var, HlilOp};

    #[test]
    fn simple_assign_tokens() {
        // x0 = (x1 + 42);
        let expr = assign(
            var(String::from("x0")),
            binary(HlilOp::Add, var(String::from("x1")), konst(42)),
            0x1000,
        );
        let lines = render_hlil_tokens(&[expr]);
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert_eq!(line.pc, 0x1000);

        // Check token kinds
        let kinds: Vec<CTokenKind> = line.tokens.iter().map(|t| t.kind).collect();
        // Expected: Var("x0") Op("=") Punct("(") Var("x1") Op("+") Literal("0x2a") Punct(")") Punct(";")
        assert!(kinds.contains(&CTokenKind::Var));
        assert!(kinds.contains(&CTokenKind::Op));
        assert!(kinds.contains(&CTokenKind::Literal));
        assert!(kinds.contains(&CTokenKind::Punct));

        // Check text reconstruction
        let text: String = line.tokens.iter().map(|t| t.text.as_str()).collect();
        assert!(text.contains("x0"));
        assert!(text.contains("x1"));
        assert!(text.contains("0x2a"));
        assert!(text.contains(";"));
    }

    #[test]
    fn var_tokens_have_var_id() {
        let expr = assign(var(String::from("x8_v1")), konst(0), 0x2000);
        let lines = render_hlil_tokens(&[expr]);
        let var_tok = lines[0]
            .tokens
            .iter()
            .find(|t| t.kind == CTokenKind::Var)
            .unwrap();
        assert_eq!(var_tok.var_id, Some("x8_v1".into()));
    }
}
