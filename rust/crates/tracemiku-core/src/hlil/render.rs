//! C-like rendering for HLIL — structured output with indentation.

use crate::hlil::expr::{HlilExpr, HlilOp, HlilOperand};

const MAX_RENDERED_NEGATIVE_ADDEND: u64 = 0x10000;

/// Render a sequence of HLIL expressions as C-like code.
pub fn render_hlil(exprs: &[HlilExpr]) -> String {
    let mut out = String::new();
    for e in exprs {
        render_expr_to(&mut out, e, 0);
    }
    out
}

fn render_expr_to(out: &mut String, e: &HlilExpr, indent: usize) {
    let prefix = "    ".repeat(indent);

    match e.op {
        HlilOp::Nop => {
            push_line(out, &prefix, &format!("/* {:#x}: nop */", e.pc));
        }
        HlilOp::Assign => {
            let dst = render_operand(e.operands.first());
            let val = render_operand(e.operands.get(1));
            push_line(out, &prefix, &format!("{dst} = {val};"));
        }
        HlilOp::VarDeclare => {
            let name = render_operand(e.operands.first());
            let ty = e.extra.get("type").map(String::as_str).unwrap_or("int64_t");
            push_line(out, &prefix, &format!("{ty} {name};"));
        }
        HlilOp::VarInit => {
            let name = render_operand(e.operands.first());
            let val = render_operand(e.operands.get(1));
            push_line(out, &prefix, &format!("int64_t {name} = {val};"));
        }

        // Structured control flow with indentation
        HlilOp::Block => {
            push_line(out, &prefix, "{");
            for child in &e.operands {
                if let HlilOperand::Expr(child_e) = child {
                    render_expr_to(out, child_e, indent + 1);
                }
            }
            push_line(out, &prefix, "}");
        }
        HlilOp::If => {
            let cond = render_operand(e.operands.first());
            let then_body = match e.operands.get(1) {
                Some(HlilOperand::Expr(ee)) => ee,
                _ => {
                    push_line(out, &prefix, &format!("if ({cond}) {{ /* ? */ }}"));
                    return;
                }
            };
            let else_body = match e.operands.get(2) {
                Some(HlilOperand::Expr(ee)) => Some(ee),
                _ => None,
            };

            if then_body.op == HlilOp::Block {
                push_line(out, &prefix, &format!("if ({cond})"));
                push_line(out, &prefix, "{");
                for child in &then_body.operands {
                    if let HlilOperand::Expr(ee) = child {
                        render_expr_to(out, ee, indent + 1);
                    }
                }
                if let Some(else_e) = else_body {
                    if else_e.op == HlilOp::Block {
                        push_line(out, &prefix, "}");
                        push_line(out, &prefix, "else");
                        push_line(out, &prefix, "{");
                        for child in &else_e.operands {
                            if let HlilOperand::Expr(ee) = child {
                                render_expr_to(out, ee, indent + 1);
                            }
                        }
                        push_line(out, &prefix, "}");
                    } else if else_e.op == HlilOp::If {
                        push_line(out, &prefix, "}");
                        push_line(
                            out,
                            &prefix,
                            &format!("else if ({})", render_operand(else_e.operands.first())),
                        );
                        // Handle chained else-if
                        // Simplified: just render the else
                    } else {
                        push_line(out, &prefix, "}");
                        push_line(out, &prefix, "else");
                        render_expr_to(out, else_e, indent + 1);
                    }
                } else {
                    push_line(out, &prefix, "}");
                }
            } else {
                push_line(out, &prefix, &format!("if ({cond})"));
                render_expr_to(out, then_body, indent + 1);
                if let Some(else_e) = else_body {
                    push_line(out, &prefix, "else");
                    render_expr_to(out, else_e, indent + 1);
                }
            }
        }
        HlilOp::While => {
            let cond = render_operand(e.operands.first());
            let body = match e.operands.get(1) {
                Some(HlilOperand::Expr(ee)) => ee,
                _ => {
                    push_line(out, &prefix, &format!("while ({cond}) {{ }}"));
                    return;
                }
            };
            push_line(out, &prefix, &format!("while ({cond})"));
            if body.op == HlilOp::Block {
                push_line(out, &prefix, "{");
                for child in &body.operands {
                    if let HlilOperand::Expr(ee) = child {
                        render_expr_to(out, ee, indent + 1);
                    }
                }
                push_line(out, &prefix, "}");
            } else {
                push_line(out, &prefix, "{");
                render_expr_to(out, body, indent + 1);
                push_line(out, &prefix, "}");
            }
        }
        HlilOp::DoWhile => {
            let body = match e.operands.first() {
                Some(HlilOperand::Expr(ee)) => ee,
                _ => {
                    push_line(out, &prefix, "do { } while (?);");
                    return;
                }
            };
            let cond = render_operand(e.operands.get(1));
            push_line(out, &prefix, "do");
            if body.op == HlilOp::Block {
                push_line(out, &prefix, "{");
                for child in &body.operands {
                    if let HlilOperand::Expr(ee) = child {
                        render_expr_to(out, ee, indent + 1);
                    }
                }
                push_line(out, &prefix, &format!("}} while ({cond});"));
            } else {
                render_expr_to(out, body, indent + 1);
                push_line(out, &prefix, &format!("while ({cond});"));
            }
        }
        HlilOp::For => {
            let init = render_for_clause(e.operands.first());
            let cond = render_for_clause(e.operands.get(1));
            let update = render_for_clause(e.operands.get(2));
            let body = match e.operands.get(3) {
                Some(HlilOperand::Expr(ee)) => ee,
                _ => {
                    push_line(
                        out,
                        &prefix,
                        &format!("for ({init}; {cond}; {update}) {{ }}"),
                    );
                    return;
                }
            };
            push_line(out, &prefix, &format!("for ({init}; {cond}; {update})"));
            render_block_like(out, body, indent);
        }
        HlilOp::Switch => {
            let selector = render_operand(e.operands.first());
            push_line(out, &prefix, &format!("switch ({selector})"));
            push_line(out, &prefix, "{");
            for op in e.operands.iter().skip(1) {
                if let HlilOperand::Expr(case_e) = op {
                    render_expr_to(out, case_e, indent + 1);
                }
            }
            push_line(out, &prefix, "}");
        }
        HlilOp::Case => {
            let label = match e.operands.first() {
                Some(HlilOperand::Str(s)) if s == "default" => "default".to_string(),
                other => format!("case {}", render_operand(other)),
            };
            push_line(out, &prefix, &format!("{label}:"));
            if let Some(HlilOperand::Expr(body)) = e.operands.get(1) {
                render_case_body(out, body, indent + 1);
            }
        }
        HlilOp::Break => {
            push_line(out, &prefix, "break;");
        }
        HlilOp::Continue => {
            push_line(out, &prefix, "continue;");
        }
        HlilOp::Goto => {
            let t = render_operand(e.operands.first());
            push_line(out, &prefix, &format!("goto loc_{t};"));
        }
        HlilOp::Label => {
            let name = render_operand(e.operands.first());
            push_line(out, &prefix.trim_end(), &format!("{name}:"));
        }
        HlilOp::Call => {
            let t = render_operand(e.operands.first());
            push_line(out, &prefix, &format!("{t}();"));
        }
        HlilOp::Ret => {
            push_line(out, &prefix, "return;");
        }
        HlilOp::Noret => {
            push_line(out, &prefix, "__noreturn();");
        }
        HlilOp::Unreachable => {
            push_line(out, &prefix, "__builtin_unreachable();");
        }
        HlilOp::Intrinsic => {
            let mnem = e.extra.get("mnem").map(String::as_str).unwrap_or("?");
            let args = e
                .operands
                .iter()
                .map(|o| render_operand(Some(o)))
                .collect::<Vec<_>>()
                .join(", ");
            push_line(out, &prefix, &format!("/* intrinsic {mnem}({args}) */"));
        }
        HlilOp::Deref => {
            let addr = render_operand(e.operands.first());
            push_line(out, &prefix, &format!("*({} *){addr};", c_type(e.size)));
        }
        HlilOp::DerefField => {
            let base = render_operand(e.operands.first());
            let offset = render_operand(e.operands.get(1));
            push_line(
                out,
                &prefix,
                &format!("*({} *)(({base}) + {offset}));", c_type(e.size)),
            );
        }
        HlilOp::Csel => {
            let c = render_operand(e.operands.first());
            let t = render_operand(e.operands.get(1));
            let f = render_operand(e.operands.get(2));
            push_line(out, &prefix, &format!("({c} ? {t} : {f});"));
        }
        HlilOp::Jump => {
            let t = render_operand(e.operands.first());
            push_line(out, &prefix, &format!("goto *{t};"));
        }
        HlilOp::Trap => {
            push_line(out, &prefix, "__builtin_trap();");
        }
        HlilOp::Bp => {
            push_line(out, &prefix, "__breakpoint();");
        }
        HlilOp::Unimpl => {
            push_line(out, &prefix, &format!("/* unimpl at {:#x} */", e.pc));
        }
        HlilOp::Undef => {
            push_line(out, &prefix, "/* undef */");
        }
        _ => push_line(out, &prefix, &format!("/* {} */", e.short())),
    }
}

fn push_line(out: &mut String, prefix: &str, line: &str) {
    out.push_str(prefix);
    out.push_str(line);
    out.push('\n');
}

fn render_block_like(out: &mut String, body: &HlilExpr, indent: usize) {
    let prefix = "    ".repeat(indent);
    push_line(out, &prefix, "{");
    if body.op == HlilOp::Block {
        for child in &body.operands {
            if let HlilOperand::Expr(ee) = child {
                render_expr_to(out, ee, indent + 1);
            }
        }
    } else {
        render_expr_to(out, body, indent + 1);
    }
    push_line(out, &prefix, "}");
}

fn render_case_body(out: &mut String, body: &HlilExpr, indent: usize) {
    if body.op == HlilOp::Block {
        for child in &body.operands {
            if let HlilOperand::Expr(ee) = child {
                render_expr_to(out, ee, indent);
            }
        }
    } else {
        render_expr_to(out, body, indent);
    }
}

fn render_for_clause(op: Option<&HlilOperand>) -> String {
    match op {
        Some(HlilOperand::Expr(e)) if e.op == HlilOp::Nop => String::new(),
        Some(HlilOperand::Expr(e)) if e.op == HlilOp::Assign => {
            let dst = render_operand(e.operands.first());
            let val = render_operand(e.operands.get(1));
            format!("{dst} = {val}")
        }
        other => render_operand(other),
    }
}

pub fn render_expr(e: &HlilExpr) -> String {
    match e.op {
        HlilOp::Var | HlilOp::Const | HlilOp::ConstPtr | HlilOp::ConstData => {
            render_operand(e.operands.first())
        }
        HlilOp::Deref => {
            format!(
                "*({} *)({})",
                c_type(e.size),
                render_operand(e.operands.first())
            )
        }
        HlilOp::DerefField => {
            let base = render_operand(e.operands.first());
            let offset = render_operand(e.operands.get(1));
            format!("*({} *)(({}) + {})", c_type(e.size), base, offset)
        }
        HlilOp::StructField => {
            format!(
                "{}.{}",
                render_operand(e.operands.first()),
                render_operand(e.operands.get(1))
            )
        }
        HlilOp::ArrayIndex => {
            format!(
                "{}[{}]",
                render_operand(e.operands.first()),
                render_operand(e.operands.get(1))
            )
        }
        HlilOp::AddressOf => format!("&{}", render_operand(e.operands.first())),
        HlilOp::AddressOfField => {
            format!(
                "&{}.{}",
                render_operand(e.operands.first()),
                render_operand(e.operands.get(1))
            )
        }
        HlilOp::Neg => render_neg(e.operands.first()),
        HlilOp::Not => format!("~{}", render_operand(e.operands.first())),
        HlilOp::Sx => format!(
            "((int{}_t)({}))",
            e.size * 8,
            render_operand(e.operands.first())
        ),
        HlilOp::Zx => format!(
            "((uint{}_t)({}))",
            e.size * 8,
            render_operand(e.operands.first())
        ),
        HlilOp::LowPart => format!(
            "((uint{}_t)({}))",
            e.size * 8,
            render_operand(e.operands.first())
        ),
        HlilOp::Csel => format!(
            "({} ? {} : {})",
            render_operand(e.operands.first()),
            render_operand(e.operands.get(1)),
            render_operand(e.operands.get(2))
        ),
        op if binary_symbol(op).is_some() => {
            let op_sym = binary_symbol(op).unwrap();
            if e.op == HlilOp::Add {
                if let (Some(left), Some(right)) = (e.operands.first(), e.operands.get(1)) {
                    let right_rendered = render_operand(Some(right));
                    if let Some(magnitude) =
                        negative_addend(right).or_else(|| negative_rendered_addend(&right_rendered))
                    {
                        return format!(
                            "({} - {})",
                            render_operand(Some(left)),
                            format_unsigned_literal(magnitude, 10)
                        );
                    }
                }
            }
            format!(
                "({} {} {})",
                render_operand(e.operands.first()),
                op_sym,
                render_operand(e.operands.get(1))
            )
        }
        HlilOp::Intrinsic => {
            let mnem = e.extra.get("mnem").map(String::as_str).unwrap_or("?");
            let args = e
                .operands
                .iter()
                .map(|o| render_operand(Some(o)))
                .collect::<Vec<_>>()
                .join(", ");
            if args.is_empty() || args == "?" {
                format!("{mnem}()")
            } else {
                format!("{mnem}({args})")
            }
        }
        _ => e.short(),
    }
}

fn render_operand(op: Option<&HlilOperand>) -> String {
    match op {
        Some(HlilOperand::Expr(e)) => render_expr(e),
        Some(HlilOperand::Var(v)) => v.clone(),
        Some(HlilOperand::Str(s)) => s.clone(),
        Some(HlilOperand::Imm(v)) => format_signed_literal(*v, 10),
        Some(HlilOperand::U64(v)) => format!("{v:#x}"),
        None => "?".to_string(),
    }
}

fn render_neg(op: Option<&HlilOperand>) -> String {
    let value = render_operand(op);
    if let Some(stripped) = value.strip_prefix('-') {
        stripped.to_string()
    } else {
        format!("-{value}")
    }
}

fn negative_addend(op: &HlilOperand) -> Option<u64> {
    match op {
        HlilOperand::Imm(v) if *v < 0 => {
            let magnitude = v.unsigned_abs();
            (magnitude <= MAX_RENDERED_NEGATIVE_ADDEND).then_some(magnitude)
        }
        HlilOperand::Expr(e) if matches!(e.op, HlilOp::Const | HlilOp::ConstPtr) => {
            e.operands.first().and_then(negative_addend)
        }
        _ => None,
    }
}

fn negative_rendered_addend(s: &str) -> Option<u64> {
    let trimmed = s.trim().trim_start_matches('(').trim_end_matches(')');
    let raw = trimmed.strip_prefix("0x")?;
    let value = u64::from_str_radix(raw, 16).ok()?;
    let signed = value as i64;
    if signed >= 0 {
        return None;
    }
    let magnitude = signed.unsigned_abs();
    (magnitude <= MAX_RENDERED_NEGATIVE_ADDEND).then_some(magnitude)
}

fn format_signed_literal(v: i64, hex_threshold: u64) -> String {
    if v < 0 {
        let magnitude = v.unsigned_abs();
        if magnitude >= hex_threshold {
            format!("-0x{magnitude:x}")
        } else {
            format!("-{magnitude}")
        }
    } else {
        format_unsigned_literal(v as u64, hex_threshold)
    }
}

fn format_unsigned_literal(v: u64, hex_threshold: u64) -> String {
    if v >= hex_threshold {
        format!("0x{v:x}")
    } else {
        v.to_string()
    }
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
        HlilOp::Rol => "rol",
        HlilOp::Ror => "ror",
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
        _ => "uint64_t",
    }
}

#[cfg(test)]
mod tests {
    use crate::hlil::expr::{
        assign, binary, block, deref, if_else, konst, ret, var, var_init, while_loop,
    };

    use super::*;

    #[test]
    fn renders_assign() {
        let a = assign(var("v0"), binary(HlilOp::Add, var("v1"), konst(2)), 0x1000);
        let rendered = render_hlil(&[a]);
        assert!(rendered.contains("v0 = (v1 + 2);"));
    }

    #[test]
    fn renders_if_else() {
        let cond = binary(HlilOp::CmpE, var("a"), konst(0));
        let then_body = block(vec![assign(var("b"), konst(1), 0x1004)], 0x1004);
        let else_body = block(vec![assign(var("b"), konst(0), 0x1008)], 0x1008);
        let if_hlil = if_else(cond, then_body, Some(else_body), 0x1000);
        let rendered = render_hlil(&[if_hlil]);
        assert!(rendered.contains("if ((a == 0))"));
        assert!(rendered.contains("b = 1;"));
        assert!(rendered.contains("b = 0;"));
    }

    #[test]
    fn renders_while_loop() {
        let cond = binary(HlilOp::CmpNe, var("i"), konst(0));
        let body = block(
            vec![assign(
                var("i"),
                binary(HlilOp::Sub, var("i"), konst(1)),
                0x1004,
            )],
            0x1000,
        );
        let w = while_loop(cond, body, 0x1000);
        let rendered = render_hlil(&[w]);
        assert!(rendered.contains("while ((i != 0))"));
        assert!(rendered.contains("i = (i - 1);"));
    }

    #[test]
    fn renders_return() {
        let rendered = render_hlil(&[ret(0x1000)]);
        assert!(rendered.contains("return;"));
    }

    #[test]
    fn renders_deref_in_assign() {
        let d = deref(8, var("ptr"), 0x1000);
        let a = assign(var("x"), d, 0x1000);
        let rendered = render_hlil(&[a]);
        assert!(rendered.contains("x = *(uint64_t *)(ptr);"));
    }

    #[test]
    fn renders_var_init() {
        let v = var_init("i", konst(0), 0x1000);
        let rendered = render_hlil(&[v]);
        assert!(rendered.contains("int64_t i = 0;"));
    }

    #[test]
    fn renders_full_decompile_output() {
        let exprs = vec![
            var_init("result", konst(0), 0x1000),
            var_init("i", konst(0), 0x1004),
            while_loop(
                binary(HlilOp::CmpUlt, var("i"), konst(10)),
                block(
                    vec![
                        assign(
                            var("result"),
                            binary(HlilOp::Add, var("result"), var("i")),
                            0x1008,
                        ),
                        assign(var("i"), binary(HlilOp::Add, var("i"), konst(1)), 0x100c),
                    ],
                    0x1008,
                ),
                0x1008,
            ),
            ret(0x1010),
        ];
        let rendered = render_hlil(&exprs);
        assert!(rendered.contains("int64_t result = 0;"), "got: {rendered}");
        assert!(rendered.contains("int64_t i = 0;"), "got: {rendered}");
        assert!(rendered.contains("while ("), "got: {rendered}");
        assert!(
            rendered.contains("result = (result + i);"),
            "got: {rendered}"
        );
        assert!(rendered.contains("return;"), "got: {rendered}");
    }
}
