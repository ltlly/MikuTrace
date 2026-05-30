//! C-like rendering for LLIL.

use crate::llil::expr::{LlilExpr, LlilOp, LlilOperand};
use crate::llil::VarNameMap;

const MAX_RENDERED_NEGATIVE_ADDEND: u64 = 0x10000;

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

/// Render a block, appending `// observed: ...` comments from trace data.
///
/// `annotations` maps an instruction PC to a description of the runtime value(s)
/// it produced. Each PC is annotated at most once (on its first surviving
/// statement) so multi-expr instructions don't repeat the comment.
pub fn render_llil_block_with_names_annotated(
    exprs: &[LlilExpr],
    names: &VarNameMap,
    annotations: &std::collections::BTreeMap<u64, String>,
) -> String {
    let mut out = String::new();
    let mut done: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for e in exprs {
        out.push_str(&render_stmt_with_names(e, names));
        if let Some(anno) = annotations.get(&e.pc) {
            if done.insert(e.pc) {
                out.push_str("  // observed: ");
                out.push_str(anno);
            }
        }
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
        LlilOp::Csel => format!(
            "({} ? {} : {});",
            render_operand(e.operands.first(), names),
            render_operand(e.operands.get(1), names),
            render_operand(e.operands.get(2), names)
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
        LlilOp::Neg => render_neg(e.operands.first(), names),
        LlilOp::Not => format!("~{}", render_operand(e.operands.first(), names)),
        LlilOp::Sx => format!(
            "((int{}_t)({}) )",
            e.size * 8,
            render_operand(e.operands.first(), names)
        ),
        LlilOp::Zx => format!(
            "((uint{}_t)({}))",
            e.size * 8,
            render_operand(e.operands.first(), names)
        ),
        LlilOp::LowPart => format!(
            "((uint{}_t)({}))",
            e.size * 8,
            render_operand(e.operands.first(), names)
        ),
        LlilOp::Csel => format!(
            "({} ? {} : {})",
            render_operand(e.operands.first(), names),
            render_operand(e.operands.get(1), names),
            render_operand(e.operands.get(2), names)
        ),
        op if binary_symbol(op).is_some() => {
            if e.op == LlilOp::Add {
                if let (Some(left), Some(right)) = (e.operands.first(), e.operands.get(1)) {
                    let right_rendered = render_operand(Some(right), names);
                    if let Some(magnitude) =
                        negative_addend(right).or_else(|| negative_rendered_addend(&right_rendered))
                    {
                        return format!(
                            "({} - {})",
                            render_operand(Some(left), names),
                            format_unsigned_literal(magnitude, 10)
                        );
                    }
                }
            }
            format!(
                "({} {} {})",
                render_operand(e.operands.first(), names),
                binary_symbol(op).unwrap(),
                render_operand(e.operands.get(1), names)
            )
        }
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

fn render_neg(op: Option<&LlilOperand>, names: &VarNameMap) -> String {
    let value = render_operand(op, names);
    if let Some(stripped) = value.strip_prefix('-') {
        stripped.to_string()
    } else {
        format!("-{value}")
    }
}

fn render_operand(op: Option<&LlilOperand>, names: &VarNameMap) -> String {
    match op {
        Some(LlilOperand::Expr(e)) => render_expr_with_names(e, names),
        Some(LlilOperand::Reg(r)) | Some(LlilOperand::Flag(r)) => render_ident(r, names),
        Some(LlilOperand::Str(s)) => s.clone(),
        Some(LlilOperand::Imm(v)) => format_signed_literal(*v, 10),
        Some(LlilOperand::U64(v)) => format!("{v:#x}"),
        None => "?".to_string(),
    }
}

fn negative_addend(op: &LlilOperand) -> Option<u64> {
    match op {
        LlilOperand::Imm(v) if *v < 0 => {
            let magnitude = v.unsigned_abs();
            (magnitude <= MAX_RENDERED_NEGATIVE_ADDEND).then_some(magnitude)
        }
        LlilOperand::U64(v) => negative_u64_addend(*v),
        LlilOperand::Expr(e) if matches!(e.op, LlilOp::Const | LlilOp::ConstPtr) => {
            e.operands.first().and_then(negative_addend)
        }
        _ => None,
    }
}

fn negative_rendered_addend(s: &str) -> Option<u64> {
    let trimmed = s.trim().trim_start_matches('(').trim_end_matches(')');
    let raw = trimmed.strip_prefix("0x")?;
    let value = u64::from_str_radix(raw, 16).ok()?;
    negative_u64_addend(value)
}

fn negative_u64_addend(value: u64) -> Option<u64> {
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
    use crate::llil::expr::{
        binary, const_ptr, expr as operand_expr, konst, reg, set_reg, LlilExpr, LlilOp, LlilOperand,
    };

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

    #[test]
    fn renders_negative_stack_offsets_as_subtraction() {
        let stmt = set_reg(
            "x0#0",
            binary(LlilOp::Add, reg("fp#2"), konst(-0x28)),
            0x1000,
        );
        assert_eq!(render_stmt(&stmt), "x0_0 = (fp_2 - 0x28);");
    }

    #[test]
    fn renders_twos_complement_stack_offsets_as_subtraction() {
        let addr = LlilExpr::new(
            LlilOp::Add,
            8,
            vec![
                operand_expr(reg("fp#2")),
                LlilOperand::U64(0xffff_ffff_ffff_ffe4),
            ],
            0,
        );
        let load = LlilExpr::new(LlilOp::Load, 4, vec![operand_expr(addr)], 0);
        let stmt = set_reg("x8#27", load, 0x1000);
        assert_eq!(render_stmt(&stmt), "x8_27 = *(uint32_t *)((fp_2 - 0x1c));");
    }

    #[test]
    fn renders_store_constptr_stack_offsets_as_subtraction() {
        let addr = binary(LlilOp::Add, reg("fp#2"), const_ptr(0xffff_ffff_ffff_fff4));
        let stmt = LlilExpr::new(
            LlilOp::Store,
            4,
            vec![operand_expr(addr), operand_expr(reg("x8#17"))],
            0x1000,
        );
        assert_eq!(render_stmt(&stmt), "*(uint32_t *)((fp_2 - 0xc)) = x8_17;");
    }

    #[test]
    fn rendered_negative_addend_only_accepts_sign_extended_offsets() {
        assert_eq!(negative_rendered_addend("0xfffffffffffffff4"), Some(0xc));
        assert_eq!(negative_rendered_addend("0xffffffff80000000"), None);
        assert_eq!(negative_rendered_addend("0xffffffff00000001"), None);
        assert_eq!(negative_rendered_addend("0x8000000000000001"), None);
    }

    #[test]
    fn u64_negative_addend_rejects_wide_offsets() {
        let stmt = set_reg(
            "x0#0",
            LlilExpr::new(
                LlilOp::Add,
                8,
                vec![
                    operand_expr(reg("fp#2")),
                    LlilOperand::U64(0xffff_ffff_8000_0000),
                ],
                0,
            ),
            0x1000,
        );
        assert_eq!(render_stmt(&stmt), "x0_0 = (fp_2 + 0xffffffff80000000);");
    }

    #[test]
    fn renders_negated_negative_literal_without_double_minus() {
        let stmt = set_reg(
            "x0#0",
            crate::llil::expr::unary(LlilOp::Neg, konst(-5)),
            0x1000,
        );
        assert_eq!(render_stmt(&stmt), "x0_0 = 5;");
    }
}
