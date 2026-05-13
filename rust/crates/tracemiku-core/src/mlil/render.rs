//! C-like rendering for MLIL.
//!
//! Produces variable-based, flag-free output with struct field access.

use crate::mlil::expr::{MlilExpr, MlilOp, MlilOperand};

const MAX_RENDERED_NEGATIVE_ADDEND: u64 = 0x10000;

pub fn render_mlil_block(exprs: &[MlilExpr]) -> String {
    let mut out = String::new();
    for e in exprs {
        out.push_str(&render_stmt(e));
        out.push('\n');
    }
    out
}

pub fn render_stmt(e: &MlilExpr) -> String {
    match e.op {
        MlilOp::Nop => format!("/* {:#x}: nop */", e.pc),
        MlilOp::SetVar => format!(
            "{} = {};",
            render_operand(e.operands.first()),
            render_operand(e.operands.get(1))
        ),
        MlilOp::SetVarField => format!(
            "{}.{} = {};",
            render_operand(e.operands.first()),
            e.operands.get(1).map(|o| render_operand(Some(o))).unwrap_or_default(),
            render_operand(e.operands.get(2))
        ),
        MlilOp::Store => format!(
            "*({} *)({}) = {};",
            c_type(e.size),
            render_operand(e.operands.first()),
            render_operand(e.operands.get(1))
        ),
        MlilOp::StoreStruct => {
            let base = render_operand(e.operands.first());
            let offset = render_operand(e.operands.get(1));
            let value = render_operand(e.operands.get(2));
            format!("*({} *)(({}) + {}) = {};", c_type(e.size), base, offset, value)
        }
        MlilOp::Goto => format!("goto loc_{};", render_target(e.operands.first())),
        MlilOp::Jump => format!("goto *{};", render_operand(e.operands.first())),
        MlilOp::If => format!(
            "if ({}) goto loc_{}; else goto loc_{};",
            render_operand(e.operands.first()),
            render_target(e.operands.get(1)),
            render_target(e.operands.get(2))
        ),
        MlilOp::Call => format!("{}();", render_operand(e.operands.first())),
        MlilOp::Tailcall => format!("tailcall {}();", render_operand(e.operands.first())),
        MlilOp::Ret => "return;".to_string(),
        MlilOp::Noret => "__noreturn();".to_string(),
        MlilOp::Intrinsic => format!(
            "/* intrinsic {} {} */",
            e.extra.get("mnem").map(String::as_str).unwrap_or("?"),
            e.operands
                .iter()
                .map(|o| render_operand(Some(o)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        MlilOp::Csel => format!(
            "({} ? {} : {})",
            render_operand(e.operands.first()),
            render_operand(e.operands.get(1)),
            render_operand(e.operands.get(2))
        ),
        MlilOp::Unimpl => format!(
            "/* UNIMPL: {} at {:#x} */",
            e.operands.first().map(|o| render_operand(Some(o))).unwrap_or_default(),
            e.pc
        ),
        _ => format!("{};", render_expr(e)),
    }
}

pub fn render_expr(e: &MlilExpr) -> String {
    match e.op {
        MlilOp::Var | MlilOp::Const | MlilOp::ConstPtr | MlilOp::ConstData => {
            render_operand(e.operands.first())
        }
        MlilOp::VarField => format!(
            "{}.{}",
            render_operand(e.operands.first()),
            e.operands.get(1).map(|o| render_operand(Some(o))).unwrap_or_default()
        ),
        MlilOp::Load => format!(
            "*({} *)({})",
            c_type(e.size),
            render_operand(e.operands.first())
        ),
        MlilOp::LoadStruct => {
            let base = render_operand(e.operands.first());
            let offset = render_operand(e.operands.get(1));
            format!("*({} *)(({}) + {})", c_type(e.size), base, offset)
        }
        MlilOp::AddressOf => format!("&{}", render_operand(e.operands.first())),
        MlilOp::AddressOfField => format!(
            "&{}.{}",
            render_operand(e.operands.first()),
            e.operands.get(1).map(|o| render_operand(Some(o))).unwrap_or_default()
        ),
        MlilOp::Neg => render_neg(e.operands.first()),
        MlilOp::Not => format!("~{}", render_operand(e.operands.first())),
        MlilOp::Sx => format!(
            "((int{}_t)({}))",
            e.size * 8,
            render_operand(e.operands.first())
        ),
        MlilOp::Zx => format!(
            "((uint{}_t)({}))",
            e.size * 8,
            render_operand(e.operands.first())
        ),
        MlilOp::LowPart => format!(
            "((uint{}_t)({}))",
            e.size * 8,
            render_operand(e.operands.first())
        ),
        MlilOp::Csel => format!(
            "({} ? {} : {})",
            render_operand(e.operands.first()),
            render_operand(e.operands.get(1)),
            render_operand(e.operands.get(2))
        ),
        op if binary_symbol(op).is_some() => {
            let op_sym = binary_symbol(op).unwrap();
            if e.op == MlilOp::Add {
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
        MlilOp::Undef => "/* undef */".to_string(),
        _ => e.short(),
    }
}

fn render_operand(op: Option<&MlilOperand>) -> String {
    match op {
        Some(MlilOperand::Expr(e)) => render_expr(e),
        Some(MlilOperand::Var(v)) => v.clone(),
        Some(MlilOperand::Str(s)) => s.clone(),
        Some(MlilOperand::Imm(v)) => format_signed_literal(*v, 10),
        Some(MlilOperand::U64(v)) => format!("{v:#x}"),
        None => "?".to_string(),
    }
}

fn render_neg(op: Option<&MlilOperand>) -> String {
    let value = render_operand(op);
    if let Some(stripped) = value.strip_prefix('-') {
        stripped.to_string()
    } else {
        format!("-{value}")
    }
}

fn negative_addend(op: &MlilOperand) -> Option<u64> {
    match op {
        MlilOperand::Imm(v) if *v < 0 => {
            let magnitude = v.unsigned_abs();
            (magnitude <= MAX_RENDERED_NEGATIVE_ADDEND).then_some(magnitude)
        }
        MlilOperand::Expr(e)
            if matches!(e.op, MlilOp::Const | MlilOp::ConstPtr) =>
        {
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

fn render_target(op: Option<&MlilOperand>) -> String {
    render_operand(op)
        .trim_start_matches("0x")
        .to_string()
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
        MlilOp::Rol => "rol",
        MlilOp::Ror => "ror",
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

#[cfg(test)]
mod tests {
    use crate::mlil::expr::{
        binary, const_ptr, expr as mlil_expr, konst, load, load_struct, set_var, set_var_field,
        store, store_struct, var, MlilExpr, MlilOp, MlilOperand,
    };

    use super::*;

    #[test]
    fn renders_set_var() {
        let s = set_var("arg_0", binary(MlilOp::Add, var("var_1"), konst(2)), 0x1000);
        assert_eq!(render_stmt(&s), "arg_0 = (var_1 + 2);");
    }

    #[test]
    fn renders_block() {
        let block = vec![
            set_var("v0", konst(1), 0x1000),
            MlilExpr::new(MlilOp::Ret, 8, vec![], 0x1004),
        ];
        assert_eq!(render_mlil_block(&block), "v0 = 1;\nreturn;\n");
    }

    #[test]
    fn renders_load_struct() {
        let l = load_struct(8, var("ptr"), 16, 0x1000);
        let rendered = render_stmt(&l);
        // LoadStruct renders as: *(type *)((base) + offset);
        assert!(rendered.contains("uint64_t"), "got: {rendered}");
        assert!(rendered.contains("ptr"), "got: {rendered}");
        assert!(rendered.contains("0x10"), "got: {rendered}");
    }

    #[test]
    fn renders_store_struct() {
        let s = store_struct(4, var("ptr"), 8, konst(42), 0x1000);
        assert_eq!(
            render_stmt(&s),
            "*(uint32_t *)((ptr) + 8) = 0x2a;"
        );
    }

    #[test]
    fn renders_if_condition() {
        let if_mlil = MlilExpr::new(
            MlilOp::If,
            1,
            vec![
                mlil_expr(binary(MlilOp::CmpE, var("v0"), konst(0))),
                MlilOperand::U64(0x2000),
                MlilOperand::U64(0x1008),
            ],
            0x1000,
        );
        assert_eq!(
            render_stmt(&if_mlil),
            "if ((v0 == 0)) goto loc_2000; else goto loc_1008;"
        );
    }

    #[test]
    fn renders_comparisons() {
        assert_eq!(render_expr(&binary(MlilOp::CmpNe, var("a"), konst(0))), "(a != 0)");
        assert_eq!(render_expr(&binary(MlilOp::CmpUlt, var("a"), var("b"))), "(a < b)");
    }

    #[test]
    fn renders_negative_as_subtraction() {
        let add_neg = set_var(
            "v0",
            binary(MlilOp::Add, var("sp"), konst(-0x20)),
            0x1000,
        );
        assert_eq!(render_stmt(&add_neg), "v0 = (sp - 0x20);");
    }

    #[test]
    fn renders_set_var_field() {
        let s = set_var_field("obj", 8, konst(42), 0x1000);
        assert_eq!(render_stmt(&s), "obj.8 = 0x2a;");
    }

    #[test]
    fn renders_full_mlil_sequence() {
        let block = vec![
            set_var("arg_0", konst(1), 0x1000),
            set_var(
                "result",
                binary(
                    MlilOp::Add,
                    load(8, var("arg_0"), 0x1004),
                    konst(10),
                ),
                0x1004,
            ),
            store(8, var("result"), var("arg_0"), 0x1008),
            MlilExpr::new(MlilOp::Ret, 8, vec![], 0x100c),
        ];
        let rendered = render_mlil_block(&block);
        assert!(rendered.contains("arg_0 = 1;"));
        assert!(rendered.contains("*"));
        assert!(rendered.contains("return;"));
    }
}
