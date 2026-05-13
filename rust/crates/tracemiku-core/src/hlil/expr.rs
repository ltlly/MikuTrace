//! HLIL expression tree — high-level, structured control flow.
//!
//! Mirrors Binary Ninja HLIL: structured if/while/for, variable declarations,
//! dereference instead of raw loads, and C-like expression semantics.

use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HlilOp {
    Nop,
    Undef,
    Unimpl,

    // --- Structured control flow ---
    Block,
    If,
    While,
    DoWhile,
    For,
    Switch,
    Case,

    // --- Loop control ---
    Break,
    Continue,

    // --- Variables ---
    VarDeclare,
    VarInit,
    Assign,
    Var,

    // --- Constants ---
    Const,
    ConstPtr,
    ConstData,

    // --- Dereference (replaces Load) ---
    Deref,
    DerefField,

    // --- Struct field access ---
    StructField,

    // --- Array access ---
    ArrayIndex,

    // --- Arithmetic ---
    Add,
    Sub,
    Mul,
    DivS,
    DivU,
    ModS,
    ModU,
    Neg,
    And,
    Or,
    Xor,
    Not,
    Lsl,
    Lsr,
    Asr,
    Rol,
    Ror,

    // --- Extend/truncate ---
    Sx,
    Zx,
    LowPart,

    // --- Comparisons ---
    CmpE,
    CmpNe,
    CmpSlt,
    CmpSle,
    CmpSge,
    CmpSgt,
    CmpUlt,
    CmpUle,
    CmpUge,
    CmpUgt,

    // --- Address ---
    AddressOf,
    AddressOfField,

    // --- Unstructured fallback ---
    Goto,
    Label,
    Jump,

    // --- Calls ---
    Call,
    Tailcall,
    Ret,
    Noret,

    // --- Other ---
    Intrinsic,
    Trap,
    Bp,
    Csel,
    Unreachable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum HlilOperand {
    Expr(Box<HlilExpr>),
    Var(String),
    Imm(i64),
    U64(u64),
    Str(String),
}

/// A high-level IL expression. For structured control flow ops (If, While,
/// For, etc.), `operands` carries the body as nested HlilExpr trees rather
/// than flat sequences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HlilExpr {
    pub op: HlilOp,
    pub size: u8,
    pub operands: Vec<HlilOperand>,
    pub extra: BTreeMap<String, String>,
    pub pc: u64,
}

impl HlilExpr {
    pub fn new(op: HlilOp, size: u8, operands: Vec<HlilOperand>, pc: u64) -> Self {
        Self {
            op,
            size,
            operands,
            extra: BTreeMap::new(),
            pc,
        }
    }

    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }

    pub fn is_control_flow(&self) -> bool {
        matches!(
            self.op,
            HlilOp::If
                | HlilOp::While
                | HlilOp::DoWhile
                | HlilOp::For
                | HlilOp::Switch
                | HlilOp::Goto
                | HlilOp::Jump
                | HlilOp::Ret
                | HlilOp::Noret
                | HlilOp::Tailcall
                | HlilOp::Break
                | HlilOp::Continue
                | HlilOp::Unreachable
        )
    }

    pub fn has_side_effect(&self) -> bool {
        matches!(
            self.op,
            HlilOp::Assign
                | HlilOp::Call
                | HlilOp::Tailcall
                | HlilOp::Ret
                | HlilOp::Noret
                | HlilOp::Goto
                | HlilOp::Jump
                | HlilOp::Intrinsic
                | HlilOp::Trap
                | HlilOp::Bp
                | HlilOp::Unimpl
        )
    }

    pub fn short(&self) -> String {
        let first = || self.operands.first();
        let second = || self.operands.get(1);
        match self.op {
            HlilOp::Nop => "nop".to_string(),
            HlilOp::Var => fmt_operand(first()),
            HlilOp::Const => fmt_operand(first()),
            HlilOp::ConstPtr => format!("ptr({})", fmt_operand(first())),
            HlilOp::ConstData => format!("data({})", fmt_operand(first())),
            HlilOp::Assign => format!(
                "{} = {}",
                fmt_operand(first()),
                fmt_operand(second())
            ),
            HlilOp::VarDeclare => format!("var {}", fmt_operand(first())),
            HlilOp::VarInit => format!(
                "var {} = {}",
                fmt_operand(first()),
                fmt_operand(second())
            ),
            HlilOp::Deref => format!(
                "*({})",
                fmt_operand(first())
            ),
            HlilOp::DerefField => format!(
                "*({}.{})",
                fmt_operand(first()),
                fmt_operand(second())
            ),
            HlilOp::StructField => format!(
                "{}.{}",
                fmt_operand(first()),
                fmt_operand(second())
            ),
            HlilOp::ArrayIndex => format!(
                "{}[{}]",
                fmt_operand(first()),
                fmt_operand(second())
            ),
            HlilOp::If => format!("if ({})", fmt_operand(first())),
            HlilOp::While => format!("while ({})", fmt_operand(first())),
            HlilOp::DoWhile => format!("do {{ ... }} while ({})", fmt_operand(first())),
            HlilOp::For => format!("for (;;)"),
            HlilOp::Switch => format!("switch ({})", fmt_operand(first())),
            HlilOp::Case => format!("case {}", fmt_operand(first())),
            HlilOp::Break => "break".to_string(),
            HlilOp::Continue => "continue".to_string(),
            HlilOp::Goto => format!("goto {}", fmt_operand(first())),
            HlilOp::Label => format!("{}:", fmt_operand(first())),
            HlilOp::Jump => format!("goto *{}", fmt_operand(first())),
            HlilOp::Call => format!("{}()", fmt_operand(first())),
            HlilOp::Ret => "return".to_string(),
            HlilOp::Noret => "__noreturn()".to_string(),
            HlilOp::Unreachable => "__unreachable()".to_string(),
            HlilOp::Block => "{{ ... }}".to_string(),
            HlilOp::Csel => format!(
                "({} ? {} : {})",
                fmt_operand(first()),
                fmt_operand(second()),
                fmt_operand(self.operands.get(2))
            ),
            op if is_simple_binary(op) => format!(
                "({} {} {})",
                fmt_operand(first()),
                op_symbol(op),
                fmt_operand(second())
            ),
            op if is_simple_unary(op) => format!(
                "{}({})",
                op_symbol(op),
                fmt_operand(first())
            ),
            _ => format!("{:?}", self.op),
        }
    }
}

// --- Constructors ---

pub fn nop() -> HlilExpr {
    HlilExpr::new(HlilOp::Nop, 0, vec![], 0)
}

pub fn var(name: impl Into<String>) -> HlilExpr {
    HlilExpr::new(HlilOp::Var, 8, vec![HlilOperand::Var(name.into())], 0)
}

pub fn konst(value: i64) -> HlilExpr {
    HlilExpr::new(HlilOp::Const, 8, vec![HlilOperand::Imm(value)], 0)
}

pub fn const_ptr(value: u64) -> HlilExpr {
    HlilExpr::new(HlilOp::ConstPtr, 8, vec![HlilOperand::U64(value)], 0)
}

pub fn const_data(value: u64) -> HlilExpr {
    HlilExpr::new(HlilOp::ConstData, 8, vec![HlilOperand::U64(value)], 0)
}

pub fn expr(e: HlilExpr) -> HlilOperand {
    HlilOperand::Expr(Box::new(e))
}

pub fn assign(dst: HlilExpr, value: HlilExpr, pc: u64) -> HlilExpr {
    let size = value.size;
    HlilExpr::new(HlilOp::Assign, size, vec![expr(dst), expr(value)], pc)
}

pub fn var_declare(name: impl Into<String>, ty: impl Into<String>, pc: u64) -> HlilExpr {
    let name_str = name.into();
    let mut e = HlilExpr::new(
        HlilOp::VarDeclare,
        0,
        vec![HlilOperand::Var(name_str)],
        pc,
    );
    e.extra.insert("type".into(), ty.into());
    e
}

pub fn var_init(name: impl Into<String>, value: HlilExpr, pc: u64) -> HlilExpr {
    let size = value.size;
    HlilExpr::new(
        HlilOp::VarInit,
        size,
        vec![HlilOperand::Var(name.into()), expr(value)],
        pc,
    )
}

pub fn block(body: Vec<HlilExpr>, pc: u64) -> HlilExpr {
    let ops: Vec<HlilOperand> = body.into_iter().map(|e| expr(e)).collect();
    HlilExpr::new(HlilOp::Block, 0, ops, pc)
}

pub fn if_else(cond: HlilExpr, then_body: HlilExpr, else_body: Option<HlilExpr>, pc: u64) -> HlilExpr {
    let mut ops = vec![expr(cond), expr(then_body)];
    if let Some(e) = else_body {
        ops.push(expr(e));
    }
    HlilExpr::new(HlilOp::If, 1, ops, pc)
}

pub fn while_loop(cond: HlilExpr, body: HlilExpr, pc: u64) -> HlilExpr {
    HlilExpr::new(HlilOp::While, 1, vec![expr(cond), expr(body)], pc)
}

pub fn do_while(body: HlilExpr, cond: HlilExpr, pc: u64) -> HlilExpr {
    HlilExpr::new(
        HlilOp::DoWhile,
        1,
        vec![expr(body), expr(cond)],
        pc,
    )
}

pub fn goto(target: u64, pc: u64) -> HlilExpr {
    HlilExpr::new(
        HlilOp::Goto,
        8,
        vec![HlilOperand::U64(target)],
        pc,
    )
}

pub fn label(name: impl Into<String>, pc: u64) -> HlilExpr {
    HlilExpr::new(
        HlilOp::Label,
        0,
        vec![HlilOperand::Str(name.into())],
        pc,
    )
}

pub fn ret(pc: u64) -> HlilExpr {
    HlilExpr::new(HlilOp::Ret, 8, vec![], pc)
}

pub fn unreachable(pc: u64) -> HlilExpr {
    HlilExpr::new(HlilOp::Unreachable, 0, vec![], pc)
}

pub fn break_(pc: u64) -> HlilExpr {
    HlilExpr::new(HlilOp::Break, 0, vec![], pc)
}

pub fn continue_(pc: u64) -> HlilExpr {
    HlilExpr::new(HlilOp::Continue, 0, vec![], pc)
}

pub fn call(target: HlilExpr, pc: u64) -> HlilExpr {
    HlilExpr::new(HlilOp::Call, 8, vec![expr(target)], pc)
}

pub fn deref(size: u8, addr: HlilExpr, pc: u64) -> HlilExpr {
    HlilExpr::new(HlilOp::Deref, size, vec![expr(addr)], pc)
}

pub fn deref_field(
    size: u8,
    base: HlilExpr,
    offset: i64,
    pc: u64,
) -> HlilExpr {
    HlilExpr::new(
        HlilOp::DerefField,
        size,
        vec![expr(base), HlilOperand::Imm(offset)],
        pc,
    )
}

pub fn struct_field(base: HlilExpr, offset: i64) -> HlilExpr {
    HlilExpr::new(
        HlilOp::StructField,
        8,
        vec![expr(base), HlilOperand::Imm(offset)],
        0,
    )
}

pub fn array_index(base: HlilExpr, index: HlilExpr) -> HlilExpr {
    HlilExpr::new(
        HlilOp::ArrayIndex,
        base.size,
        vec![expr(base), expr(index)],
        0,
    )
}

pub fn binary(op: HlilOp, left: HlilExpr, right: HlilExpr) -> HlilExpr {
    let size = left.size.max(right.size);
    HlilExpr::new(op, size, vec![expr(left), expr(right)], 0)
}

pub fn unary(op: HlilOp, value: HlilExpr) -> HlilExpr {
    let size = value.size;
    HlilExpr::new(op, size, vec![expr(value)], 0)
}

pub fn sx(size: u8, value: HlilExpr) -> HlilExpr {
    HlilExpr::new(HlilOp::Sx, size, vec![expr(value)], 0)
}

pub fn zx(size: u8, value: HlilExpr) -> HlilExpr {
    HlilExpr::new(HlilOp::Zx, size, vec![expr(value)], 0)
}

pub fn low_part(size: u8, value: HlilExpr) -> HlilExpr {
    HlilExpr::new(HlilOp::LowPart, size, vec![expr(value)], 0)
}

pub fn address_of(value: HlilExpr) -> HlilExpr {
    HlilExpr::new(HlilOp::AddressOf, 8, vec![expr(value)], 0)
}

pub fn address_of_field(base: HlilExpr, offset: i64) -> HlilExpr {
    HlilExpr::new(
        HlilOp::AddressOfField,
        8,
        vec![expr(base), HlilOperand::Imm(offset)],
        0,
    )
}

// --- Helpers ---

fn fmt_operand(op: Option<&HlilOperand>) -> String {
    match op {
        Some(HlilOperand::Expr(e)) => e.short(),
        Some(HlilOperand::Var(v)) => v.clone(),
        Some(HlilOperand::Str(s)) => s.clone(),
        Some(HlilOperand::Imm(v)) => fmt_signed_literal(*v, 16),
        Some(HlilOperand::U64(v)) => format!("{v:#x}"),
        None => "?".to_string(),
    }
}

fn fmt_signed_literal(v: i64, hex_threshold: u64) -> String {
    if v < 0 {
        let magnitude = v.unsigned_abs();
        if magnitude >= hex_threshold {
            format!("-0x{magnitude:x}")
        } else {
            format!("-{magnitude}")
        }
    } else if (v as u64) >= hex_threshold {
        format!("0x{v:x}")
    } else {
        v.to_string()
    }
}

fn is_simple_binary(op: HlilOp) -> bool {
    matches!(
        op,
        HlilOp::Add
            | HlilOp::Sub
            | HlilOp::Mul
            | HlilOp::DivS
            | HlilOp::DivU
            | HlilOp::ModS
            | HlilOp::ModU
            | HlilOp::And
            | HlilOp::Or
            | HlilOp::Xor
            | HlilOp::Lsl
            | HlilOp::Lsr
            | HlilOp::Asr
            | HlilOp::Rol
            | HlilOp::Ror
            | HlilOp::CmpE
            | HlilOp::CmpNe
            | HlilOp::CmpSlt
            | HlilOp::CmpSle
            | HlilOp::CmpSge
            | HlilOp::CmpSgt
            | HlilOp::CmpUlt
            | HlilOp::CmpUle
            | HlilOp::CmpUge
            | HlilOp::CmpUgt
    )
}

fn is_simple_unary(op: HlilOp) -> bool {
    matches!(op, HlilOp::Neg | HlilOp::Not)
}

fn op_symbol(op: HlilOp) -> &'static str {
    match op {
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
        HlilOp::Neg => "-",
        HlilOp::Not => "~",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_constructors() {
        assert_eq!(var("v0").op, HlilOp::Var);
        assert_eq!(konst(42).op, HlilOp::Const);
        assert_eq!(ret(0x1000).op, HlilOp::Ret);
    }

    #[test]
    fn assign_short_display() {
        let a = assign(var("v0"), binary(HlilOp::Add, var("v1"), konst(2)), 0x1000);
        assert_eq!(a.short(), "v0 = (v1 + 2)");
    }

    #[test]
    fn if_else_short() {
        let cond = binary(HlilOp::CmpE, var("a"), konst(0));
        let then_body = assign(var("b"), konst(0x10), 0x1004);
        let else_body = assign(var("b"), konst(0), 0x1008);
        let if_hlil = if_else(cond, then_body, Some(else_body), 0x1000);
        assert_eq!(if_hlil.short(), "if ((a == 0))");
    }

    #[test]
    fn while_short() {
        let cond = binary(HlilOp::CmpNe, var("i"), konst(0));
        let body = assign(var("i"), binary(HlilOp::Sub, var("i"), konst(10)), 0x1004);
        let w = while_loop(cond, body, 0x1000);
        assert_eq!(w.short(), "while ((i != 0))");
    }

    #[test]
    fn deref_and_struct_field() {
        let d = deref(8, var("ptr"), 0x1000);
        assert_eq!(d.short(), "*(ptr)");

        let sf = struct_field(var("obj"), 16);
        assert_eq!(sf.short(), "obj.0x10");
    }

    #[test]
    fn block_contains_children() {
        let body = vec![
            assign(var("x"), konst(1), 0x1000),
            assign(var("y"), konst(2), 0x1004),
        ];
        let b = block(body, 0x1000);
        assert_eq!(b.op, HlilOp::Block);
        assert_eq!(b.operands.len(), 2);
    }

    #[test]
    fn control_flow_detection() {
        assert!(if_else(konst(1), nop(), None, 0).is_control_flow());
        assert!(while_loop(konst(1), nop(), 0).is_control_flow());
        assert!(!assign(var("x"), konst(1), 0).is_control_flow());
    }
}
