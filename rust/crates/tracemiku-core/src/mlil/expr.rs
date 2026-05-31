//! MLIL expression tree — medium-level, variable-based, flag-free.
//!
//! Mirrors Binary Ninja MLIL: registers become sized variables, flags are
//! folded into direct comparisons, and struct access is explicit.

use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MlilOp {
    Nop,
    Undef,
    Unimpl,

    // --- Variable-based (mirrors BN MLIL SET_VAR / VAR) ---
    SetVar,
    Var,
    SetVarField,
    VarField,

    // --- Constants ---
    Const,
    ConstPtr,
    ConstData,

    // --- Memory ---
    Load,
    Store,
    LoadStruct,
    StoreStruct,

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

    // --- Sign/zero extend ---
    Sx,
    Zx,
    LowPart,

    // --- Comparisons (inline, no flags) ---
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

    // --- Pointer ---
    AddressOf,
    AddressOfField,

    // --- Control flow ---
    Goto,
    Jump,
    If,
    Call,
    Tailcall,
    Ret,
    Noret,

    // --- Intrinsic / trap ---
    Intrinsic,
    Trap,
    Bp,

    // --- Structured select ---
    Csel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum MlilOperand {
    Expr(Box<MlilExpr>),
    Var(String),
    Imm(i64),
    U64(u64),
    Str(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MlilExpr {
    pub op: MlilOp,
    pub size: u8,
    pub operands: Vec<MlilOperand>,
    pub extra: BTreeMap<String, String>,
    pub pc: u64,
}

impl MlilExpr {
    pub fn new(op: MlilOp, size: u8, operands: Vec<MlilOperand>, pc: u64) -> Self {
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

    pub fn has_side_effect(&self) -> bool {
        matches!(
            self.op,
            MlilOp::Store
                | MlilOp::StoreStruct
                | MlilOp::Call
                | MlilOp::Tailcall
                | MlilOp::Ret
                | MlilOp::Noret
                | MlilOp::Goto
                | MlilOp::Jump
                | MlilOp::If
                | MlilOp::Intrinsic
                | MlilOp::Trap
                | MlilOp::Bp
                | MlilOp::Unimpl
        )
    }

    pub fn is_control_flow(&self) -> bool {
        matches!(
            self.op,
            MlilOp::Goto
                | MlilOp::Jump
                | MlilOp::If
                | MlilOp::Ret
                | MlilOp::Noret
                | MlilOp::Tailcall
        )
    }

    pub fn short(&self) -> String {
        let first = || self.operands.first();
        let second = || self.operands.get(1);
        match self.op {
            MlilOp::Nop => "nop".to_string(),
            MlilOp::Var => format!("var({})", fmt_operand(first())),
            MlilOp::Const => fmt_operand(first()),
            MlilOp::ConstPtr => format!("ptr({})", fmt_operand(first())),
            MlilOp::ConstData => format!("data({})", fmt_operand(first())),
            MlilOp::SetVar => format!("{} = {}", fmt_operand(first()), fmt_operand(second())),
            MlilOp::SetVarField => format!(
                "{}.{} = {}",
                fmt_operand(first()),
                fmt_operand(self.operands.get(1)),
                fmt_operand(self.operands.get(2))
            ),
            MlilOp::Load => format!("load.{}({})", self.size, fmt_operand(first())),
            MlilOp::Store => format!(
                "store.{}({}, {})",
                self.size,
                fmt_operand(first()),
                fmt_operand(second())
            ),
            MlilOp::LoadStruct => format!(
                "load_struct.{}({}, offset={})",
                self.size,
                fmt_operand(first()),
                fmt_operand(second())
            ),
            MlilOp::StoreStruct => format!(
                "store_struct.{}({}, offset={}, {})",
                self.size,
                fmt_operand(first()),
                fmt_operand(second()),
                fmt_operand(self.operands.get(2))
            ),
            MlilOp::Goto => format!("goto {}", fmt_operand(first())),
            MlilOp::If => format!(
                "if {} then {} else {}",
                fmt_operand(first()),
                fmt_operand(second()),
                fmt_operand(self.operands.get(2))
            ),
            MlilOp::Call => format!("call({})", fmt_operand(first())),
            MlilOp::Ret => "ret".to_string(),
            MlilOp::Noret => "noret".to_string(),
            MlilOp::Csel => format!(
                "csel({}, {}, {})",
                fmt_operand(first()),
                fmt_operand(second()),
                fmt_operand(self.operands.get(2))
            ),
            MlilOp::Intrinsic => {
                let mnem = self.extra.get("mnem").map(String::as_str).unwrap_or("?");
                format!("intrinsic({mnem})")
            }
            MlilOp::Sx => format!("sx.{}({})", self.size, fmt_operand(first())),
            MlilOp::Zx => format!("zx.{}({})", self.size, fmt_operand(first())),
            MlilOp::LowPart => format!("low_part({})", fmt_operand(first())),
            MlilOp::AddressOf => format!("&({})", fmt_operand(first())),
            MlilOp::AddressOfField => {
                format!("&({}.{})", fmt_operand(first()), fmt_operand(second()))
            }
            MlilOp::VarField => format!("{}.{}", fmt_operand(first()), fmt_operand(second())),
            op if is_binary(op) => format!(
                "({} {} {})",
                fmt_operand(first()),
                op_symbol(op),
                fmt_operand(second())
            ),
            op if is_unary(op) => format!("{}({})", op_symbol(op), fmt_operand(first())),
            _ => format!("{:?}", self.op),
        }
    }
}

// --- Constructors ---

pub fn var(name: impl Into<String>) -> MlilExpr {
    MlilExpr::new(MlilOp::Var, 8, vec![MlilOperand::Var(name.into())], 0)
}

pub fn konst(value: i64) -> MlilExpr {
    MlilExpr::new(MlilOp::Const, 8, vec![MlilOperand::Imm(value)], 0)
}

pub fn const_ptr(value: u64) -> MlilExpr {
    MlilExpr::new(MlilOp::ConstPtr, 8, vec![MlilOperand::U64(value)], 0)
}

pub fn const_data(value: u64) -> MlilExpr {
    MlilExpr::new(MlilOp::ConstData, 8, vec![MlilOperand::U64(value)], 0)
}

pub fn expr(e: MlilExpr) -> MlilOperand {
    MlilOperand::Expr(Box::new(e))
}

pub fn set_var(dst: impl Into<String>, value: MlilExpr, pc: u64) -> MlilExpr {
    let size = value.size;
    MlilExpr::new(
        MlilOp::SetVar,
        size,
        vec![MlilOperand::Var(dst.into()), expr(value)],
        pc,
    )
}

pub fn set_var_field(dst: impl Into<String>, offset: i64, value: MlilExpr, pc: u64) -> MlilExpr {
    let size = value.size;
    MlilExpr::new(
        MlilOp::SetVarField,
        size,
        vec![
            MlilOperand::Var(dst.into()),
            MlilOperand::Imm(offset),
            expr(value),
        ],
        pc,
    )
}

pub fn unary(op: MlilOp, value: MlilExpr) -> MlilExpr {
    let size = value.size;
    MlilExpr::new(op, size, vec![expr(value)], 0)
}

pub fn binary(op: MlilOp, left: MlilExpr, right: MlilExpr) -> MlilExpr {
    let size = left.size.max(right.size);
    MlilExpr::new(op, size, vec![expr(left), expr(right)], 0)
}

pub fn load(size: u8, addr: MlilExpr, pc: u64) -> MlilExpr {
    MlilExpr::new(MlilOp::Load, size, vec![expr(addr)], pc)
}

pub fn store(size: u8, addr: MlilExpr, value: MlilExpr, pc: u64) -> MlilExpr {
    MlilExpr::new(MlilOp::Store, size, vec![expr(addr), expr(value)], pc)
}

pub fn load_struct(size: u8, addr: MlilExpr, offset: i64, pc: u64) -> MlilExpr {
    MlilExpr::new(
        MlilOp::LoadStruct,
        size,
        vec![expr(addr), MlilOperand::Imm(offset)],
        pc,
    )
}

pub fn store_struct(size: u8, addr: MlilExpr, offset: i64, value: MlilExpr, pc: u64) -> MlilExpr {
    MlilExpr::new(
        MlilOp::StoreStruct,
        size,
        vec![expr(addr), MlilOperand::Imm(offset), expr(value)],
        pc,
    )
}

pub fn sx(size: u8, value: MlilExpr) -> MlilExpr {
    MlilExpr::new(MlilOp::Sx, size, vec![expr(value)], 0)
}

pub fn zx(size: u8, value: MlilExpr) -> MlilExpr {
    MlilExpr::new(MlilOp::Zx, size, vec![expr(value)], 0)
}

pub fn low_part(size: u8, value: MlilExpr) -> MlilExpr {
    MlilExpr::new(MlilOp::LowPart, size, vec![expr(value)], 0)
}

pub fn csel(cond: MlilExpr, true_val: MlilExpr, false_val: MlilExpr) -> MlilExpr {
    let size = true_val.size.max(false_val.size);
    MlilExpr::new(
        MlilOp::Csel,
        size,
        vec![expr(cond), expr(true_val), expr(false_val)],
        0,
    )
}

pub fn address_of(value: MlilExpr) -> MlilExpr {
    MlilExpr::new(MlilOp::AddressOf, 8, vec![expr(value)], 0)
}

pub fn address_of_field(base: MlilExpr, offset: i64) -> MlilExpr {
    MlilExpr::new(
        MlilOp::AddressOfField,
        8,
        vec![expr(base), MlilOperand::Imm(offset)],
        0,
    )
}

// --- Helpers ---

fn fmt_operand(op: Option<&MlilOperand>) -> String {
    match op {
        Some(MlilOperand::Expr(e)) => e.short(),
        Some(MlilOperand::Var(v)) => v.clone(),
        Some(MlilOperand::Str(s)) => s.clone(),
        Some(MlilOperand::Imm(v)) => fmt_signed_literal(*v, 16),
        Some(MlilOperand::U64(v)) => format!("{v:#x}"),
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

fn is_binary(op: MlilOp) -> bool {
    matches!(
        op,
        MlilOp::Add
            | MlilOp::Sub
            | MlilOp::Mul
            | MlilOp::DivS
            | MlilOp::DivU
            | MlilOp::ModS
            | MlilOp::ModU
            | MlilOp::And
            | MlilOp::Or
            | MlilOp::Xor
            | MlilOp::Lsl
            | MlilOp::Lsr
            | MlilOp::Asr
            | MlilOp::Rol
            | MlilOp::Ror
            | MlilOp::CmpE
            | MlilOp::CmpNe
            | MlilOp::CmpSlt
            | MlilOp::CmpSle
            | MlilOp::CmpSge
            | MlilOp::CmpSgt
            | MlilOp::CmpUlt
            | MlilOp::CmpUle
            | MlilOp::CmpUge
            | MlilOp::CmpUgt
    )
}

fn is_unary(op: MlilOp) -> bool {
    matches!(op, MlilOp::Neg | MlilOp::Not)
}

fn op_symbol(op: MlilOp) -> &'static str {
    match op {
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
        MlilOp::Neg => "-",
        MlilOp::Not => "~",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_produce_correct_ops() {
        assert_eq!(var("v0").op, MlilOp::Var);
        assert_eq!(konst(42).op, MlilOp::Const);
        assert_eq!(const_ptr(0x1000).op, MlilOp::ConstPtr);
    }

    #[test]
    fn set_var_short_display() {
        let s = set_var("v0", binary(MlilOp::Add, var("v1"), konst(2)), 0x1000);
        assert_eq!(s.short(), "v0 = (var(v1) + 2)");
    }

    #[test]
    fn set_var_short_display_hex_large() {
        let s = set_var("v0", binary(MlilOp::Add, var("v1"), konst(42)), 0x1000);
        assert!(s.short().contains("0x2a"));
    }

    #[test]
    fn binary_short_display() {
        assert_eq!(
            binary(MlilOp::Add, var("v0"), konst(1)).short(),
            "(var(v0) + 1)"
        );
        assert_eq!(
            binary(MlilOp::CmpE, var("v0"), konst(0)).short(),
            "(var(v0) == 0)"
        );
    }

    #[test]
    fn load_store_short_display() {
        assert_eq!(load(8, var("ptr"), 0x1000).short(), "load.8(var(ptr))");
        assert_eq!(
            store(4, var("ptr"), konst(7), 0x1000).short(),
            "store.4(var(ptr), 7)"
        );
    }

    #[test]
    fn control_flow_detection() {
        assert!(MlilExpr::new(MlilOp::If, 1, vec![], 0).is_control_flow());
        assert!(MlilExpr::new(MlilOp::Goto, 8, vec![], 0).is_control_flow());
        assert!(!MlilExpr::new(MlilOp::Add, 8, vec![], 0).is_control_flow());
    }

    #[test]
    fn side_effect_detection() {
        assert!(MlilExpr::new(MlilOp::Store, 4, vec![], 0).has_side_effect());
        assert!(MlilExpr::new(MlilOp::Call, 8, vec![], 0).has_side_effect());
        assert!(!MlilExpr::new(MlilOp::SetVar, 8, vec![], 0).has_side_effect());
    }

    #[test]
    fn struct_load_store_short() {
        let l = load_struct(8, var("base"), 16, 0x1000);
        assert!(l.short().contains("load_struct"));
        assert!(l.short().contains("offset=0x10"), "got: {}", l.short());

        let s = store_struct(4, var("base"), 8, konst(42), 0x1000);
        assert!(s.short().contains("store_struct"));
        assert!(s.short().contains("offset=8"), "got: {}", s.short());
    }

    #[test]
    fn address_of_and_field() {
        let a = address_of(var("v0"));
        assert_eq!(a.short(), "&(var(v0))");

        let af = address_of_field(var("base"), 16);
        assert_eq!(af.short(), "&(var(base).0x10)");
    }
}
