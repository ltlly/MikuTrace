//! BN-style LLIL expression tree.

use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LlilOp {
    Nop,
    Undef,
    Unimpl,
    Reg,
    Const,
    ConstPtr,
    Flag,
    FlagCond,
    Load,
    Store,
    SetReg,
    SetFlag,
    Add,
    Sub,
    Mul,
    Neg,
    DivS,
    DivU,
    And,
    Or,
    Xor,
    Not,
    Lsl,
    Lsr,
    Asr,
    Rol,
    Ror,
    Sx,
    Zx,
    LowPart,
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
    Goto,
    Jump,
    If,
    Call,
    Tailcall,
    Ret,
    Intrinsic,
    Bp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum LlilOperand {
    Expr(Box<LlilExpr>),
    Reg(String),
    Flag(String),
    Imm(i64),
    U64(u64),
    Str(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LlilExpr {
    pub op: LlilOp,
    /// Operand width in bytes. Statement-level expressions carry the width of
    /// the value being written/read when applicable.
    pub size: u8,
    pub operands: Vec<LlilOperand>,
    pub extra: BTreeMap<String, String>,
    pub pc: u64,
}

impl LlilExpr {
    pub fn new(op: LlilOp, size: u8, operands: Vec<LlilOperand>, pc: u64) -> Self {
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
            LlilOp::Store
                | LlilOp::Call
                | LlilOp::Tailcall
                | LlilOp::Ret
                | LlilOp::Goto
                | LlilOp::Jump
                | LlilOp::If
                | LlilOp::Intrinsic
                | LlilOp::Bp
                | LlilOp::Unimpl
                | LlilOp::SetFlag
                | LlilOp::Load
        )
    }

    pub fn short(&self) -> String {
        match self.op {
            LlilOp::Nop => "nop".to_string(),
            LlilOp::Reg => format!("reg({})", fmt_operand(self.operands.first())),
            LlilOp::Const => fmt_operand(self.operands.first()),
            LlilOp::ConstPtr => format!("ptr({})", fmt_operand(self.operands.first())),
            LlilOp::Flag => format!("flag({})", fmt_operand(self.operands.first())),
            LlilOp::FlagCond => format!("flag_cond({})", fmt_operand(self.operands.first())),
            LlilOp::SetReg => format!(
                "{} = {}",
                fmt_operand(self.operands.first()),
                fmt_operand(self.operands.get(1))
            ),
            LlilOp::SetFlag => format!(
                "{} = {}",
                fmt_operand(self.operands.first()),
                fmt_operand(self.operands.get(1))
            ),
            LlilOp::Load => format!("load.{}({})", self.size, fmt_operand(self.operands.first())),
            LlilOp::Store => format!(
                "store.{}({}, {})",
                self.size,
                fmt_operand(self.operands.first()),
                fmt_operand(self.operands.get(1))
            ),
            LlilOp::Goto => format!("goto {}", fmt_operand(self.operands.first())),
            LlilOp::If => format!(
                "if {} then {} else {}",
                fmt_operand(self.operands.first()),
                fmt_operand(self.operands.get(1)),
                fmt_operand(self.operands.get(2))
            ),
            LlilOp::Call => format!("call({})", fmt_operand(self.operands.first())),
            LlilOp::Ret => "ret".to_string(),
            LlilOp::Intrinsic => {
                let mnem = self.extra.get("mnem").map(String::as_str).unwrap_or("?");
                format!("intrinsic({mnem})")
            }
            op if is_binary(op) => format!(
                "({} {} {})",
                fmt_operand(self.operands.first()),
                op_symbol(op),
                fmt_operand(self.operands.get(1))
            ),
            op => format!("{op:?}"),
        }
    }
}

pub fn reg(name: impl Into<String>) -> LlilExpr {
    LlilExpr::new(LlilOp::Reg, 8, vec![LlilOperand::Reg(name.into())], 0)
}

pub fn flag(name: impl Into<String>) -> LlilExpr {
    LlilExpr::new(LlilOp::Flag, 1, vec![LlilOperand::Flag(name.into())], 0)
}

pub fn flag_cond(cond: impl Into<String>) -> LlilExpr {
    LlilExpr::new(LlilOp::FlagCond, 1, vec![LlilOperand::Str(cond.into())], 0)
}

pub fn konst(value: i64) -> LlilExpr {
    LlilExpr::new(LlilOp::Const, 8, vec![LlilOperand::Imm(value)], 0)
}

pub fn const_ptr(value: u64) -> LlilExpr {
    LlilExpr::new(LlilOp::ConstPtr, 8, vec![LlilOperand::U64(value)], 0)
}

pub fn expr(e: LlilExpr) -> LlilOperand {
    LlilOperand::Expr(Box::new(e))
}

pub fn set_reg(dst: impl Into<String>, value: LlilExpr, pc: u64) -> LlilExpr {
    let size = value.size;
    LlilExpr::new(
        LlilOp::SetReg,
        size,
        vec![LlilOperand::Reg(dst.into()), expr(value)],
        pc,
    )
}

pub fn set_flag(dst: impl Into<String>, value: LlilExpr, pc: u64) -> LlilExpr {
    LlilExpr::new(
        LlilOp::SetFlag,
        1,
        vec![LlilOperand::Flag(dst.into()), expr(value)],
        pc,
    )
}

pub fn unary(op: LlilOp, value: LlilExpr) -> LlilExpr {
    let size = value.size;
    LlilExpr::new(op, size, vec![expr(value)], 0)
}

pub fn binary(op: LlilOp, left: LlilExpr, right: LlilExpr) -> LlilExpr {
    let size = left.size.max(right.size);
    LlilExpr::new(op, size, vec![expr(left), expr(right)], 0)
}

fn fmt_operand(op: Option<&LlilOperand>) -> String {
    match op {
        Some(LlilOperand::Expr(e)) => e.short(),
        Some(LlilOperand::Reg(r)) | Some(LlilOperand::Flag(r)) | Some(LlilOperand::Str(r)) => {
            r.clone()
        }
        Some(LlilOperand::Imm(v)) => {
            if v.abs() >= 16 {
                format!("{v:#x}")
            } else {
                v.to_string()
            }
        }
        Some(LlilOperand::U64(v)) => format!("{v:#x}"),
        None => "?".to_string(),
    }
}

fn is_binary(op: LlilOp) -> bool {
    matches!(
        op,
        LlilOp::Add
            | LlilOp::Sub
            | LlilOp::Mul
            | LlilOp::DivS
            | LlilOp::DivU
            | LlilOp::And
            | LlilOp::Or
            | LlilOp::Xor
            | LlilOp::Lsl
            | LlilOp::Lsr
            | LlilOp::Asr
            | LlilOp::Rol
            | LlilOp::Ror
            | LlilOp::CmpE
            | LlilOp::CmpNe
            | LlilOp::CmpSlt
            | LlilOp::CmpSle
            | LlilOp::CmpSge
            | LlilOp::CmpSgt
            | LlilOp::CmpUlt
            | LlilOp::CmpUle
            | LlilOp::CmpUge
            | LlilOp::CmpUgt
    )
}

fn op_symbol(op: LlilOp) -> &'static str {
    match op {
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
        _ => "?",
    }
}
