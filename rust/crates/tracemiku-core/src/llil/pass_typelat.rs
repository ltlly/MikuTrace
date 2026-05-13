//! Type-lattice inference over LLIL.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::llil::expr::{LlilExpr, LlilOp, LlilOperand};
use crate::llil::util::parse_ssa_reg;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeKind {
    Any,
    Int,
    Ptr,
    Handle,
    Bool,
    Conflict,
}

pub type TypeEnv = BTreeMap<String, TypeKind>;

pub fn join_type(a: TypeKind, b: TypeKind) -> TypeKind {
    use TypeKind::*;
    match (a, b) {
        (x, y) if x == y => x,
        (Any, x) | (x, Any) => x,
        (Ptr, Int) | (Int, Ptr) => Ptr,
        _ => Conflict,
    }
}

pub fn typelat_block(exprs: &[LlilExpr]) -> TypeEnv {
    let mut env = TypeEnv::new();
    for e in exprs {
        infer_stmt(e, &mut env);
    }
    env
}

fn infer_stmt(e: &LlilExpr, env: &mut TypeEnv) {
    if e.op == LlilOp::SetReg {
        let Some(LlilOperand::Reg(dst)) = e.operands.first() else {
            return;
        };
        let ty = e
            .operands
            .get(1)
            .map(|op| infer_operand(op, env))
            .unwrap_or(TypeKind::Any);
        update(
            env,
            dst,
            if ty == TypeKind::Any {
                TypeKind::Int
            } else {
                ty
            },
        );
        return;
    }
    infer_expr(e, env);
}

fn infer_operand(op: &LlilOperand, env: &mut TypeEnv) -> TypeKind {
    match op {
        LlilOperand::Expr(e) => infer_expr(e, env),
        LlilOperand::Reg(r) => *env.get(r).unwrap_or(&TypeKind::Any),
        LlilOperand::Imm(_) => TypeKind::Int,
        LlilOperand::U64(_) => TypeKind::Ptr,
        LlilOperand::Flag(_) | LlilOperand::Str(_) => TypeKind::Any,
    }
}

fn infer_expr(e: &LlilExpr, env: &mut TypeEnv) -> TypeKind {
    match e.op {
        LlilOp::Const => TypeKind::Int,
        LlilOp::ConstPtr => TypeKind::Ptr,
        LlilOp::Reg => match e.operands.first() {
            Some(LlilOperand::Reg(r)) => *env.get(r).unwrap_or(&TypeKind::Any),
            _ => TypeKind::Any,
        },
        LlilOp::Flag | LlilOp::FlagCond => TypeKind::Bool,
        LlilOp::Load => {
            if let Some(addr) = e.operands.first() {
                force_ptr(addr, env);
            }
            TypeKind::Int
        }
        LlilOp::Store => {
            if let Some(addr) = e.operands.first() {
                force_ptr(addr, env);
            }
            for op in e.operands.iter().skip(1) {
                infer_operand(op, env);
            }
            TypeKind::Any
        }
        LlilOp::Add => {
            let mut ty = TypeKind::Any;
            for op in &e.operands {
                ty = join_type(ty, infer_operand(op, env));
            }
            if ty == TypeKind::Any {
                TypeKind::Int
            } else {
                ty
            }
        }
        LlilOp::Sub => {
            let lhs = e
                .operands
                .first()
                .map(|op| infer_operand(op, env))
                .unwrap_or(TypeKind::Any);
            let rhs = e
                .operands
                .get(1)
                .map(|op| infer_operand(op, env))
                .unwrap_or(TypeKind::Any);
            if lhs == TypeKind::Ptr && rhs == TypeKind::Ptr {
                TypeKind::Int
            } else if lhs == TypeKind::Ptr {
                TypeKind::Ptr
            } else {
                TypeKind::Int
            }
        }
        LlilOp::Mul
        | LlilOp::Neg
        | LlilOp::DivS
        | LlilOp::DivU
        | LlilOp::And
        | LlilOp::Or
        | LlilOp::Xor
        | LlilOp::Not
        | LlilOp::Lsl
        | LlilOp::Lsr
        | LlilOp::Asr
        | LlilOp::Rol
        | LlilOp::Ror => {
            for op in &e.operands {
                infer_operand(op, env);
            }
            TypeKind::Int
        }
        LlilOp::CmpE
        | LlilOp::CmpNe
        | LlilOp::CmpSlt
        | LlilOp::CmpSle
        | LlilOp::CmpSge
        | LlilOp::CmpSgt
        | LlilOp::CmpUlt
        | LlilOp::CmpUle
        | LlilOp::CmpUge
        | LlilOp::CmpUgt => {
            for op in &e.operands {
                infer_operand(op, env);
            }
            TypeKind::Bool
        }
        LlilOp::Sx | LlilOp::Zx | LlilOp::LowPart => {
            for op in &e.operands {
                infer_operand(op, env);
            }
            TypeKind::Int
        }
        LlilOp::Csel => {
            for op in &e.operands {
                infer_operand(op, env);
            }
            join_type(
                infer_operand(e.operands.get(1).unwrap_or(&LlilOperand::Imm(0)), env),
                infer_operand(e.operands.get(2).unwrap_or(&LlilOperand::Imm(0)), env),
            )
        }
        _ => {
            for op in &e.operands {
                infer_operand(op, env);
            }
            TypeKind::Any
        }
    }
}

fn force_ptr(op: &LlilOperand, env: &mut TypeEnv) {
    match op {
        LlilOperand::Expr(e) => force_ptr_expr(e, env),
        LlilOperand::Reg(r) => update(env, r, TypeKind::Ptr),
        _ => {}
    }
}

fn force_ptr_expr(e: &LlilExpr, env: &mut TypeEnv) {
    match e.op {
        LlilOp::Reg => {
            if let Some(LlilOperand::Reg(r)) = e.operands.first() {
                update(env, r, TypeKind::Ptr);
            }
        }
        LlilOp::Add => {
            for op in &e.operands {
                if reg_name(op).is_some() {
                    force_ptr(op, env);
                } else {
                    infer_operand(op, env);
                }
            }
        }
        _ => {
            infer_expr(e, env);
        }
    }
}

fn reg_name(op: &LlilOperand) -> Option<&str> {
    match op {
        LlilOperand::Reg(r) => Some(r),
        LlilOperand::Expr(e) if e.op == LlilOp::Reg => match e.operands.first() {
            Some(LlilOperand::Reg(r)) => Some(r),
            _ => None,
        },
        _ => None,
    }
}

fn update(env: &mut TypeEnv, reg: &str, ty: TypeKind) {
    let base = parse_ssa_reg(reg).map(|(name, ver)| format!("{name}#{ver}"));
    let key = base.unwrap_or_else(|| reg.to_string());
    let cur = *env.get(&key).unwrap_or(&TypeKind::Any);
    env.insert(key, join_type(cur, ty));
}

#[cfg(test)]
mod tests {
    use crate::llil::expr::{binary, expr, reg, set_reg, LlilExpr, LlilOp};

    use super::*;

    #[test]
    fn infers_pointer_from_load_address() {
        let load = LlilExpr::new(LlilOp::Load, 8, vec![expr(reg("x1#0"))], 0x1000);
        let block = vec![set_reg("x0#1", load, 0x1000)];
        let env = typelat_block(&block);
        assert_eq!(env.get("x1#0"), Some(&TypeKind::Ptr));
        assert_eq!(env.get("x0#1"), Some(&TypeKind::Int));
    }

    #[test]
    fn ptr_plus_int_stays_ptr() {
        let load = LlilExpr::new(
            LlilOp::Load,
            8,
            vec![expr(binary(LlilOp::Add, reg("x1#0"), reg("x2#0")))],
            0x1000,
        );
        let env = typelat_block(&[set_reg("x0#1", load, 0x1000)]);
        assert_eq!(env.get("x1#0"), Some(&TypeKind::Ptr));
    }
}
