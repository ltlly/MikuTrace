//! Struct-shape recovery from LLIL memory accesses.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::llil::expr::{LlilExpr, LlilOp, LlilOperand};
use crate::llil::pass_typelat::{TypeEnv, TypeKind};
use crate::llil::util::walk_expr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldAccess {
    pub offset: i64,
    pub size: u8,
    pub reads: u32,
    pub writes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StructShape {
    pub base: String,
    pub fields: BTreeMap<i64, FieldAccess>,
    pub conflict: bool,
}

pub fn struct_recover_block(exprs: &[LlilExpr], types: &TypeEnv) -> BTreeMap<String, StructShape> {
    let mut shapes = BTreeMap::new();
    for root in exprs {
        let mut nodes = Vec::new();
        walk_expr(root, &mut nodes);
        for node in nodes {
            if !matches!(node.op, LlilOp::Load | LlilOp::Store) {
                continue;
            }
            let Some(addr) = node.operands.first() else {
                continue;
            };
            let Some((base, offset)) = extract_base_offset(addr) else {
                continue;
            };
            if types.get(&base) != Some(&TypeKind::Ptr) {
                continue;
            }
            let shape = shapes.entry(base.clone()).or_insert_with(|| StructShape {
                base: base.clone(),
                fields: BTreeMap::new(),
                conflict: false,
            });
            let field = shape.fields.entry(offset).or_insert(FieldAccess {
                offset,
                size: node.size,
                reads: 0,
                writes: 0,
            });
            if field.size != node.size {
                shape.conflict = true;
            }
            if node.op == LlilOp::Load {
                field.reads += 1;
            } else {
                field.writes += 1;
            }
        }
    }
    shapes
}

fn extract_base_offset(op: &LlilOperand) -> Option<(String, i64)> {
    match op {
        LlilOperand::Reg(r) => Some((r.clone(), 0)),
        LlilOperand::Expr(e) if e.op == LlilOp::Reg => match e.operands.first() {
            Some(LlilOperand::Reg(r)) => Some((r.clone(), 0)),
            _ => None,
        },
        LlilOperand::Expr(e) if e.op == LlilOp::Add && e.operands.len() == 2 => {
            let a = extract_base_offset(&e.operands[0]);
            let b = imm_operand(&e.operands[1]);
            if let (Some((base, off)), Some(disp)) = (a, b) {
                return Some((base, off + disp));
            }
            let a = imm_operand(&e.operands[0]);
            let b = extract_base_offset(&e.operands[1]);
            if let (Some(disp), Some((base, off))) = (a, b) {
                return Some((base, off + disp));
            }
            None
        }
        _ => None,
    }
}

fn imm_operand(op: &LlilOperand) -> Option<i64> {
    match op {
        LlilOperand::Imm(v) => Some(*v),
        LlilOperand::Expr(e) if e.op == LlilOp::Const => match e.operands.first() {
            Some(LlilOperand::Imm(v)) => Some(*v),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::llil::expr::{binary, expr, konst, reg, LlilExpr, LlilOp};
    use crate::llil::pass_typelat::{TypeEnv, TypeKind};

    use super::*;

    #[test]
    fn recovers_load_field_shape() {
        let load = LlilExpr::new(
            LlilOp::Load,
            8,
            vec![expr(binary(LlilOp::Add, reg("x1#0"), konst(16)))],
            0x1000,
        );
        let mut types = TypeEnv::new();
        types.insert("x1#0".to_string(), TypeKind::Ptr);
        let shapes = struct_recover_block(&[load], &types);
        let shape = shapes.get("x1#0").unwrap();
        assert_eq!(shape.fields.get(&16).unwrap().reads, 1);
    }
}
