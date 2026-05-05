//! Lightweight LLIL restructure pass.
//!
//! This is intentionally conservative: it preserves linear statement order and
//! only classifies statement nodes into block / if / goto / return forms. Loop
//! reconstruction can build on this stable tree without changing the wire
//! shape.

use serde::Serialize;

use crate::llil::expr::{LlilExpr, LlilOp, LlilOperand};
use crate::llil::render::render_stmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StructNode {
    Stmt {
        pc: String,
        text: String,
    },
    If {
        pc: String,
        cond: String,
        true_target: String,
        false_target: String,
    },
    Goto {
        pc: String,
        target: String,
    },
    Return {
        pc: String,
    },
}

pub fn restructure_block(exprs: &[LlilExpr]) -> Vec<StructNode> {
    exprs.iter().map(restructure_stmt).collect()
}

fn restructure_stmt(e: &LlilExpr) -> StructNode {
    match e.op {
        LlilOp::If => StructNode::If {
            pc: format!("{:#x}", e.pc),
            cond: render_operand(e.operands.first()),
            true_target: render_target(e.operands.get(1)),
            false_target: render_target(e.operands.get(2)),
        },
        LlilOp::Goto => StructNode::Goto {
            pc: format!("{:#x}", e.pc),
            target: render_target(e.operands.first()),
        },
        LlilOp::Ret => StructNode::Return {
            pc: format!("{:#x}", e.pc),
        },
        _ => StructNode::Stmt {
            pc: format!("{:#x}", e.pc),
            text: render_stmt(e),
        },
    }
}

fn render_operand(op: Option<&LlilOperand>) -> String {
    match op {
        Some(LlilOperand::Expr(e)) => e.short(),
        Some(LlilOperand::Reg(r)) | Some(LlilOperand::Flag(r)) | Some(LlilOperand::Str(r)) => {
            r.clone()
        }
        Some(LlilOperand::Imm(v)) => v.to_string(),
        Some(LlilOperand::U64(v)) => format!("{v:#x}"),
        None => "?".to_string(),
    }
}

fn render_target(op: Option<&LlilOperand>) -> String {
    render_operand(op)
}

#[cfg(test)]
mod tests {
    use crate::llil::expr::{expr, flag_cond, LlilExpr, LlilOp, LlilOperand};

    use super::*;

    #[test]
    fn classifies_if_node() {
        let br = LlilExpr::new(
            LlilOp::If,
            1,
            vec![
                expr(flag_cond("eq")),
                LlilOperand::U64(0x2000),
                LlilOperand::U64(0x1008),
            ],
            0x1004,
        );
        let nodes = restructure_block(&[br]);
        assert!(matches!(nodes[0], StructNode::If { .. }));
    }
}
