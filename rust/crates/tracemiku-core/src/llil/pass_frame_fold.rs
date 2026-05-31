//! Stack frame folding pass.
//!
//! Marks function prologue/epilogue operations so renderers can collapse
//! them. Detects common ARM64 frame setup/teardown patterns.

use crate::llil::expr::{LlilExpr, LlilOp, LlilOperand};

#[derive(Debug, Clone, Default)]
pub struct FrameFoldResult {
    pub exprs: Vec<LlilExpr>,
    pub frame_size: i64,
    pub has_frame: bool,
}

/// Fold stack frame prologue/epilogue: mark frame ops for collapsing.
pub fn frame_fold_block(exprs: &[LlilExpr]) -> FrameFoldResult {
    let n = exprs.len();
    if n < 3 {
        return FrameFoldResult {
            exprs: exprs.to_vec(),
            frame_size: 0,
            has_frame: false,
        };
    }

    let mut out: Vec<LlilExpr> = exprs.to_vec();
    let mut frame_size: i64 = 0;
    let mut has_frame = false;

    // Detect prologue: first few instructions that set up the stack frame
    // Pattern: sub sp, sp, #N  or  stp fp, lr, [sp, #-N]!
    for i in 0..n.min(5) {
        let e = &exprs[i];
        match e.op {
            LlilOp::SetReg => {
                // sub sp, sp, #N → frame_size = N
                if let (Some(LlilOperand::Reg(dst)), Some(LlilOperand::Expr(val))) =
                    (e.operands.first(), e.operands.get(1))
                {
                    if dst == "sp" || dst.starts_with("sp#") {
                        if let Some(size) = extract_sub_imm(val) {
                            frame_size = size;
                            has_frame = true;
                            out[i]
                                .extra
                                .insert("frame_op".into(), "prologue_sub_sp".into());
                        }
                    }
                }
            }
            LlilOp::Store => {
                // stp fp, lr, [sp, #offset] or str xN, [sp, #offset]
                if let Some(LlilOperand::Expr(addr)) = e.operands.first() {
                    if contains_reg(addr, "sp") || contains_reg(addr, "fp") {
                        out[i]
                            .extra
                            .insert("frame_op".into(), "prologue_save".into());
                        has_frame = true;
                    }
                }
            }
            _ => {}
        }
    }

    // Detect epilogue: last few instructions before ret
    for i in (n.saturating_sub(6)..n).rev() {
        let e = &exprs[i];
        match e.op {
            LlilOp::Load => {
                if let Some(LlilOperand::Expr(addr)) = e.operands.first() {
                    if contains_reg(addr, "sp") || contains_reg(addr, "fp") {
                        out[i]
                            .extra
                            .insert("frame_op".into(), "epilogue_restore".into());
                    }
                }
            }
            LlilOp::SetReg => {
                if let (Some(LlilOperand::Reg(dst)), Some(LlilOperand::Expr(val))) =
                    (e.operands.first(), e.operands.get(1))
                {
                    if dst == "sp" || dst.starts_with("sp#") {
                        if extract_sub_imm(val).map_or(false, |s| s < 0) {
                            out[i]
                                .extra
                                .insert("frame_op".into(), "epilogue_add_sp".into());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    FrameFoldResult {
        exprs: out,
        frame_size,
        has_frame,
    }
}

fn extract_sub_imm(val: &LlilExpr) -> Option<i64> {
    if val.op != LlilOp::Sub || val.operands.len() != 2 {
        return None;
    }
    match val.operands.get(1) {
        Some(LlilOperand::Imm(v)) => Some(*v),
        Some(LlilOperand::Expr(e)) if e.op == LlilOp::Const => match e.operands.first() {
            Some(LlilOperand::Imm(v)) => Some(*v),
            _ => None,
        },
        _ => None,
    }
}

fn contains_reg(e: &LlilExpr, reg: &str) -> bool {
    if let LlilOp::Reg | LlilOp::Flag = e.op {
        if let Some(LlilOperand::Reg(r)) | Some(LlilOperand::Flag(r)) = e.operands.first() {
            let base = r.split('#').next().unwrap_or(r);
            return base == reg;
        }
    }
    for op in &e.operands {
        if let LlilOperand::Expr(child) = op {
            if contains_reg(child, reg) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::llil::expr::{binary, konst, reg, set_reg, LlilOp, LlilOperand};

    use super::*;

    #[test]
    fn test_detect_prologue_sub_sp() {
        // sub sp, sp, #0x30; stp x29, x30, [sp, #0x20]
        let exprs = vec![
            set_reg(
                "sp#1",
                binary(LlilOp::Sub, reg("sp#0"), konst(0x30)),
                0x1000,
            ),
            LlilExpr::new(
                LlilOp::Store,
                8,
                vec![
                    LlilOperand::Expr(Box::new(binary(LlilOp::Add, reg("sp#1"), konst(0x20)))),
                    LlilOperand::Expr(Box::new(reg("fp#0"))),
                ],
                0x1004,
            ),
            LlilExpr::new(LlilOp::Ret, 8, vec![], 0x1008),
        ];
        let result = frame_fold_block(&exprs);
        assert!(result.has_frame);
        assert_eq!(result.frame_size, 0x30);
        assert_eq!(
            result.exprs[0].extra.get("frame_op").map(String::as_str),
            Some("prologue_sub_sp")
        );
    }

    #[test]
    fn test_no_frame_on_empty() {
        let result = frame_fold_block(&[]);
        assert!(!result.has_frame);
    }
}
