//! Block-local SSA for LLIL.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::llil::expr::{expr, LlilExpr, LlilOp, LlilOperand};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SsaVar {
    pub name: String,
    pub version: u32,
}

impl SsaVar {
    pub fn display(&self) -> String {
        format!("{}#{}", self.name, self.version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SsaBlock {
    pub exprs: Vec<LlilExpr>,
    pub entry_versions: BTreeMap<String, u32>,
    pub exit_versions: BTreeMap<String, u32>,
    pub defs: BTreeMap<SsaVar, usize>,
    pub uses: BTreeMap<SsaVar, Vec<usize>>,
}

#[derive(Debug, Clone, Default)]
struct SsaCtx {
    versions: BTreeMap<String, u32>,
    defs: BTreeMap<SsaVar, usize>,
    uses: BTreeMap<SsaVar, Vec<usize>>,
}

/// Convert one linear LLIL block into block-local SSA.
///
/// Register operands are rewritten from `x0` to `x0#N`. A `SET_REG x0, expr`
/// first rewrites `expr` against the current versions, then increments x0 and
/// writes the destination as `x0#N+1`.
pub fn ssa_block(exprs: &[LlilExpr]) -> SsaBlock {
    let mut ctx = SsaCtx::default();
    let entry_versions = ctx.versions.clone();
    let out: Vec<LlilExpr> = exprs
        .iter()
        .enumerate()
        .map(|(idx, e)| ssa_stmt(e, idx, &mut ctx))
        .collect();
    SsaBlock {
        exprs: out,
        entry_versions,
        exit_versions: ctx.versions,
        defs: ctx.defs,
        uses: ctx.uses,
    }
}

fn ssa_stmt(e: &LlilExpr, idx: usize, ctx: &mut SsaCtx) -> LlilExpr {
    match e.op {
        LlilOp::SetReg => {
            let dst = match e.operands.first() {
                Some(LlilOperand::Reg(r)) => r.clone(),
                _ => return ssa_expr(e, idx, ctx),
            };
            let value = match e.operands.get(1) {
                Some(LlilOperand::Expr(v)) => ssa_expr(v, idx, ctx),
                _ => LlilExpr::new(LlilOp::Undef, 0, Vec::new(), e.pc),
            };
            let version = bump_version(ctx, &dst);
            let var = SsaVar { name: dst, version };
            ctx.defs.insert(var.clone(), idx);
            let mut out = e.clone();
            out.operands = vec![LlilOperand::Reg(var.display()), expr(value)];
            out
        }
        LlilOp::Call => {
            let mut out = ssa_expr(e, idx, ctx);
            kill_caller_saved(idx, ctx);
            out.extra
                .insert("ssa_call_kill".to_string(), "caller_saved".to_string());
            out
        }
        _ => ssa_expr(e, idx, ctx),
    }
}

fn ssa_expr(e: &LlilExpr, idx: usize, ctx: &mut SsaCtx) -> LlilExpr {
    let mut out = e.clone();
    out.operands = e
        .operands
        .iter()
        .map(|op| match op {
            LlilOperand::Expr(sub) => expr(ssa_expr(sub, idx, ctx)),
            LlilOperand::Reg(r) => {
                let version = *ctx.versions.get(r).unwrap_or(&0);
                let var = SsaVar {
                    name: r.clone(),
                    version,
                };
                ctx.uses.entry(var.clone()).or_default().push(idx);
                LlilOperand::Reg(var.display())
            }
            other => other.clone(),
        })
        .collect();
    out
}

fn bump_version(ctx: &mut SsaCtx, reg: &str) -> u32 {
    let version = ctx.versions.entry(reg.to_string()).or_insert(0);
    *version += 1;
    *version
}

fn kill_caller_saved(idx: usize, ctx: &mut SsaCtx) {
    for reg in caller_saved_regs() {
        let version = bump_version(ctx, reg);
        ctx.defs.insert(
            SsaVar {
                name: reg.to_string(),
                version,
            },
            idx,
        );
    }
}

fn caller_saved_regs() -> impl Iterator<Item = &'static str> {
    [
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
        "x14", "x15", "x16", "x17", "x18", "lr", "nzcv",
    ]
    .into_iter()
}

#[cfg(test)]
mod tests {
    use crate::llil::expr::{binary, konst, reg, set_reg, LlilOp};

    use super::*;

    #[test]
    fn ssa_versions_defs_after_uses() {
        let exprs = vec![
            set_reg("x0", konst(1), 0x1000),
            set_reg("x1", binary(LlilOp::Add, reg("x0"), konst(2)), 0x1004),
            set_reg("x0", binary(LlilOp::Add, reg("x1"), reg("x0")), 0x1008),
        ];
        let ssa = ssa_block(&exprs);
        assert_eq!(ssa.exprs[0].short(), "x0#1 = 1");
        assert_eq!(ssa.exprs[1].short(), "x1#1 = (reg(x0#1) + 2)");
        assert_eq!(ssa.exprs[2].short(), "x0#2 = (reg(x1#1) + reg(x0#1))");
        assert_eq!(ssa.exit_versions.get("x0"), Some(&2));
        assert_eq!(ssa.exit_versions.get("x1"), Some(&1));
    }

    #[test]
    fn ssa_call_kills_aapcs64_caller_saved() {
        let call = LlilExpr::new(LlilOp::Call, 8, vec![expr(reg("x9"))], 0x2000);
        let ssa = ssa_block(&[call]);
        assert_eq!(ssa.exit_versions.get("x0"), Some(&1));
        assert_eq!(ssa.exit_versions.get("x18"), Some(&1));
        assert_eq!(ssa.exit_versions.get("lr"), Some(&1));
        assert_eq!(
            ssa.exprs[0].extra.get("ssa_call_kill").map(String::as_str),
            Some("caller_saved")
        );
    }
}
