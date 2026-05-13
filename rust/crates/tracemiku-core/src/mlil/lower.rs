//! LLIL → MLIL lowering pass.
//!
//! Transforms register-based LLIL into variable-based, flag-free MLIL.
//! This is the core transformation that mirrors BN's LLIL→MLIL lift.
//!
//! Key transformations:
//!   1. SET_REG → SET_VAR  (register → variable)
//!   2. REG     → VAR      (register use → variable use)
//!   3. FLAG/FLAFCOND/SET_FLAG → direct comparison expressions
//!   4. LOAD/STORE base+const → LOAD_STRUCT/STORE_STRUCT

use serde::Serialize;

use crate::llil::expr::{LlilExpr, LlilOp, LlilOperand};
use crate::llil::pass_var_unify::VarNameMap;
use crate::mlil::expr::{
    binary, expr, load, load_struct, set_var, store,
    store_struct, unary, var as mlil_var, MlilExpr, MlilOp, MlilOperand,
};

#[derive(Debug, Clone, Default, Serialize)]
pub struct LowerStats {
    pub llil_count: usize,
    pub mlil_count: usize,
    pub skipped_flags: usize,
    pub struct_loads: usize,
    pub struct_stores: usize,
}

/// Lower a sequence of LLIL expressions into MLIL.
///
/// `names` is the variable name map from SSA register names to user-facing
/// variable names (e.g. "x0#1" → "arg_0" or "x0_v1").
pub fn lower_llil_to_mlil(exprs: &[LlilExpr], names: &VarNameMap) -> (Vec<MlilExpr>, LowerStats) {
    let mut out = Vec::new();
    let mut stats = LowerStats {
        llil_count: exprs.len(),
        ..Default::default()
    };

    for e in exprs {
        if let Some(lowered) = lower_expr(e, names) {
            // Track struct detection
            if has_nested_op(&lowered, MlilOp::LoadStruct) {
                stats.struct_loads += 1;
            }
            if has_nested_op(&lowered, MlilOp::StoreStruct) {
                stats.struct_stores += 1;
            }
            stats.mlil_count += 1;
            out.push(lowered);
        } else {
            stats.skipped_flags += 1;
        }
    }

    (out, stats)
}

/// Check if an expression tree contains the given op at any depth.
fn has_nested_op(e: &MlilExpr, target: MlilOp) -> bool {
    if e.op == target {
        return true;
    }
    for op in &e.operands {
        if let MlilOperand::Expr(child) = op {
            if has_nested_op(child, target) {
                return true;
            }
        }
    }
    false
}

fn lower_expr(e: &LlilExpr, names: &VarNameMap) -> Option<MlilExpr> {
    let pc = e.pc;
    match e.op {
        // Skip flag operations — they should already be eliminated
        LlilOp::SetFlag | LlilOp::Flag | LlilOp::FlagCond => return None,

        // SET_REG → SET_VAR
        LlilOp::SetReg => {
            let dst = match e.operands.first() {
                Some(LlilOperand::Reg(r)) => resolve_var(r, names),
                _ => return Some(intrinsic_mlil(e)),
            };
            let value = match e.operands.get(1) {
                Some(LlilOperand::Expr(v)) => lower_expr(v, names)?,
                _ => return Some(intrinsic_mlil(e)),
            };
            return Some(set_var(dst, value, pc));
        }

        // REG → VAR
        LlilOp::Reg => {
            let name = match e.operands.first() {
                Some(LlilOperand::Reg(r)) => resolve_var(r, names),
                _ => return Some(intrinsic_mlil(e)),
            };
            // Treat reg(X) as a VAR. This is used inside expressions.
            return Some(mlil_var(name));
        }

        // LOAD → LOAD or LOAD_STRUCT
        LlilOp::Load => {
            let addr = match e.operands.first() {
                Some(LlilOperand::Expr(a)) => lower_expr(a, names)?,
                _ => return Some(intrinsic_mlil(e)),
            };
            // Try to detect struct-style access: base + constant offset
            if let Some((base, offset)) = detect_base_offset(&addr) {
                return Some(load_struct(e.size, base, offset, pc));
            }
            return Some(load(e.size, addr, pc));
        }

        // STORE → STORE or STORE_STRUCT
        LlilOp::Store => {
            let addr = match e.operands.first() {
                Some(LlilOperand::Expr(a)) => lower_expr(a, names)?,
                _ => return Some(intrinsic_mlil(e)),
            };
            let value = match e.operands.get(1) {
                Some(LlilOperand::Expr(v)) => lower_expr(v, names)?,
                _ => return Some(intrinsic_mlil(e)),
            };
            if let Some((base, offset)) = detect_base_offset(&addr) {
                return Some(store_struct(e.size, base, offset, value, pc));
            }
            return Some(store(e.size, addr, value, pc));
        }

        // IF: lower condition, keep targets
        LlilOp::If => {
            let cond = match e.operands.first() {
                Some(LlilOperand::Expr(c)) => lower_expr(c, names)?,
                _ => return Some(intrinsic_mlil(e)),
            };
            let t = lower_operand_or_u64(e.operands.get(1), names, 0);
            let f = lower_operand_or_u64(e.operands.get(2), names, 0);
            return Some(MlilExpr::new(
                MlilOp::If,
                e.size,
                vec![expr(cond), t, f],
                pc,
            ));
        }

        // Direct mappings (same operation, just lower operands)
        LlilOp::Nop => return Some(MlilExpr::new(MlilOp::Nop, 0, vec![], pc)),
        LlilOp::Ret => return Some(MlilExpr::new(MlilOp::Ret, e.size, vec![], pc)),
        LlilOp::Goto => {
            let t = lower_operand_or_u64(e.operands.first(), names, 0);
            return Some(MlilExpr::new(MlilOp::Goto, e.size, vec![t], pc));
        }
        LlilOp::Jump => {
            let t = match e.operands.first() {
                Some(LlilOperand::Expr(ee)) => expr(lower_expr(ee, names)?),
                other => lower_operand_or_u64(other, names, 0),
            };
            return Some(MlilExpr::new(MlilOp::Jump, e.size, vec![t], pc));
        }
        LlilOp::Call => {
            let ops: Vec<MlilOperand> = e
                .operands
                .iter()
                .map(|o| lower_operand(o, names))
                .collect::<Option<Vec<_>>>()?;
            return Some(MlilExpr::new(MlilOp::Call, e.size, ops, pc));
        }
        LlilOp::Tailcall => {
            let ops: Vec<MlilOperand> = e
                .operands
                .iter()
                .map(|o| lower_operand(o, names))
                .collect::<Option<Vec<_>>>()?;
            return Some(MlilExpr::new(MlilOp::Tailcall, e.size, ops, pc));
        }

        // Intrinsic → Intrinsic
        LlilOp::Intrinsic => {
            let ops: Vec<MlilOperand> = e
                .operands
                .iter()
                .map(|o| lower_operand(o, names))
                .collect::<Option<Vec<_>>>()?;
            let mut out = MlilExpr::new(MlilOp::Intrinsic, e.size, ops, pc);
            for (k, v) in &e.extra {
                out.extra.insert(k.clone(), v.clone());
            }
            return Some(out);
        }

        // Constant expressions
        LlilOp::Const => {
            let ops: Vec<MlilOperand> = e
                .operands
                .iter()
                .map(|o| lower_operand(o, names))
                .collect::<Option<Vec<_>>>()?;
            return Some(MlilExpr::new(MlilOp::Const, e.size, ops, pc));
        }
        LlilOp::ConstPtr => {
            let ops: Vec<MlilOperand> = e
                .operands
                .iter()
                .map(|o| lower_operand(o, names))
                .collect::<Option<Vec<_>>>()?;
            return Some(MlilExpr::new(MlilOp::ConstPtr, e.size, ops, pc));
        }

        // Unary ops
        LlilOp::Neg | LlilOp::Not => {
            let val = match e.operands.first() {
                Some(LlilOperand::Expr(v)) => lower_expr(v, names)?,
                _ => return Some(intrinsic_mlil(e)),
            };
            let mlil_op = match e.op {
                LlilOp::Neg => MlilOp::Neg,
                LlilOp::Not => MlilOp::Not,
                _ => unreachable!(),
            };
            return Some(unary(mlil_op, val));
        }

        // Binary ops
        op if is_llil_binary(op) => {
            let lhs = match e.operands.first() {
                Some(LlilOperand::Expr(v)) => lower_expr(v, names)?,
                _ => return Some(intrinsic_mlil(e)),
            };
            let rhs = match e.operands.get(1) {
                Some(LlilOperand::Expr(v)) => lower_expr(v, names)?,
                _ => return Some(intrinsic_mlil(e)),
            };
            let mlil_op = map_binary_op(op);
            return Some(binary(mlil_op, lhs, rhs));
        }

        // Sx / Zx / LowPart
        LlilOp::Sx | LlilOp::Zx | LlilOp::LowPart => {
            let val = match e.operands.first() {
                Some(LlilOperand::Expr(v)) => lower_expr(v, names)?,
                _ => return Some(intrinsic_mlil(e)),
            };
            let mlil_op = match e.op {
                LlilOp::Sx => MlilOp::Sx,
                LlilOp::Zx => MlilOp::Zx,
                LlilOp::LowPart => MlilOp::LowPart,
                _ => unreachable!(),
            };
            return Some(MlilExpr::new(mlil_op, e.size, vec![expr(val)], pc));
        }

        // Csel
        LlilOp::Csel => {
            let cond = match e.operands.first() {
                Some(LlilOperand::Expr(v)) => lower_expr(v, names)?,
                _ => return Some(intrinsic_mlil(e)),
            };
            let t = match e.operands.get(1) {
                Some(LlilOperand::Expr(v)) => lower_expr(v, names)?,
                _ => return Some(intrinsic_mlil(e)),
            };
            let f = match e.operands.get(2) {
                Some(LlilOperand::Expr(v)) => lower_expr(v, names)?,
                _ => return Some(intrinsic_mlil(e)),
            };
            return Some(MlilExpr::new(
                MlilOp::Csel,
                e.size,
                vec![expr(cond), expr(t), expr(f)],
                pc,
            ));
        }

        // Bp
        LlilOp::Bp => {
            return Some(MlilExpr::new(MlilOp::Bp, e.size, vec![], pc));
        }

        _ => return Some(intrinsic_mlil(e)),
    }
}

fn lower_operand_or_u64(op: Option<&LlilOperand>, names: &VarNameMap, default: u64) -> MlilOperand {
    match op {
        Some(o) => lower_operand(o, names).unwrap_or(MlilOperand::U64(default)),
        None => MlilOperand::U64(default),
    }
}

fn lower_operand(op: &LlilOperand, names: &VarNameMap) -> Option<MlilOperand> {
    match op {
        LlilOperand::Expr(e) => Some(expr(lower_expr(e, names)?)),
        LlilOperand::Reg(r) => Some(MlilOperand::Var(resolve_var(r, names))),
        LlilOperand::Imm(v) => Some(MlilOperand::Imm(*v)),
        LlilOperand::U64(v) => Some(MlilOperand::U64(*v)),
        LlilOperand::Str(s) => Some(MlilOperand::Str(s.clone())),
        LlilOperand::Flag(f) => {
            // Flag operand in MLIL: convert to constant (0/1)
            // This shouldn't happen often since flags should be eliminated
            Some(MlilOperand::Var(f.clone()))
        }
    }
}

fn resolve_var(reg: &str, names: &VarNameMap) -> String {
    names.get(reg).cloned().unwrap_or_else(|| reg.to_string())
}

fn detect_base_offset(addr: &MlilExpr) -> Option<(MlilExpr, i64)> {
    // addr = (base + offset): struct field access
    // Only match non-negative, small offsets — large or negative values
    // represent pointer arithmetic, not struct fields.
    if addr.op == MlilOp::Add && addr.operands.len() == 2 {
        let left = addr.operands.first()?;
        let right = addr.operands.get(1)?;

        // Try both orderings: (base, offset) or (offset, base)
        if let Some(result) = try_base_offset(left, right) {
            return Some(result);
        }
        if let Some(result) = try_base_offset(right, left) {
            return Some(result);
        }
    }
    None
}

/// Try to extract (base_expr, non_negative_offset) from a single ordering.
fn try_base_offset(maybe_base: &MlilOperand, maybe_offset: &MlilOperand) -> Option<(MlilExpr, i64)> {
    let base = match maybe_base {
        MlilOperand::Expr(e) => *e.clone(),
        MlilOperand::Var(_) => MlilExpr::new(
            MlilOp::Var,
            8,
            vec![maybe_base.clone()],
            0,
        ),
        _ => return None,
    };

    let offset = match maybe_offset {
        MlilOperand::Imm(v) => *v,
        MlilOperand::U64(v) => v.checked_into()?,
        MlilOperand::Expr(e) if e.op == MlilOp::Const => match e.operands.first() {
            Some(MlilOperand::Imm(v)) => *v,
            _ => return None,
        },
        MlilOperand::Expr(e) if e.op == MlilOp::ConstPtr => match e.operands.first() {
            Some(MlilOperand::U64(v)) => v.checked_into()?,
            _ => return None,
        },
        _ => return None,
    };

    // Reject negative offsets — they represent regular pointer arithmetic
    if offset < 0 {
        return None;
    }

    Some((base, offset))
}

/// Safe u64→i64 conversion, rejecting values that would wrap negative.
trait CheckedInto<T> {
    fn checked_into(self) -> Option<T>;
}

impl CheckedInto<i64> for u64 {
    fn checked_into(self) -> Option<i64> {
        if self > i64::MAX as u64 {
            None
        } else {
            Some(self as i64)
        }
    }
}

fn is_llil_binary(op: LlilOp) -> bool {
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

fn map_binary_op(op: LlilOp) -> MlilOp {
    match op {
        LlilOp::Add => MlilOp::Add,
        LlilOp::Sub => MlilOp::Sub,
        LlilOp::Mul => MlilOp::Mul,
        LlilOp::DivS => MlilOp::DivS,
        LlilOp::DivU => MlilOp::DivU,
        LlilOp::And => MlilOp::And,
        LlilOp::Or => MlilOp::Or,
        LlilOp::Xor => MlilOp::Xor,
        LlilOp::Lsl => MlilOp::Lsl,
        LlilOp::Lsr => MlilOp::Lsr,
        LlilOp::Asr => MlilOp::Asr,
        LlilOp::Rol => MlilOp::Rol,
        LlilOp::Ror => MlilOp::Ror,
        LlilOp::CmpE => MlilOp::CmpE,
        LlilOp::CmpNe => MlilOp::CmpNe,
        LlilOp::CmpSlt => MlilOp::CmpSlt,
        LlilOp::CmpSle => MlilOp::CmpSle,
        LlilOp::CmpSge => MlilOp::CmpSge,
        LlilOp::CmpSgt => MlilOp::CmpSgt,
        LlilOp::CmpUlt => MlilOp::CmpUlt,
        LlilOp::CmpUle => MlilOp::CmpUle,
        LlilOp::CmpUge => MlilOp::CmpUge,
        LlilOp::CmpUgt => MlilOp::CmpUgt,
        _ => MlilOp::Unimpl,
    }
}

fn intrinsic_mlil(_e: &LlilExpr) -> MlilExpr {
    MlilExpr::new(
        MlilOp::Unimpl,
        0,
        vec![
            MlilOperand::Str("llil_op".into()),
            MlilOperand::Str(format!("{:#x}", _e.pc)),
        ],
        _e.pc,
    )
}

#[cfg(test)]
mod tests {
    use crate::llil::expr::{
        binary as llil_binary, const_ptr as llil_const_ptr, expr as llil_expr, flag as llil_flag,
        flag_cond as llil_flag_cond, konst as llil_konst, reg as llil_reg, set_flag,
        set_reg as llil_set_reg, LlilExpr, LlilOp, LlilOperand,
    };
    use crate::llil::pass_var_unify::VarNameMap;

    use super::*;

    fn test_names() -> VarNameMap {
        let mut m = VarNameMap::new();
        m.insert("x0#1".into(), "arg_0".into());
        m.insert("x1#1".into(), "var_1".into());
        m.insert("x2#1".into(), "ptr_2".into());
        m
    }

    #[test]
    fn lowers_set_reg_to_set_var() {
        let llil = llil_set_reg("x0#1", llil_konst(42), 0x1000);
        let (mlil, stats) = lower_llil_to_mlil(&[llil], &test_names());
        assert_eq!(stats.mlil_count, 1);
        assert_eq!(mlil[0].op, MlilOp::SetVar);
        assert!(mlil[0].short().contains("arg_0"), "got: {}", mlil[0].short());
        assert!(mlil[0].short().contains("0x2a"), "got: {}", mlil[0].short());
    }

    #[test]
    fn skips_flag_operations() {
        let flag_op = set_flag(
            "z",
            llil_binary(LlilOp::CmpE, llil_reg("x0#0"), llil_konst(0)),
            0x1000,
        );
        let (_, stats) = lower_llil_to_mlil(&[flag_op], &test_names());
        assert_eq!(stats.skipped_flags, 1);
        assert_eq!(stats.mlil_count, 0);
    }

    #[test]
    fn lowers_binary_expression() {
        let add = llil_binary(LlilOp::Add, llil_reg("x0#1"), llil_reg("x1#1"));
        let set = llil_set_reg("x2#1", add.clone(), 0x1000);
        let (mlil, _) = lower_llil_to_mlil(&[set], &test_names());
        assert_eq!(mlil[0].op, MlilOp::SetVar);
        assert!(mlil[0].short().contains("arg_0"));
        assert!(mlil[0].short().contains("var_1"));
        assert!(mlil[0].short().contains("+"));
    }

    #[test]
    fn lowers_load_to_load() {
        let load_llil = LlilExpr::new(
            LlilOp::Load,
            8,
            vec![llil_expr(llil_reg("x2#1"))],
            0x1000,
        );
        let set = llil_set_reg("x0#1", load_llil, 0x1000);
        let (mlil, _) = lower_llil_to_mlil(&[set], &test_names());
        assert_eq!(mlil[0].op, MlilOp::SetVar);
        assert!(mlil[0].short().contains("load.8"));
    }

    #[test]
    fn lowers_load_with_offset_to_load_struct() {
        // load from x2#1 + 16
        let addr = llil_binary(LlilOp::Add, llil_reg("x2#1"), llil_konst(16));
        let load_llil = LlilExpr::new(
            LlilOp::Load,
            8,
            vec![llil_expr(addr)],
            0x1000,
        );
        let set = llil_set_reg("x0#1", load_llil, 0x1000);
        let (mlil, _) = lower_llil_to_mlil(&[set], &test_names());
        assert_eq!(mlil[0].op, MlilOp::SetVar);
        assert!(mlil[0].short().contains("load_struct"));
    }

    #[test]
    fn lowers_if_with_folded_condition() {
        // if (x0#1 == 0) goto 0x2000 else goto 0x1008
        let cond = llil_binary(LlilOp::CmpE, llil_reg("x0#1"), llil_konst(0));
        let if_llil = LlilExpr::new(
            LlilOp::If,
            1,
            vec![
                llil_expr(cond),
                LlilOperand::U64(0x2000),
                LlilOperand::U64(0x1008),
            ],
            0x1000,
        );
        let (mlil, _) = lower_llil_to_mlil(&[if_llil], &test_names());
        assert_eq!(mlil[0].op, MlilOp::If);
        assert!(mlil[0].short().contains("=="));
    }

    #[test]
    fn lowers_call_and_ret() {
        let call = LlilExpr::new(
            LlilOp::Call,
            8,
            vec![LlilOperand::U64(0x5000)],
            0x1000,
        );
        let ret = LlilExpr::new(LlilOp::Ret, 8, vec![], 0x1004);
        let (mlil, _) = lower_llil_to_mlil(&[call, ret], &test_names());
        assert_eq!(mlil[0].op, MlilOp::Call);
        assert_eq!(mlil[1].op, MlilOp::Ret);
    }

    #[test]
    fn lowers_store_with_offset_to_store_struct() {
        let addr = llil_binary(LlilOp::Add, llil_reg("x2#1"), llil_konst(32));
        let store_llil = LlilExpr::new(
            LlilOp::Store,
            4,
            vec![llil_expr(addr), llil_expr(llil_reg("x0#1"))],
            0x1000,
        );
        let (mlil, _) = lower_llil_to_mlil(&[store_llil], &test_names());
        assert_eq!(mlil[0].op, MlilOp::StoreStruct);
        assert!(mlil[0].short().contains("store_struct"));
    }

    #[test]
    fn full_pipeline_integration() {
        // Test a realistic sequence:
        // x0#1 = 1
        // x1#1 = x0#1 + 3
        // if (x1#1 == 4) goto 0x2000 else 0x1000
        let exprs = vec![
            llil_set_reg("x0#1", llil_konst(1), 0x1000),
            llil_set_reg(
                "x1#1",
                llil_binary(LlilOp::Add, llil_reg("x0#1"), llil_konst(3)),
                0x1004,
            ),
            LlilExpr::new(
                LlilOp::If,
                1,
                vec![
                    llil_expr(llil_binary(LlilOp::CmpE, llil_reg("x1#1"), llil_konst(4))),
                    LlilOperand::U64(0x2000),
                    LlilOperand::U64(0x1000),
                ],
                0x1008,
            ),
        ];
        let names = test_names();
        let (mlil, stats) = lower_llil_to_mlil(&exprs, &names);
        assert_eq!(stats.mlil_count, 3);
        assert_eq!(stats.skipped_flags, 0);
        assert_eq!(mlil[0].op, MlilOp::SetVar);
        assert_eq!(mlil[1].op, MlilOp::SetVar);
        assert_eq!(mlil[2].op, MlilOp::If);
    }
}
