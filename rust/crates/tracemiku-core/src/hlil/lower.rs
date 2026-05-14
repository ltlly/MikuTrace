//! MLIL → HLIL lowering pass.
//!
//! Transforms variable-based MLIL into structured, high-level HLIL.
//!
//! Key transformations:
//!   1. SET_VAR       → ASSIGN
//!   2. LOAD          → DEREF
//!   3. LOAD_STRUCT   → DEREF_FIELD
//!   4. STORE         → ASSIGN(DEREF(addr), value)
//!   5. STORE_STRUCT  → ASSIGN(DEREF_FIELD(addr, offset), value)

use std::collections::BTreeSet;

use serde::Serialize;

use crate::llil::pass_var_unify::VarNameMap;
use crate::mlil::expr::{MlilExpr, MlilOp, MlilOperand};
use crate::hlil::expr::{
    assign, binary, deref, deref_field,
    expr, goto, if_else, label, ret as hlil_ret, var as hlil_var,
    HlilExpr, HlilOp, HlilOperand,
};
use crate::hlil::pass_restructure::restructure_hlil;

#[derive(Debug, Clone, Default, Serialize)]
pub struct LowerStats {
    pub mlil_count: usize,
    pub hlil_count: usize,
    pub stores_to_assigns: usize,
    pub unresolved: usize,
}

/// Lower MLIL expressions into HLIL.
pub fn lower_mlil_to_hlil(exprs: &[MlilExpr], _names: &VarNameMap) -> (Vec<HlilExpr>, LowerStats) {
    let mut out = Vec::new();
    let mut stats = LowerStats {
        mlil_count: exprs.len(),
        ..Default::default()
    };

    for e in exprs {
        if let Some(lowered) = lower_expr(e) {
            stats.hlil_count += 1;
            out.push(lowered);
        } else {
            stats.unresolved += 1;
        }
    }

    // Insert Label expressions at all Goto/If target addresses so the
    // renderer produces loc_*: labels alongside goto loc_*; statements.
    insert_labels(&mut out);
    // Restructure flat goto-based HLIL into structured control flow
    // (if/else, while, do-while).
    out = restructure_hlil(&out);
    stats.hlil_count = out.len();

    (out, stats)
}

fn lower_expr(e: &MlilExpr) -> Option<HlilExpr> {
    let pc = e.pc;
    match e.op {
        MlilOp::Nop => Some(HlilExpr::new(HlilOp::Nop, 0, vec![], pc)),

        // SET_VAR → ASSIGN
        MlilOp::SetVar => {
            let dst = match e.operands.first() {
                Some(MlilOperand::Var(v)) => hlil_var(v.clone()),
                _ => return None,
            };
            let value = match e.operands.get(1) {
                Some(MlilOperand::Expr(v)) => lower_expr(v)?,
                _ => return None,
            };
            Some(assign(dst, value, pc))
        }

        // SET_VAR_FIELD → ASSIGN(STRUCT_FIELD(...), value)
        MlilOp::SetVarField => {
            let base = match e.operands.first() {
                Some(MlilOperand::Var(v)) => hlil_var(v.clone()),
                _ => return None,
            };
            let offset = match e.operands.get(1) {
                Some(MlilOperand::Imm(v)) => *v,
                _ => return None,
            };
            let value = match e.operands.get(2) {
                Some(MlilOperand::Expr(v)) => lower_expr(v)?,
                _ => return None,
            };
            let dst = HlilExpr::new(
                HlilOp::StructField,
                8,
                vec![expr(base), HlilOperand::Imm(offset)],
                pc,
            );
            Some(assign(dst, value, pc))
        }

        // VAR → VAR
        MlilOp::Var => {
            let name = match e.operands.first() {
                Some(MlilOperand::Var(v)) => v.clone(),
                _ => return None,
            };
            Some(hlil_var(name))
        }

        // LOAD → DEREF
        MlilOp::Load => {
            let addr = match e.operands.first() {
                Some(MlilOperand::Expr(a)) => lower_expr(a)?,
                _ => return None,
            };
            Some(deref(e.size, addr, pc))
        }

        // LOAD_STRUCT → DEREF_FIELD
        MlilOp::LoadStruct => {
            let base = match e.operands.first() {
                Some(MlilOperand::Expr(b)) => lower_expr(b)?,
                _ => return None,
            };
            let offset = match e.operands.get(1) {
                Some(MlilOperand::Imm(v)) => *v,
                _ => return None,
            };
            Some(deref_field(e.size, base, offset, pc))
        }

        // STORE → ASSIGN(DEREF(addr), value)
        MlilOp::Store => {
            let addr = match e.operands.first() {
                Some(MlilOperand::Expr(a)) => lower_expr(a)?,
                _ => return None,
            };
            let value = match e.operands.get(1) {
                Some(MlilOperand::Expr(v)) => lower_expr(v)?,
                _ => return None,
            };
            let deref_expr = deref(e.size, addr, pc);
            Some(assign(deref_expr, value, pc))
        }

        // STORE_STRUCT → ASSIGN(DEREF_FIELD(addr, offset), value)
        MlilOp::StoreStruct => {
            let base = match e.operands.first() {
                Some(MlilOperand::Expr(b)) => lower_expr(b)?,
                _ => return None,
            };
            let offset = match e.operands.get(1) {
                Some(MlilOperand::Imm(v)) => *v,
                _ => return None,
            };
            let value = match e.operands.get(2) {
                Some(MlilOperand::Expr(v)) => lower_expr(v)?,
                _ => return None,
            };
            let df = deref_field(e.size, base, offset, pc);
            Some(assign(df, value, pc))
        }

        // Constants
        MlilOp::Const => {
            let ops: Vec<HlilOperand> = e
                .operands
                .iter()
                .map(lower_operand)
                .collect();
            Some(HlilExpr::new(HlilOp::Const, e.size, ops, pc))
        }
        MlilOp::ConstPtr => {
            let ops: Vec<HlilOperand> = e
                .operands
                .iter()
                .map(lower_operand)
                .collect();
            Some(HlilExpr::new(HlilOp::ConstPtr, e.size, ops, pc))
        }
        MlilOp::ConstData => {
            let ops: Vec<HlilOperand> = e
                .operands
                .iter()
                .map(lower_operand)
                .collect();
            Some(HlilExpr::new(HlilOp::ConstData, e.size, ops, pc))
        }

        // Control flow
        MlilOp::Jump => {
            let target = match e.operands.first() {
                Some(o) => lower_operand(o),
                _ => return None,
            };
            Some(HlilExpr::new(HlilOp::Jump, e.size, vec![target], pc))
        }
        MlilOp::Goto => {
            let t = match e.operands.first() {
                Some(MlilOperand::U64(v)) => *v,
                _ => return None,
            };
            Some(goto(t, pc))
        }
        MlilOp::If => {
            let cond = match e.operands.first() {
                Some(MlilOperand::Expr(c)) => lower_expr(c)?,
                _ => return None,
            };
            let t = match e.operands.get(1) {
                Some(MlilOperand::U64(v)) => *v,
                _ => return None,
            };
            let f = match e.operands.get(2) {
                Some(MlilOperand::U64(v)) => *v,
                _ => return None,
            };
            // At the basic lowering level, If stays as structured if with goto bodies
            let then_body = goto(t, pc);
            let else_body = goto(f, pc);
            Some(if_else(cond, then_body, Some(else_body), pc))
        }
        MlilOp::Call => {
            let target = match e.operands.first() {
                Some(o) => lower_operand(o),
                _ => return None,
            };
            Some(HlilExpr::new(HlilOp::Call, e.size, vec![target], pc))
        }
        MlilOp::Tailcall => {
            let target = match e.operands.first() {
                Some(o) => lower_operand(o),
                _ => return None,
            };
            Some(HlilExpr::new(HlilOp::Tailcall, e.size, vec![target], pc))
        }
        MlilOp::Ret => Some(hlil_ret(pc)),
        MlilOp::Noret => Some(HlilExpr::new(HlilOp::Noret, e.size, vec![], pc)),

        // Binary ops
        op if is_mlil_binary(op) => {
            let lhs = match e.operands.first() {
                Some(MlilOperand::Expr(v)) => lower_expr(v)?,
                _ => return None,
            };
            let rhs = match e.operands.get(1) {
                Some(MlilOperand::Expr(v)) => lower_expr(v)?,
                _ => return None,
            };
            Some(binary(map_binary_op(op), lhs, rhs))
        }

        // Unary ops
        MlilOp::Neg | MlilOp::Not => {
            let val = match e.operands.first() {
                Some(MlilOperand::Expr(v)) => lower_expr(v)?,
                _ => return None,
            };
            let op = match e.op {
                MlilOp::Neg => HlilOp::Neg,
                MlilOp::Not => HlilOp::Not,
                _ => unreachable!(),
            };
            Some(HlilExpr::new(op, e.size, vec![expr(val)], pc))
        }

        // Extend
        MlilOp::Sx | MlilOp::Zx | MlilOp::LowPart => {
            let val = match e.operands.first() {
                Some(MlilOperand::Expr(v)) => lower_expr(v)?,
                _ => return None,
            };
            let op = match e.op {
                MlilOp::Sx => HlilOp::Sx,
                MlilOp::Zx => HlilOp::Zx,
                MlilOp::LowPart => HlilOp::LowPart,
                _ => unreachable!(),
            };
            Some(HlilExpr::new(op, e.size, vec![expr(val)], pc))
        }

        // Csel
        MlilOp::Csel => {
            let cond = match e.operands.first() {
                Some(MlilOperand::Expr(v)) => lower_expr(v)?,
                _ => return None,
            };
            let t_val = match e.operands.get(1) {
                Some(MlilOperand::Expr(v)) => lower_expr(v)?,
                _ => return None,
            };
            let f_val = match e.operands.get(2) {
                Some(MlilOperand::Expr(v)) => lower_expr(v)?,
                _ => return None,
            };
            Some(HlilExpr::new(
                HlilOp::Csel,
                e.size,
                vec![expr(cond), expr(t_val), expr(f_val)],
                pc,
            ))
        }

        // Intrinsic / Trap / Bp
        MlilOp::Intrinsic => {
            let ops: Vec<HlilOperand> = e
                .operands
                .iter()
                .map(lower_operand)
                .collect();
            let mut out = HlilExpr::new(HlilOp::Intrinsic, e.size, ops, pc);
            out.extra = e.extra.clone();
            Some(out)
        }
        MlilOp::Trap => Some(HlilExpr::new(HlilOp::Trap, e.size, vec![], pc)),
        MlilOp::Bp => Some(HlilExpr::new(HlilOp::Bp, e.size, vec![], pc)),

        // AddressOf
        MlilOp::AddressOf => {
            let val = match e.operands.first() {
                Some(MlilOperand::Expr(v)) => lower_expr(v)?,
                _ => return None,
            };
            Some(HlilExpr::new(HlilOp::AddressOf, e.size, vec![expr(val)], pc))
        }
        MlilOp::AddressOfField => {
            let base = match e.operands.first() {
                Some(MlilOperand::Expr(v)) => lower_expr(v)?,
                _ => return None,
            };
            let offset = match e.operands.get(1) {
                Some(MlilOperand::Imm(v)) => *v,
                _ => return None,
            };
            Some(HlilExpr::new(
                HlilOp::AddressOfField,
                e.size,
                vec![expr(base), HlilOperand::Imm(offset)],
                pc,
            ))
        }

        _ => None,
    }
}

fn lower_operand(op: &MlilOperand) -> HlilOperand {
    match op {
        MlilOperand::Expr(e) => {
            match lower_expr(e) {
                Some(hlil_e) => expr(hlil_e),
                None => HlilOperand::Str("__unimpl".into()),
            }
        }
        MlilOperand::Var(v) => HlilOperand::Var(v.clone()),
        MlilOperand::Imm(v) => HlilOperand::Imm(*v),
        MlilOperand::U64(v) => HlilOperand::U64(*v),
        MlilOperand::Str(s) => HlilOperand::Str(s.clone()),
    }
}

fn is_mlil_binary(op: MlilOp) -> bool {
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

// ============================================================================
// Label insertion — post-lowering pass
// ============================================================================

/// After lowering, scan HLIL for `goto` and `if` targets and insert a `Label`
/// expression before the first HLIL expression whose address matches each
/// unique target.  This ensures the renderer produces `loc_xxx:` labels.
fn insert_labels(exprs: &mut Vec<HlilExpr>) {
    let targets = collect_goto_targets(exprs);
    if targets.is_empty() {
        return;
    }
    let mut i = 0;
    while i < exprs.len() {
        if exprs[i].op != HlilOp::Label && targets.contains(&exprs[i].pc) {
            let name = format!("loc_{:x}", exprs[i].pc);
            exprs.insert(i, label(&name, exprs[i].pc));
            i += 1; // skip past the newly inserted label
        }
        i += 1;
    }
}


/// Recursively collect every address targeted by a `Goto` op (at the top
/// level or nested inside `If`, `Block`, `While`, `DoWhile` bodies).
fn collect_goto_targets(exprs: &[HlilExpr]) -> BTreeSet<u64> {
    let mut targets = BTreeSet::new();
    for e in exprs {
        collect_targets_from_expr(e, &mut targets);
    }
    targets
}

fn collect_targets_from_expr(e: &HlilExpr, targets: &mut BTreeSet<u64>) {
    match e.op {
        HlilOp::Goto => {
            if let Some(HlilOperand::U64(t)) = e.operands.first() {
                targets.insert(*t);
            }
        }
        HlilOp::If | HlilOp::Block | HlilOp::While | HlilOp::DoWhile => {
            for op in &e.operands {
                if let HlilOperand::Expr(child) = op {
                    collect_targets_from_expr(child, targets);
                }
            }
        }
        _ => {}
    }
}

fn map_binary_op(op: MlilOp) -> HlilOp {
    match op {
        MlilOp::Add => HlilOp::Add,
        MlilOp::Sub => HlilOp::Sub,
        MlilOp::Mul => HlilOp::Mul,
        MlilOp::DivS => HlilOp::DivS,
        MlilOp::DivU => HlilOp::DivU,
        MlilOp::ModS => HlilOp::ModS,
        MlilOp::ModU => HlilOp::ModU,
        MlilOp::And => HlilOp::And,
        MlilOp::Or => HlilOp::Or,
        MlilOp::Xor => HlilOp::Xor,
        MlilOp::Lsl => HlilOp::Lsl,
        MlilOp::Lsr => HlilOp::Lsr,
        MlilOp::Asr => HlilOp::Asr,
        MlilOp::Rol => HlilOp::Rol,
        MlilOp::Ror => HlilOp::Ror,
        MlilOp::CmpE => HlilOp::CmpE,
        MlilOp::CmpNe => HlilOp::CmpNe,
        MlilOp::CmpSlt => HlilOp::CmpSlt,
        MlilOp::CmpSle => HlilOp::CmpSle,
        MlilOp::CmpSge => HlilOp::CmpSge,
        MlilOp::CmpSgt => HlilOp::CmpSgt,
        MlilOp::CmpUlt => HlilOp::CmpUlt,
        MlilOp::CmpUle => HlilOp::CmpUle,
        MlilOp::CmpUge => HlilOp::CmpUge,
        MlilOp::CmpUgt => HlilOp::CmpUgt,
        _ => HlilOp::Unimpl,
    }
}

#[cfg(test)]
mod tests {
    use crate::mlil::expr::{
        binary as mlil_binary, expr as mlil_expr, konst as mlil_konst, load as mlil_load,
        load_struct as mlil_load_struct, set_var as mlil_set_var, store as mlil_store,
        store_struct as mlil_store_struct, var as mlil_var, MlilExpr, MlilOp, MlilOperand,
    };
    use crate::mlil::lower::{LowerStats as MlilLowerStats, lower_llil_to_mlil};
    use crate::llil::expr::{
        binary as llil_binary, konst as llil_konst, reg as llil_reg,
        set_reg as llil_set_reg, LlilExpr, LlilOp, LlilOperand,
    };
    use crate::llil::pass_var_unify::VarNameMap;

    use super::*;

    fn test_names() -> VarNameMap {
        let mut m = VarNameMap::new();
        m.insert("x0#1".into(), "v0".into());
        m.insert("x1#1".into(), "v1".into());
        m.insert("x2#1".into(), "ptr".into());
        m
    }

    #[test]
    fn lowers_set_var_to_assign() {
        let mlil = mlil_set_var("v0", mlil_konst(42), 0x1000);
        let (hlil, stats) = lower_mlil_to_hlil(&[mlil], &test_names());
        assert_eq!(stats.hlil_count, 1);
        assert_eq!(hlil[0].op, HlilOp::Assign);
    }

    #[test]
    fn lowers_load_to_deref() {
        let mlil = mlil_load(8, mlil_var("ptr"), 0x1000);
        let (hlil, _) = lower_mlil_to_hlil(&[mlil], &test_names());
        assert_eq!(hlil[0].op, HlilOp::Deref);
    }

    #[test]
    fn lowers_store_to_assign_deref() {
        let mlil = mlil_store(8, mlil_var("ptr"), mlil_var("v0"), 0x1000);
        let (hlil, _) = lower_mlil_to_hlil(&[mlil], &test_names());
        assert_eq!(hlil[0].op, HlilOp::Assign);
        // The assign dest should be a Deref
        match hlil[0].operands.first() {
            Some(HlilOperand::Expr(e)) => assert_eq!(e.op, HlilOp::Deref),
            _ => panic!("Expected Deref expression as assign dest"),
        }
    }

    #[test]
    fn lowers_load_struct_to_deref_field() {
        let mlil = mlil_load_struct(4, mlil_var("ptr"), 0x10, 0x1000);
        let (hlil, _) = lower_mlil_to_hlil(&[mlil], &test_names());
        assert_eq!(hlil[0].op, HlilOp::DerefField);
    }

    #[test]
    fn insert_labels_at_goto_targets() {
        // Two instructions: a goto at 0x1000 targeting 0x1008, then a set_var at 0x1008
        let mlil_exprs = vec![
            // Goto to 0x1008
            MlilExpr::new(MlilOp::Goto, 8, vec![MlilOperand::U64(0x1008)], 0x1000),
            // Target instruction at 0x1008
            mlil_set_var("v0", mlil_konst(42), 0x1008),
        ];
        let (hlil, _) = lower_mlil_to_hlil(&mlil_exprs, &VarNameMap::new());
        // The output should contain a Label before the target
        assert_eq!(hlil.len(), 3, "expected 3 exprs: goto + label + assign, got {}: {:#?}", hlil.len(), hlil);
        assert_eq!(hlil[0].op, HlilOp::Goto, "first should be Goto");
        assert_eq!(hlil[1].op, HlilOp::Label, "second should be Label");
        assert_eq!(hlil[2].op, HlilOp::Assign, "third should be Assign");
        // Verify label name
        if let Some(HlilOperand::Str(name)) = hlil[1].operands.first() {
            assert_eq!(name, "loc_1008");
        } else {
            panic!("Label operand should be a Str");
        }
    }

    #[test]
    fn restructures_if_at_targets() {
        // MLIL If: cond=v0, true=0x1008, false=0x1010
        // Then expressions at 0x1008 and 0x1010
        // After restructuring, the If should have a structured body.
        let cond = mlil_var("v0");
        let mlil_exprs = vec![
            MlilExpr::new(
                MlilOp::If,
                1,
                vec![
                    mlil_expr(cond),
                    MlilOperand::U64(0x1008),
                    MlilOperand::U64(0x1010),
                ],
                0x1000,
            ),
            mlil_set_var("v1", mlil_konst(1), 0x1008),
            mlil_set_var("v2", mlil_konst(2), 0x1010),
        ];
        let (hlil, _) = lower_mlil_to_hlil(&mlil_exprs, &VarNameMap::new());
        // After restructuring: If(cond, Block([Assign v1=1]), None) + Label + assign v2=2
        // The false branch (0x1010) is the fallthrough (no convergence), so it's an if-then.
        assert!(hlil.len() >= 2, "expected at least 2 exprs, got {}: {:#?}", hlil.len(), hlil);
        assert_eq!(hlil[0].op, HlilOp::If, "first should be structured If");
        // The If should have a block body (not just a goto)
        if let Some(HlilOperand::Expr(body)) = hlil[0].operands.get(1) {
            assert_eq!(body.op, HlilOp::Block, "If body should be Block");
            // The block should contain the assign
            assert!(body.operands.iter().any(|o| {
                matches!(o, HlilOperand::Expr(e) if e.op == HlilOp::Assign)
            }), "If block body should contain an Assign");
        } else {
            panic!("If should have a Block body, got: {:?}", hlil[0]);
        }
    }

    #[test]
    fn full_llil_to_hlil_pipeline() {
        // llil: x0#1 = 1; x1#1 = x0#1 + 3; ret
        let llil_exprs = vec![
            llil_set_reg("x0#1", llil_konst(1), 0x1000),
            llil_set_reg(
                "x1#1",
                llil_binary(LlilOp::Add, llil_reg("x0#1"), llil_konst(3)),
                0x1004,
            ),
            LlilExpr::new(LlilOp::Ret, 8, vec![], 0x1008),
        ];
        let names = test_names();

        // Lower: LLIL → MLIL
        let (mlil, _) = lower_llil_to_mlil(&llil_exprs, &names);

        // Lower: MLIL → HLIL
        let (hlil, stats) = lower_mlil_to_hlil(&mlil, &names);
        assert!(stats.hlil_count >= 2);
        assert_eq!(hlil.last().unwrap().op, HlilOp::Ret);
    }
}
