//! Fold flag-setting N/Z/C/V statements into following conditional branches.
//!
//! M5: NZCV model — tracks N, Z, C, V flags independently and maps ARM64
//! condition codes to the required flag value expressions.

use std::collections::BTreeMap;

use crate::llil::expr::{binary, expr, konst, LlilExpr, LlilOp, LlilOperand};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagElimResult {
    pub exprs: Vec<LlilExpr>,
    pub folded_pairs: Vec<(u64, u64)>,
}

pub fn flag_elim_block(exprs: &[LlilExpr]) -> FlagElimResult {
    let mut out = Vec::new();
    let mut folded_pairs = Vec::new();
    let mut pending_flags: BTreeMap<String, (u64, LlilExpr)> = BTreeMap::new();

    for e in exprs {
        if let Some((flag_name, value)) = detect_set_flag(e) {
            pending_flags.insert(flag_name, (e.pc, value));
            continue;
        }
        if e.op == LlilOp::If {
            if let Some(cond_str) = flag_cond_str(e) {
                if let Some(mut folded) = fold_if_from_flags(e, cond_str, &pending_flags) {
                    // Record all consumed pending flags
                    let needed = flags_needed_for_cond(cond_str);
                    for name in needed {
                        if let Some((cmp_pc, _)) = pending_flags.get(&name) {
                            folded_pairs.push((*cmp_pc, e.pc));
                        }
                    }
                    folded
                        .extra
                        .insert("flag_elim".to_string(), format!("nzcv:{}", cond_str));
                    out.push(folded);
                    // Don't clear pending flags — other branches may also consume
                    continue;
                }
            }
        }

        // NEW: Fold FlagCond in any non-If expression (e.g. Csel inside SetReg).
        // This resolves the case where Csel(FlagCond("eq"), ...) reaches MLIL
        // lower and causes the entire instruction to be silently dropped.
        if contains_flag_cond(e) {
            let folded = fold_flags_in_expr(e, &pending_flags);
            out.push(folded);
            // Flags stay in pending (they are read-only and may be reused).
            continue;
        }
        // Flush any pending flags that were used as non-branch setflags
        if e.op == LlilOp::If
            || e.is_control_flow()
            || matches!(
                e.op,
                LlilOp::SetFlag | LlilOp::Call | LlilOp::Load | LlilOp::Store
            )
        {
            if !matches!(e.op, LlilOp::If) && !matches!(e.op, LlilOp::SetFlag) {
                // Control flow or side-effecting instruction: flush remaining pending
                for (flag_name, (pc, val)) in std::mem::take(&mut pending_flags).into_iter() {
                    let restored = set_flag_from_val(&flag_name, pc, &val);
                    out.push(restored);
                }
            }
        }

        if !matches!(e.op, LlilOp::SetFlag) {
            out.push(e.clone());
        }
    }

    // Flush remaining flags at end of block
    for (flag_name, (pc, val)) in pending_flags.into_iter() {
        let restored = set_flag_from_val(&flag_name, pc, &val);
        out.push(restored);
    }

    FlagElimResult {
        exprs: out,
        folded_pairs,
    }
}

/// Returns (flag_name, value_expr) if this is a SetFlag for n/z/c/v.
fn detect_set_flag(e: &LlilExpr) -> Option<(String, LlilExpr)> {
    if e.op != LlilOp::SetFlag {
        return None;
    }
    match (e.operands.first(), e.operands.get(1)) {
        (Some(LlilOperand::Flag(name)), Some(LlilOperand::Expr(value)))
            if name == "n" || name == "z" || name == "c" || name == "v" =>
        {
            Some((name.clone(), (**value).clone()))
        }
        _ => None,
    }
}

/// Extract the condition string from an IF(FlagCond).
fn flag_cond_str(e: &LlilExpr) -> Option<&str> {
    if e.op != LlilOp::If {
        return None;
    }
    match e.operands.first() {
        Some(LlilOperand::Expr(cond)) if cond.op == LlilOp::FlagCond => {
            match cond.operands.first() {
                Some(LlilOperand::Str(s)) => Some(s.as_str()),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Which flags does this condition need?
fn flags_needed_for_cond(cond: &str) -> Vec<String> {
    match cond {
        "eq" | "ne" => vec!["z".to_string()],
        "cs" | "hs" | "cc" | "lo" => vec!["c".to_string()],
        "mi" | "pl" => vec!["n".to_string()],
        "vs" | "vc" => vec!["v".to_string()],
        "hi" | "ls" => vec!["c".to_string(), "z".to_string()],
        "ge" | "lt" => vec!["n".to_string(), "v".to_string()],
        "gt" | "le" => vec!["n".to_string(), "v".to_string(), "z".to_string()],
        _ => vec![],
    }
}

/// Try to fold IF(FlagCond) using pending flag values.
fn fold_if_from_flags(
    e: &LlilExpr,
    cond: &str,
    pending: &BTreeMap<String, (u64, LlilExpr)>,
) -> Option<LlilExpr> {
    let new_cond = cond_expr_from_flags(cond, pending)?;
    let mut out = e.clone();
    out.operands[0] = expr(new_cond);
    Some(out)
}

/// Build the comparison expression for a condition given pending flag values.
///
/// First tries to recognize simple compare patterns (e.g. `cmp X, #0`).
/// Falls back to building the expression from raw NZCV flag values.
fn cond_expr_from_flags(
    cond: &str,
    pending: &BTreeMap<String, (u64, LlilExpr)>,
) -> Option<LlilExpr> {
    // Optimisation: if all flags come from the same cmp X, Y, produce a direct comparison
    if let Some(simple) = try_simple_cmp_fold(cond, pending) {
        return Some(simple);
    }

    let get = |flag: &str| pending.get(flag).map(|(_, v)| v.clone());

    match cond {
        "eq" => get("z"),
        "ne" => get("z")
            .and_then(invert_z_for_ne)
            .or_else(|| get("z").map(|z| binary(LlilOp::CmpE, z, konst(0)))),
        "cs" | "hs" => get("c"),
        "cc" | "lo" => get("c").map(|c| binary(LlilOp::CmpE, c, konst(0))),
        "mi" => get("n"),
        "pl" => get("n").map(|n| binary(LlilOp::CmpE, n, konst(0))),
        "vs" => get("v"),
        "vc" => get("v").map(|v| binary(LlilOp::CmpE, v, konst(0))),
        "hi" => {
            let c = get("c")?;
            let z = get("z")?;
            let z_false = binary(LlilOp::CmpE, z, konst(0));
            Some(binary(LlilOp::And, c, z_false))
        }
        "ls" => {
            let c = get("c")?;
            let z = get("z")?;
            let c_false = binary(LlilOp::CmpE, c, konst(0));
            Some(binary(LlilOp::Or, c_false, z))
        }
        "ge" => {
            let n = get("n")?;
            let v = get("v")?;
            Some(binary(LlilOp::CmpE, n, v))
        }
        "lt" => {
            let n = get("n")?;
            let v = get("v")?;
            Some(binary(LlilOp::CmpNe, n, v))
        }
        "gt" => {
            let n = get("n")?;
            let v = get("v")?;
            let z = get("z")?;
            let z_false = binary(LlilOp::CmpE, z, konst(0));
            let n_eq_v = binary(LlilOp::CmpE, n, v);
            Some(binary(LlilOp::And, z_false, n_eq_v))
        }
        "le" => {
            let n = get("n")?;
            let v = get("v")?;
            let z = get("z")?;
            let n_ne_v = binary(LlilOp::CmpNe, n, v);
            Some(binary(LlilOp::Or, z, n_ne_v))
        }
        _ => None,
    }
}

/// Try to fold a cmp+b.cond into a simple comparison when all flags come from the same sub.
///
/// Pattern: `cmp X, Y` sets N/Z/C/V via sub. We extract X and Y from the flag
/// expressions and produce a direct `X <comp> Y` instead of the full flag logic.
fn try_simple_cmp_fold(
    cond: &str,
    pending: &BTreeMap<String, (u64, LlilExpr)>,
) -> Option<LlilExpr> {
    // Extract lhs/rhs from N flag: N = CmpSlt(result, 0) = CmpSlt(X - Y, 0)
    // If we can find a common (lhs, rhs) pair across all flags, fold directly.
    let n_val = pending.get("n")?.1.clone();
    let z_val = pending.get("z")?.1.clone();

    // N is CmpSlt(sub_result, 0). Extract the sub_result.
    let sub_result = extract_sub_result(&n_val)?;

    // Z is CmpE(sub_result, 0). Extract and check consistency.
    let z_sub = extract_sub_result_from_z(&z_val)?;
    if !expr_eq(&sub_result, &z_sub) {
        return None; // Inconsistent — flags from different instructions
    }

    // sub_result = X - Y. Extract X and Y.
    let (lhs, rhs) = extract_binary_operands(&sub_result, LlilOp::Sub)?;

    // Now produce the direct comparison based on the condition
    map_cond_to_comparison(cond, lhs, rhs)
}

/// Extract the sub_result from N = CmpSlt(sub_result, 0).
fn extract_sub_result(n: &LlilExpr) -> Option<LlilExpr> {
    if n.op != LlilOp::CmpSlt || n.operands.len() != 2 {
        return None;
    }
    let rhs = match n.operands.get(1) {
        Some(LlilOperand::Imm(0)) => true,
        Some(LlilOperand::Expr(e)) if e.op == LlilOp::Const => {
            matches!(e.operands.first(), Some(LlilOperand::Imm(0)))
        }
        _ => false,
    };
    if !rhs {
        return None;
    }
    match n.operands.first() {
        Some(LlilOperand::Expr(e)) => Some(*e.clone()),
        _ => None,
    }
}

/// Extract sub_result from Z = CmpE(sub_result, 0).
fn extract_sub_result_from_z(z: &LlilExpr) -> Option<LlilExpr> {
    if z.op != LlilOp::CmpE || z.operands.len() != 2 {
        return None;
    }
    let rhs = match z.operands.get(1) {
        Some(LlilOperand::Imm(0)) => true,
        Some(LlilOperand::Expr(e)) if e.op == LlilOp::Const => {
            matches!(e.operands.first(), Some(LlilOperand::Imm(0)))
        }
        _ => false,
    };
    if !rhs {
        return None;
    }
    match z.operands.first() {
        Some(LlilOperand::Expr(e)) => Some(*e.clone()),
        _ => None,
    }
}

/// Extract (lhs, rhs) from a binary expression: lhs - rhs or lhs + rhs.
fn extract_binary_operands(e: &LlilExpr, expected_op: LlilOp) -> Option<(LlilExpr, LlilExpr)> {
    if e.op != expected_op || e.operands.len() != 2 {
        return None;
    }
    let lhs = match e.operands.first() {
        Some(LlilOperand::Expr(v)) => *v.clone(),
        _ => return None,
    };
    let rhs = match e.operands.get(1) {
        Some(LlilOperand::Expr(v)) => *v.clone(),
        Some(LlilOperand::Imm(v)) => LlilExpr::new(LlilOp::Const, 8, vec![LlilOperand::Imm(*v)], 0),
        _ => return None,
    };
    Some((lhs, rhs))
}

/// Map an ARM condition code to a direct comparison between lhs and rhs.
fn map_cond_to_comparison(cond: &str, lhs: LlilExpr, rhs: LlilExpr) -> Option<LlilExpr> {
    match cond {
        "eq" => Some(binary(LlilOp::CmpE, lhs, rhs)),
        "ne" => Some(binary(LlilOp::CmpNe, lhs, rhs)),
        "cs" | "hs" => Some(binary(LlilOp::CmpUge, lhs, rhs)),
        "cc" | "lo" => Some(binary(LlilOp::CmpUlt, lhs, rhs)),
        "mi" => Some(binary(LlilOp::CmpSlt, lhs, konst(0))), // N flag: result < 0
        "pl" => Some(binary(LlilOp::CmpSge, lhs, konst(0))), // !N
        "vs" => None, // Overflow flag — keep complex expression
        "vc" => None,
        "hi" => Some(binary(LlilOp::CmpUgt, lhs, rhs)),
        "ls" => Some(binary(LlilOp::CmpUle, lhs, rhs)),
        "ge" => Some(binary(LlilOp::CmpSge, lhs, rhs)),
        "lt" => Some(binary(LlilOp::CmpSlt, lhs, rhs)),
        "gt" => Some(binary(LlilOp::CmpSgt, lhs, rhs)),
        "le" => Some(binary(LlilOp::CmpSle, lhs, rhs)),
        _ => None,
    }
}

/// Quick structural equality check for two expression trees.
fn expr_eq(a: &LlilExpr, b: &LlilExpr) -> bool {
    if a.op != b.op || a.operands.len() != b.operands.len() {
        return false;
    }
    for (ao, bo) in a.operands.iter().zip(b.operands.iter()) {
        match (ao, bo) {
            (LlilOperand::Expr(ae), LlilOperand::Expr(be)) => {
                if !expr_eq(ae, be) {
                    return false;
                }
            }
            _ => {
                if ao != bo {
                    return false;
                }
            }
        }
    }
    true
}

/// If Z = CmpE(X, 0) then ne = CmpNe(X, 0)
fn invert_z_for_ne(z_val: LlilExpr) -> Option<LlilExpr> {
    if z_val.op == LlilOp::CmpE {
        let left = z_val.operands.first()?.clone();
        let right = z_val.operands.get(1)?.clone();
        Some(LlilExpr::new(
            LlilOp::CmpNe,
            z_val.size,
            vec![left, right],
            z_val.pc,
        ))
    } else {
        None
    }
}

/// Check if an expression tree contains a FlagCond at any depth.
fn contains_flag_cond(e: &LlilExpr) -> bool {
    if e.op == LlilOp::FlagCond {
        return true;
    }
    for op in &e.operands {
        if let LlilOperand::Expr(child) = op {
            if contains_flag_cond(child) {
                return true;
            }
        }
    }
    false
}

/// Recursively fold every FlagCond in an expression tree using pending flags.
///
/// When the required flags are available, the FlagCond is replaced with a
/// direct comparison expression (e.g. `CmpE(x, y)`).  When flags are missing
/// the FlagCond is left in place — it will be caught later by the MLIL
/// fallback path.
fn fold_flags_in_expr(e: &LlilExpr, pending: &BTreeMap<String, (u64, LlilExpr)>) -> LlilExpr {
    let mut out = e.clone();
    for i in 0..out.operands.len() {
        match &out.operands[i] {
            LlilOperand::Expr(child) => {
                if child.op == LlilOp::FlagCond {
                    if let Some(LlilOperand::Str(cond_str)) = child.operands.first() {
                        if let Some(folded) = cond_expr_from_flags(cond_str.as_str(), pending) {
                            out.operands[i] = expr(folded);
                        }
                    }
                } else {
                    let folded = fold_flags_in_expr(child, pending);
                    out.operands[i] = expr(folded);
                }
            }
            _ => {}
        }
    }
    out
}

fn set_flag_from_val(flag_name: &str, pc: u64, val: &LlilExpr) -> LlilExpr {
    // Reconstruct a SetFlag with the preserved flag name.
    LlilExpr::new(
        LlilOp::SetFlag,
        1,
        vec![LlilOperand::Flag(flag_name.to_string()), expr(val.clone())],
        pc,
    )
}

#[cfg(test)]
mod tests {
    use crate::llil::expr::{
        binary, flag_cond, konst, reg, set_flag, LlilExpr, LlilOp, LlilOperand,
    };

    use super::*;

    #[test]
    fn folds_nzcv_cmp_into_if_eq() {
        // cmp x0, x1 produces n, z, c, v
        let result = binary(LlilOp::Sub, reg("x0"), konst(3));
        let n = set_flag(
            "n",
            binary(LlilOp::CmpSlt, result.clone(), konst(0)),
            0x1000,
        );
        let z = set_flag("z", binary(LlilOp::CmpE, result.clone(), konst(0)), 0x1000);
        let c = set_flag("c", binary(LlilOp::CmpUge, reg("x0"), konst(3)), 0x1000);
        let v = set_flag("v", konst(0), 0x1000);
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
        let result = flag_elim_block(&[n.clone(), z.clone(), c.clone(), v.clone(), br]);
        assert_eq!(result.folded_pairs.len(), 1);
        assert_eq!(result.folded_pairs[0], (0x1000, 0x1004));
        // The ne condition should also work
        let c2 = set_flag("c", binary(LlilOp::CmpUge, reg("x0"), konst(3)), 0x1000);
        let br_ne = LlilExpr::new(
            LlilOp::If,
            1,
            vec![
                expr(flag_cond("ne")),
                LlilOperand::U64(0x2000),
                LlilOperand::U64(0x1008),
            ],
            0x1004,
        );
        let result2 = flag_elim_block(&[n.clone(), z.clone(), c2, v.clone(), br_ne]);
        assert_eq!(result2.folded_pairs.len(), 1);
    }

    #[test]
    fn folds_ne_by_inverting_z() {
        let result = binary(LlilOp::Sub, reg("x0"), konst(3));
        let z = set_flag("z", binary(LlilOp::CmpE, result.clone(), konst(0)), 0x1000);
        let br_ne = LlilExpr::new(
            LlilOp::If,
            1,
            vec![
                expr(flag_cond("ne")),
                LlilOperand::U64(0x2000),
                LlilOperand::U64(0x1008),
            ],
            0x1004,
        );
        let r = flag_elim_block(&[z, br_ne]);
        assert_eq!(r.folded_pairs.len(), 1);
        assert!(r.exprs[0].short().contains("!="));
    }
}
