//! Multi-precision arithmetic merging pass (Ghidra SplitVarnode / AddForm / SubForm).
//!
//! Detects ARM64 multi-precision arithmetic patterns in LLIL and replaces them
//! with canonical multi-precision expressions.
//!
//! Patterns detected:
//!
//!   SplitVarnode — 64-bit value split into two 32-bit halves:
//!     SetReg(lo, And(src, 0xFFFFFFFF))  or  SetReg(lo, LowPart_4(src))
//!     SetReg(hi, Lsr(src, 32))
//!     → both annotated as split halves of the wider value
//!
//!   AddForm — 128-bit addition through ADDS+ADC chain:
//!     SetReg(lo, Add(a_lo, b_lo))        // adds (flag-setting)
//!     SetFlag(C, ...)                     // carry produced
//!     SetReg(hi, Add(Add(a_hi, b_hi), C)) // adc (carry-consuming)
//!     → replaced with SetReg(hi:lo, MpAdd(a_hi, a_lo, b_hi, b_lo))
//!
//!   SubForm — 128-bit subtraction through SUBS+SBC chain:
//!     SetReg(lo, Sub(a_lo, b_lo))                // subs
//!     SetFlag(C, ...)                             // borrow/carry
//!     SetReg(hi, Sub(Sub(a_hi, b_hi), C))         // sbc
//!     → replaced with SetReg(hi:lo, MpSub(a_hi, a_lo, b_hi, b_lo))
//!
//!   WidenMul — 32x32→64 multiply (UMULL/SMULL):
//!     SetReg(dst8, Mul(Zx(w_src1), Zx(w_src2)))   // umull
//!     SetReg(dst8, Mul(Sx(w_src1), Sx(w_src2)))   // smull
//!     → replaced with SetReg(dst, MpMul(src1, src2))
//!
//!   CarryFlag — detection and annotation of NZCV flag usage for carry propagation.
//!     Flags "C", "CF", "nzcv.C", or similar are tracked as carry chain links.
//!
//! This pass runs in Phase 3 (high-level simplification) alongside BitFieldTransform.

use super::pass::{
    Pass, PassContext, PassIlExpr, PassIlExprs, PassIlOperand, PassInfo, PassResult,
};

// ============================================================================
// Helpers
// ============================================================================

/// Names that might represent the ARM64 carry flag (C bit of NZCV).
const CARRY_FLAG_NAMES: &[&str] = &["C", "CF", "nzcv.C", "NZCV.C", "carry", "CARRY"];

/// Extract an i64 constant from any operand type.
fn const_val(op: &PassIlOperand) -> Option<i64> {
    match op {
        PassIlOperand::Imm(v) => Some(*v),
        PassIlOperand::U64(v) => Some(*v as i64),
        _ => None,
    }
}

/// Check if an operand is a reference to the carry flag.
fn is_carry_flag(op: &PassIlOperand) -> bool {
    match op {
        PassIlOperand::Var(name) => {
            let upper = name.to_uppercase();
            CARRY_FLAG_NAMES.iter().any(|n| upper == n.to_uppercase())
        }
        _ => false,
    }
}

/// Deep-clone an operand.
fn clone_op(op: &PassIlOperand) -> PassIlOperand {
    match op {
        PassIlOperand::Expr(e) => PassIlOperand::Expr(e.clone()),
        PassIlOperand::Var(v) => PassIlOperand::Var(v.clone()),
        PassIlOperand::Imm(v) => PassIlOperand::Imm(*v),
        PassIlOperand::U64(v) => PassIlOperand::U64(*v),
        PassIlOperand::Str(s) => PassIlOperand::Str(s.clone()),
    }
}

/// Extract the destination variable name from a SetReg expression.
fn setreg_dest(expr: &PassIlExpr) -> Option<&str> {
    if expr.op == "LLIL_SetReg" {
        match expr.operands.first() {
            Some(PassIlOperand::Var(name)) => Some(name.as_str()),
            _ => None,
        }
    } else {
        None
    }
}

/// Extract the source sub-expression from a SetReg.
fn setreg_src(expr: &PassIlExpr) -> Option<&PassIlExpr> {
    if expr.op == "LLIL_SetReg" && expr.operands.len() >= 2 {
        match &expr.operands[1] {
            PassIlOperand::Expr(e) => Some(e),
            _ => None,
        }
    } else {
        None
    }
}

/// Check if a SetFlag defines a carry flag.
fn is_carry_setflag(expr: &PassIlExpr) -> bool {
    if expr.op == "LLIL_SetFlag" {
        if let Some(PassIlOperand::Var(name)) = expr.operands.first() {
            return CARRY_FLAG_NAMES
                .iter()
                .any(|n| name.to_uppercase() == n.to_uppercase());
        }
    }
    false
}

/// Check whether an expression tree contains a reference to the carry flag.
fn contains_carry_flag(expr: &PassIlExpr) -> bool {
    for op in &expr.operands {
        match op {
            PassIlOperand::Var(name) => {
                if CARRY_FLAG_NAMES
                    .iter()
                    .any(|n| name.to_uppercase() == n.to_uppercase())
                {
                    return true;
                }
            }
            PassIlOperand::Expr(child) if contains_carry_flag(child) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

// ============================================================================
// MultiPrecisionPass
// ============================================================================

#[derive(Debug)]
pub struct MultiPrecisionPass;

impl MultiPrecisionPass {
    // ------------------------------------------------------------------
    // SplitVarnode: 64-bit value -> two 32-bit halves
    // ------------------------------------------------------------------

    fn match_low32_extract(expr: &PassIlExpr) -> Option<(String, &'static str)> {
        if expr.op == "LLIL_And" && expr.operands.len() == 2 {
            for (var_idx, mask_idx) in [(0usize, 1usize), (1, 0)] {
                if let PassIlOperand::Var(src) = &expr.operands[var_idx] {
                    if let Some(mask) = const_val(&expr.operands[mask_idx]) {
                        if mask == 0xFFFFFFFFi64 || mask as u64 == 0xFFFFFFFFu64 {
                            return Some((src.clone(), "and_mask32"));
                        }
                    }
                }
            }
        }
        if expr.op == "LLIL_LowPart" && expr.operands.len() == 1 {
            if let PassIlOperand::Var(src) = &expr.operands[0] {
                if expr.size == 4 {
                    return Some((src.clone(), "lowpart4"));
                }
            }
        }
        None
    }

    fn match_high32_extract(expr: &PassIlExpr) -> Option<(String, &'static str)> {
        if expr.op == "LLIL_Lsr" && expr.operands.len() == 2 {
            if let PassIlOperand::Var(src) = &expr.operands[0] {
                if let Some(shift) = const_val(&expr.operands[1]) {
                    if shift == 32 {
                        return Some((src.clone(), "lsr32"));
                    }
                }
            }
        }
        None
    }

    fn scan_split_varnode(exprs: &mut Vec<PassIlExpr>) -> bool {
        let mut changed = false;
        let mut i = 0;
        while i + 1 < exprs.len() {
            if exprs[i].op != "LLIL_SetReg" || exprs[i + 1].op != "LLIL_SetReg" {
                i += 1;
                continue;
            }
            let lo_src = match setreg_src(&exprs[i]) {
                Some(s) => s,
                None => {
                    i += 1;
                    continue;
                }
            };
            let hi_src = match setreg_src(&exprs[i + 1]) {
                Some(s) => s,
                None => {
                    i += 1;
                    continue;
                }
            };
            let src_lo = match Self::match_low32_extract(lo_src) {
                Some((s, _)) => s,
                None => {
                    i += 1;
                    continue;
                }
            };
            let src_hi = match Self::match_high32_extract(hi_src) {
                Some((s, _)) => s,
                None => {
                    i += 1;
                    continue;
                }
            };
            if src_lo == src_hi {
                let lo_dest = setreg_dest(&exprs[i]).unwrap_or("?").to_string();
                let _hi_dest = setreg_dest(&exprs[i + 1]).unwrap_or("?").to_string();
                exprs[i]
                    .extra
                    .push(("mp_split".to_string(), format!("src={src_lo},role=lo")));
                exprs[i + 1].extra.push((
                    "mp_split".to_string(),
                    format!("src={src_lo},role=hi,lo={lo_dest}"),
                ));
                changed = true;
                i += 2;
            } else {
                i += 1;
            }
        }
        changed
    }

    // ------------------------------------------------------------------
    // AddForm: 128-bit addition through ADDS+ADC chain
    // ------------------------------------------------------------------

    fn scan_add_form(exprs: &mut Vec<PassIlExpr>) -> bool {
        let mut changed = false;
        let mut i = 0;

        while i < exprs.len() {
            if exprs[i].op != "LLIL_SetReg" {
                i += 1;
                continue;
            }
            let (a_lo, b_lo, _adds_pc) = match Self::match_adds_setreg(&exprs[i]) {
                Some(v) => v,
                None => {
                    i += 1;
                    continue;
                }
            };
            let lo_dest = setreg_dest(&exprs[i]).unwrap_or("").to_string();
            let adds_pc = exprs[i].pc;

            let mut found = false;
            let mut window_end = i + 1;
            let mut carry_seen = false;
            let mut flag_idx: Option<usize> = None;

            while window_end < exprs.len() && window_end - i <= 4 {
                let ec_op = exprs[window_end].op.clone();
                let ec_is_setreg = ec_op == "LLIL_SetReg";

                if is_carry_setflag(&exprs[window_end]) {
                    carry_seen = true;
                    flag_idx = Some(window_end);
                    window_end += 1;
                    continue;
                }

                if ec_is_setreg {
                    let ec_src = setreg_src(&exprs[window_end]);
                    let ec_pc = exprs[window_end].pc;

                    if let Some((a_hi, b_hi)) =
                        ec_src.and_then(|s| Self::match_adc_src(s, carry_seen))
                    {
                        let hi_dest = setreg_dest(&exprs[window_end]).unwrap_or("?").to_string();

                        let mp_add = PassIlExpr {
                            op: "LLIL_MpAdd".to_string(),
                            size: 16,
                            pc: adds_pc,
                            operands: vec![a_hi, a_lo, b_hi, b_lo],
                            extra: vec![
                                ("mp_op".to_string(), "add128".to_string()),
                                ("mp_lo_size".to_string(), "8".to_string()),
                                ("mp_hi_size".to_string(), "8".to_string()),
                            ],
                        };

                        Self::mark_consumed(&mut exprs[i]);
                        if let Some(fi) = flag_idx {
                            Self::mark_consumed(&mut exprs[fi]);
                        }
                        exprs[window_end] = PassIlExpr {
                            op: "LLIL_SetReg".to_string(),
                            size: 16,
                            pc: ec_pc,
                            operands: vec![
                                PassIlOperand::Var(format!("{hi_dest}:{lo_dest}")),
                                PassIlOperand::Expr(Box::new(mp_add)),
                            ],
                            extra: vec![("mp_fusion".to_string(), "add128".to_string())],
                        };
                        changed = true;
                        i = window_end + 1;
                        found = true;
                        break;
                    }
                    break;
                }

                window_end += 1;
            }

            if !found {
                i += 1;
            }
        }

        if changed {
            exprs.retain(|e| !e.extra.iter().any(|(k, v)| k == "mp_consumed" && v == "1"));
        }
        changed
    }

    /// Match a SetReg containing LLIL_Add (the adds instruction).
    fn match_adds_setreg(expr: &PassIlExpr) -> Option<(PassIlOperand, PassIlOperand, u64)> {
        let src = setreg_src(expr)?;
        if src.op != "LLIL_Add" || src.operands.len() != 2 {
            return None;
        }
        if contains_carry_flag(src) {
            return None;
        }
        let a_lo = clone_op(&src.operands[0]);
        let b_lo = clone_op(&src.operands[1]);
        Some((a_lo, b_lo, src.pc))
    }

    /// Match an ADC source: Add(Add(a_hi, b_hi), Var(C)) or variants.
    fn match_adc_src(
        expr: &PassIlExpr,
        carry_known: bool,
    ) -> Option<(PassIlOperand, PassIlOperand)> {
        if expr.op != "LLIL_Add" || expr.operands.len() != 2 {
            return None;
        }
        if !carry_known && !contains_carry_flag(expr) {
            return None;
        }

        // Case A: Add(Add(a_hi, b_hi), Var(C)) or Add(Var(C), Add(a_hi, b_hi))
        for (inner_idx, flag_idx) in [(0usize, 1usize), (1, 0)] {
            let inner = match &expr.operands[inner_idx] {
                PassIlOperand::Expr(e) => e,
                _ => continue,
            };
            let flag = &expr.operands[flag_idx];
            if inner.op == "LLIL_Add"
                && inner.operands.len() == 2
                && is_carry_flag(flag)
                && !contains_carry_flag(inner)
            {
                return Some((clone_op(&inner.operands[0]), clone_op(&inner.operands[1])));
            }
        }

        // Case B: Add(a_hi, Add(b_hi, Var(C)))
        for (outer_idx, inner_idx) in [(0usize, 1usize), (1, 0)] {
            let outer_simple = &expr.operands[outer_idx];
            let inner_expr = match &expr.operands[inner_idx] {
                PassIlOperand::Expr(e) => e,
                _ => continue,
            };
            if inner_expr.op == "LLIL_Add" && inner_expr.operands.len() == 2 {
                for (ii, fi) in [(0usize, 1usize), (1, 0)] {
                    if is_carry_flag(&inner_expr.operands[fi]) {
                        return Some((clone_op(outer_simple), clone_op(&inner_expr.operands[ii])));
                    }
                }
            }
        }

        None
    }

    // ------------------------------------------------------------------
    // SubForm: 128-bit subtraction through SUBS+SBC chain
    // ------------------------------------------------------------------

    fn scan_sub_form(exprs: &mut Vec<PassIlExpr>) -> bool {
        let mut changed = false;
        let mut i = 0;

        while i < exprs.len() {
            if exprs[i].op != "LLIL_SetReg" {
                i += 1;
                continue;
            }
            let (a_lo, b_lo, _subs_pc) = match Self::match_subs_setreg(&exprs[i]) {
                Some(v) => v,
                None => {
                    i += 1;
                    continue;
                }
            };
            let lo_dest = setreg_dest(&exprs[i]).unwrap_or("").to_string();
            let subs_pc = exprs[i].pc;

            let mut found = false;
            let mut window_end = i + 1;
            let mut carry_seen = false;
            let mut flag_idx: Option<usize> = None;

            while window_end < exprs.len() && window_end - i <= 4 {
                let ec_is_setreg = exprs[window_end].op == "LLIL_SetReg";

                if is_carry_setflag(&exprs[window_end]) {
                    carry_seen = true;
                    flag_idx = Some(window_end);
                    window_end += 1;
                    continue;
                }

                if ec_is_setreg {
                    let ec_src = setreg_src(&exprs[window_end]);
                    let ec_pc = exprs[window_end].pc;

                    if let Some((a_hi, b_hi)) =
                        ec_src.and_then(|s| Self::match_sbc_src(s, carry_seen))
                    {
                        let hi_dest = setreg_dest(&exprs[window_end]).unwrap_or("?").to_string();

                        let mp_sub = PassIlExpr {
                            op: "LLIL_MpSub".to_string(),
                            size: 16,
                            pc: subs_pc,
                            operands: vec![a_hi, a_lo, b_hi, b_lo],
                            extra: vec![
                                ("mp_op".to_string(), "sub128".to_string()),
                                ("mp_lo_size".to_string(), "8".to_string()),
                                ("mp_hi_size".to_string(), "8".to_string()),
                            ],
                        };

                        Self::mark_consumed(&mut exprs[i]);
                        if let Some(fi) = flag_idx {
                            Self::mark_consumed(&mut exprs[fi]);
                        }
                        exprs[window_end] = PassIlExpr {
                            op: "LLIL_SetReg".to_string(),
                            size: 16,
                            pc: ec_pc,
                            operands: vec![
                                PassIlOperand::Var(format!("{hi_dest}:{lo_dest}")),
                                PassIlOperand::Expr(Box::new(mp_sub)),
                            ],
                            extra: vec![("mp_fusion".to_string(), "sub128".to_string())],
                        };
                        changed = true;
                        i = window_end + 1;
                        found = true;
                        break;
                    }
                    break;
                }

                window_end += 1;
            }

            if !found {
                i += 1;
            }
        }

        if changed {
            exprs.retain(|e| !e.extra.iter().any(|(k, v)| k == "mp_consumed" && v == "1"));
        }
        changed
    }

    fn match_subs_setreg(expr: &PassIlExpr) -> Option<(PassIlOperand, PassIlOperand, u64)> {
        let src = setreg_src(expr)?;
        if src.op != "LLIL_Sub" || src.operands.len() != 2 {
            return None;
        }
        if contains_carry_flag(src) {
            return None;
        }
        let a_lo = clone_op(&src.operands[0]);
        let b_lo = clone_op(&src.operands[1]);
        Some((a_lo, b_lo, src.pc))
    }

    /// Match an SBC source: Sub(Sub(a_hi, b_hi), Var(C)) or variants.
    fn match_sbc_src(
        expr: &PassIlExpr,
        carry_known: bool,
    ) -> Option<(PassIlOperand, PassIlOperand)> {
        if !carry_known && !contains_carry_flag(expr) {
            return None;
        }

        if expr.op == "LLIL_Sub" && expr.operands.len() == 2 {
            // Case 1: Sub(Sub(a_hi, b_hi), Var(C)) — canonical SBC
            if let PassIlOperand::Expr(inner) = &expr.operands[0] {
                if inner.op == "LLIL_Sub"
                    && inner.operands.len() == 2
                    && is_carry_flag(&expr.operands[1])
                    && !contains_carry_flag(inner)
                {
                    return Some((clone_op(&inner.operands[0]), clone_op(&inner.operands[1])));
                }
            }

            // Case 2: Sub(Sub(a_hi, Var(C)), b_hi)
            if let PassIlOperand::Expr(inner) = &expr.operands[0] {
                if inner.op == "LLIL_Sub"
                    && inner.operands.len() == 2
                    && is_carry_flag(&inner.operands[1])
                {
                    return Some((clone_op(&inner.operands[0]), clone_op(&expr.operands[1])));
                }
            }

            // Case 3: Sub(a_hi, Add(b_hi, Var(C)))
            if let PassIlOperand::Expr(inner) = &expr.operands[1] {
                if inner.op == "LLIL_Add" && inner.operands.len() == 2 {
                    if is_carry_flag(&inner.operands[0]) {
                        return Some((clone_op(&expr.operands[0]), clone_op(&inner.operands[1])));
                    }
                    if is_carry_flag(&inner.operands[1]) {
                        return Some((clone_op(&expr.operands[0]), clone_op(&inner.operands[0])));
                    }
                }
            }
        }

        None
    }

    // ------------------------------------------------------------------
    // WidenMul: 32x32->64 multiply (UMULL/SMULL)
    // ------------------------------------------------------------------

    fn scan_widen_mul(exprs: &mut Vec<PassIlExpr>) -> bool {
        let mut changed = false;

        for expr in exprs.iter_mut() {
            if expr.op != "LLIL_SetReg" || expr.size != 8 {
                continue;
            }
            let src = match setreg_src(expr) {
                Some(s) => s,
                None => continue,
            };
            if src.op != "LLIL_Mul" || src.operands.len() != 2 {
                continue;
            }

            let a = &src.operands[0];
            let b = &src.operands[1];

            if let (PassIlOperand::Expr(zx_a), PassIlOperand::Expr(zx_b)) = (a, b) {
                let is_umull = zx_a.op == "LLIL_Zx" && zx_b.op == "LLIL_Zx";
                let is_smull = zx_a.op == "LLIL_Sx" && zx_b.op == "LLIL_Sx";

                if (is_umull || is_smull) && zx_a.size == 8 && zx_b.size == 8 {
                    let src_a = zx_a.operands.first();
                    let src_b = zx_b.operands.first();
                    if let (Some(PassIlOperand::Var(sa)), Some(PassIlOperand::Var(sb))) =
                        (src_a, src_b)
                    {
                        let mnem = if is_umull { "umull" } else { "smull" };
                        *expr = PassIlExpr {
                            op: "LLIL_SetReg".to_string(),
                            size: 8,
                            pc: expr.pc,
                            operands: vec![
                                expr.operands[0].clone(),
                                PassIlOperand::Expr(Box::new(PassIlExpr {
                                    op: "LLIL_MpMul".to_string(),
                                    size: 8,
                                    pc: src.pc,
                                    operands: vec![
                                        PassIlOperand::Var(sa.clone()),
                                        PassIlOperand::Var(sb.clone()),
                                    ],
                                    extra: vec![("mp_op".to_string(), mnem.to_string())],
                                })),
                            ],
                            extra: vec![],
                        };
                        changed = true;
                        break;
                    }
                }
            }
        }

        changed
    }

    // ------------------------------------------------------------------
    // CarryFlag annotation
    // ------------------------------------------------------------------

    fn annotate_carry_chains(exprs: &mut Vec<PassIlExpr>) -> bool {
        let mut changed = false;

        for i in 0..exprs.len() {
            if is_carry_setflag(&exprs[i])
                && !exprs[i].extra.iter().any(|(k, _)| k == "mp_carry_def")
            {
                exprs[i]
                    .extra
                    .push(("mp_carry_def".to_string(), "1".to_string()));
                changed = true;
            }
        }

        for i in 0..exprs.len() {
            if exprs[i].op == "LLIL_SetReg" {
                if let Some(src) = setreg_src(&exprs[i]) {
                    if contains_carry_flag(src)
                        && !exprs[i].extra.iter().any(|(k, _)| k == "mp_carry_use")
                    {
                        exprs[i]
                            .extra
                            .push(("mp_carry_use".to_string(), "1".to_string()));
                        changed = true;
                    }
                }
            }
        }

        changed
    }

    // ------------------------------------------------------------------
    // Entry point
    // ------------------------------------------------------------------

    fn run_all(exprs: &mut Vec<PassIlExpr>) -> bool {
        let mut changed = false;

        if Self::scan_split_varnode(exprs) {
            changed = true;
        }
        if Self::scan_add_form(exprs) {
            changed = true;
        }
        if Self::scan_sub_form(exprs) {
            changed = true;
        }
        if Self::scan_widen_mul(exprs) {
            changed = true;
        }
        if Self::annotate_carry_chains(exprs) {
            changed = true;
        }

        if changed {
            exprs.retain(|e| !e.extra.iter().any(|(k, v)| k == "mp_consumed" && v == "1"));
        }

        changed
    }

    fn mark_consumed(expr: &mut PassIlExpr) {
        if !expr
            .extra
            .iter()
            .any(|(k, v)| k == "mp_consumed" && v == "1")
        {
            expr.extra
                .push(("mp_consumed".to_string(), "1".to_string()));
        }
    }
}

// ============================================================================
// Pass trait implementation
// ============================================================================

impl Pass for MultiPrecisionPass {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "MultiPrecision",
            description: "Detect multi-precision arithmetic patterns (SplitVarnode, AddForm, SubForm, WidenMul) and merge into canonical expressions",
            phase: 3,
            requires: &[],
            invalidates: &["DeadCodeElim"],
            repeat_until_fixpoint: false,
        }
    }

    fn run(&self, _ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        if Self::run_all(&mut exprs.exprs) {
            PassResult::Changed
        } else {
            PassResult::Unchanged
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::pass::PassIlOperand;

    fn make_expr(op: &str, operands: Vec<PassIlOperand>) -> PassIlExpr {
        PassIlExpr {
            op: op.to_string(),
            size: 8,
            pc: 0x1000,
            operands,
            extra: vec![],
        }
    }

    fn make_setreg(dest: &str, src_expr: PassIlExpr) -> PassIlExpr {
        PassIlExpr {
            op: "LLIL_SetReg".to_string(),
            size: src_expr.size,
            pc: src_expr.pc,
            operands: vec![
                PassIlOperand::Var(dest.to_string()),
                PassIlOperand::Expr(Box::new(src_expr)),
            ],
            extra: vec![],
        }
    }

    fn make_setflag(flag: &str, src_expr: PassIlExpr) -> PassIlExpr {
        PassIlExpr {
            op: "LLIL_SetFlag".to_string(),
            size: 1,
            pc: src_expr.pc,
            operands: vec![
                PassIlOperand::Var(flag.to_string()),
                PassIlOperand::Expr(Box::new(src_expr)),
            ],
            extra: vec![],
        }
    }

    fn imm(v: i64) -> PassIlOperand {
        PassIlOperand::Imm(v)
    }

    fn reg(name: &str) -> PassIlOperand {
        PassIlOperand::Var(name.to_string())
    }

    fn expr(op: &str, operands: Vec<PassIlOperand>) -> PassIlOperand {
        PassIlOperand::Expr(Box::new(make_expr(op, operands)))
    }

    // =========================================================================
    // SplitVarnode tests
    // =========================================================================

    #[test]
    fn test_split_varnode_and_lsr() {
        let lo = make_setreg(
            "w0",
            make_expr("LLIL_And", vec![reg("x0"), imm(0xFFFFFFFF)]),
        );
        let hi = make_setreg("w1", make_expr("LLIL_Lsr", vec![reg("x0"), imm(32)]));
        let mut exprs = vec![lo, hi];

        assert!(MultiPrecisionPass::scan_split_varnode(&mut exprs));
        assert!(exprs[0]
            .extra
            .iter()
            .any(|(k, v)| k == "mp_split" && v.contains("role=lo")));
        assert!(exprs[1]
            .extra
            .iter()
            .any(|(k, v)| k == "mp_split" && v.contains("role=hi")));
    }

    #[test]
    fn test_split_varnode_swapped_order() {
        // hi first, then lo — caller is expected to emit in canonical order;
        // our scan only matches lo-then-hi. Verify no false match here.
        let hi = make_setreg("w1", make_expr("LLIL_Lsr", vec![reg("x0"), imm(32)]));
        let lo = make_setreg(
            "w0",
            make_expr("LLIL_And", vec![reg("x0"), imm(0xFFFFFFFF)]),
        );
        let mut exprs = vec![hi, lo];

        // Should NOT match: first expr is Lsr (hi), second is And (lo)
        let matched = MultiPrecisionPass::scan_split_varnode(&mut exprs);
        // Lsr doesn't match low32; And doesn't match high32 → no match
        assert!(!matched);
    }

    #[test]
    fn test_split_varnode_lowpart_lsr() {
        let lo_src = PassIlExpr {
            op: "LLIL_LowPart".to_string(),
            size: 4,
            pc: 0x1000,
            operands: vec![reg("x0")],
            extra: vec![],
        };
        let lo = PassIlExpr {
            op: "LLIL_SetReg".to_string(),
            size: 4,
            pc: 0x1000,
            operands: vec![
                PassIlOperand::Var("w0".to_string()),
                PassIlOperand::Expr(Box::new(lo_src)),
            ],
            extra: vec![],
        };
        let hi = make_setreg("w1", make_expr("LLIL_Lsr", vec![reg("x0"), imm(32)]));
        let mut exprs = vec![lo, hi];

        assert!(MultiPrecisionPass::scan_split_varnode(&mut exprs));
        assert!(exprs[0].extra.iter().any(|(k, _)| k == "mp_split"));
    }

    #[test]
    fn test_split_varnode_different_sources_no_match() {
        let lo = make_setreg(
            "w0",
            make_expr("LLIL_And", vec![reg("x0"), imm(0xFFFFFFFF)]),
        );
        let hi = make_setreg("w1", make_expr("LLIL_Lsr", vec![reg("x1"), imm(32)]));
        let mut exprs = vec![lo, hi];
        assert!(!MultiPrecisionPass::scan_split_varnode(&mut exprs));
    }

    #[test]
    fn test_split_varnode_wrong_shift_no_match() {
        let lo = make_setreg(
            "w0",
            make_expr("LLIL_And", vec![reg("x0"), imm(0xFFFFFFFF)]),
        );
        let hi = make_setreg("w1", make_expr("LLIL_Lsr", vec![reg("x0"), imm(16)]));
        let mut exprs = vec![lo, hi];
        assert!(!MultiPrecisionPass::scan_split_varnode(&mut exprs));
    }

    // =========================================================================
    // AddForm tests (128-bit add)
    // =========================================================================

    #[test]
    fn test_add_form_basic() {
        let adds_expr = make_setreg("x0#1", make_expr("LLIL_Add", vec![reg("x2"), reg("x4")]));
        let adc_src = make_expr(
            "LLIL_Add",
            vec![expr("LLIL_Add", vec![reg("x3"), reg("x5")]), reg("C")],
        );
        let adc_expr = make_setreg("x1#1", adc_src);
        let mut exprs = vec![adds_expr, adc_expr];

        let changed = MultiPrecisionPass::scan_add_form(&mut exprs);
        assert!(changed, "Should match 128-bit add");
        assert_eq!(
            exprs.len(),
            1,
            "Expected 1 expr after fusion, got {}",
            exprs.len()
        );
        assert_eq!(exprs[0].op, "LLIL_SetReg");
        assert!(exprs[0]
            .extra
            .iter()
            .any(|(k, v)| k == "mp_fusion" && v == "add128"));
    }

    #[test]
    fn test_add_form_with_setflag() {
        let adds_expr = make_setreg("x0#1", make_expr("LLIL_Add", vec![reg("x2"), reg("x4")]));
        let flag_src = make_expr("LLIL_Add", vec![reg("x2"), reg("x4")]);
        let setflag = make_setflag("C", flag_src);
        let adc_src = make_expr(
            "LLIL_Add",
            vec![expr("LLIL_Add", vec![reg("x3"), reg("x5")]), reg("C")],
        );
        let adc_expr = make_setreg("x1#1", adc_src);
        let mut exprs = vec![adds_expr, setflag, adc_expr];

        let changed = MultiPrecisionPass::scan_add_form(&mut exprs);
        assert!(changed, "Should match add with explicit SetFlag(C)");
        assert_eq!(exprs.len(), 1, "Expected 1 expr after fusion");
    }

    #[test]
    fn test_add_form_carry_on_left() {
        let adds_expr = make_setreg("x0#1", make_expr("LLIL_Add", vec![reg("x2"), reg("x4")]));
        let adc_src = make_expr(
            "LLIL_Add",
            vec![reg("C"), expr("LLIL_Add", vec![reg("x3"), reg("x5")])],
        );
        let adc_expr = make_setreg("x1#1", adc_src);
        let mut exprs = vec![adds_expr, adc_expr];

        let changed = MultiPrecisionPass::scan_add_form(&mut exprs);
        assert!(changed);
        assert_eq!(exprs.len(), 1);
    }

    #[test]
    fn test_add_form_nested_carry() {
        let adds_expr = make_setreg("x0#1", make_expr("LLIL_Add", vec![reg("x2"), reg("x4")]));
        let adc_src = make_expr(
            "LLIL_Add",
            vec![reg("x3"), expr("LLIL_Add", vec![reg("x5"), reg("C")])],
        );
        let adc_expr = make_setreg("x1#1", adc_src);
        let mut exprs = vec![adds_expr, adc_expr];

        let changed = MultiPrecisionPass::scan_add_form(&mut exprs);
        assert!(changed);
        assert_eq!(exprs.len(), 1);
    }

    #[test]
    fn test_add_form_no_carry_no_match() {
        let add1 = make_setreg("x0#1", make_expr("LLIL_Add", vec![reg("x2"), reg("x4")]));
        let add2 = make_setreg("x1#1", make_expr("LLIL_Add", vec![reg("x3"), reg("x5")]));
        let mut exprs = vec![add1, add2];

        let changed = MultiPrecisionPass::scan_add_form(&mut exprs);
        assert!(!changed);
        assert_eq!(exprs.len(), 2);
    }

    // =========================================================================
    // SubForm tests (128-bit sub)
    // =========================================================================

    #[test]
    fn test_sub_form_basic() {
        let subs_expr = make_setreg("x0#1", make_expr("LLIL_Sub", vec![reg("x2"), reg("x4")]));
        let sbc_src = make_expr(
            "LLIL_Sub",
            vec![expr("LLIL_Sub", vec![reg("x3"), reg("x5")]), reg("C")],
        );
        let sbc_expr = make_setreg("x1#1", sbc_src);
        let mut exprs = vec![subs_expr, sbc_expr];

        let changed = MultiPrecisionPass::scan_sub_form(&mut exprs);
        assert!(changed, "Should match 128-bit sub");
        assert_eq!(exprs.len(), 1, "Expected 1 expr after fusion");
        assert!(exprs[0]
            .extra
            .iter()
            .any(|(k, v)| k == "mp_fusion" && v == "sub128"));
    }

    #[test]
    fn test_sub_form_sbc_alt() {
        let subs_expr = make_setreg("x0#1", make_expr("LLIL_Sub", vec![reg("x2"), reg("x4")]));
        let sbc_src = make_expr(
            "LLIL_Sub",
            vec![expr("LLIL_Sub", vec![reg("x3"), reg("C")]), reg("x5")],
        );
        let sbc_expr = make_setreg("x1#1", sbc_src);
        let mut exprs = vec![subs_expr, sbc_expr];

        let changed = MultiPrecisionPass::scan_sub_form(&mut exprs);
        assert!(changed);
        assert_eq!(exprs.len(), 1);
    }

    #[test]
    fn test_sub_form_sub_add_carry() {
        let subs_expr = make_setreg("x0#1", make_expr("LLIL_Sub", vec![reg("x2"), reg("x4")]));
        let sbc_src = make_expr(
            "LLIL_Sub",
            vec![reg("x3"), expr("LLIL_Add", vec![reg("x5"), reg("C")])],
        );
        let sbc_expr = make_setreg("x1#1", sbc_src);
        let mut exprs = vec![subs_expr, sbc_expr];

        let changed = MultiPrecisionPass::scan_sub_form(&mut exprs);
        assert!(changed);
        assert_eq!(exprs.len(), 1);
    }

    #[test]
    fn test_sub_form_no_carry_no_match() {
        let sub1 = make_setreg("x0#1", make_expr("LLIL_Sub", vec![reg("x2"), reg("x4")]));
        let sub2 = make_setreg("x1#1", make_expr("LLIL_Sub", vec![reg("x3"), reg("x5")]));
        let mut exprs = vec![sub1, sub2];

        let changed = MultiPrecisionPass::scan_sub_form(&mut exprs);
        assert!(!changed);
        assert_eq!(exprs.len(), 2);
    }

    // =========================================================================
    // WidenMul tests (UMULL/SMULL)
    // =========================================================================

    /// Helper: build a 32->64 widened multiply SetReg with given extend op.
    fn make_widen_mul_setreg(dest: &str, ext_op: &str, src1: &str, src2: &str) -> PassIlExpr {
        let mul = PassIlExpr {
            op: "LLIL_Mul".to_string(),
            size: 8,
            pc: 0x1000,
            operands: vec![
                PassIlOperand::Expr(Box::new(PassIlExpr {
                    op: ext_op.to_string(),
                    size: 8,
                    pc: 0x1000,
                    operands: vec![reg(src1)],
                    extra: vec![],
                })),
                PassIlOperand::Expr(Box::new(PassIlExpr {
                    op: ext_op.to_string(),
                    size: 8,
                    pc: 0x1000,
                    operands: vec![reg(src2)],
                    extra: vec![],
                })),
            ],
            extra: vec![],
        };
        make_setreg(dest, mul)
    }

    #[test]
    fn test_widen_mul_umull() {
        let setreg = make_widen_mul_setreg("x0#1", "LLIL_Zx", "w1", "w2");
        let mut exprs = vec![setreg];

        let changed = MultiPrecisionPass::scan_widen_mul(&mut exprs);
        assert!(changed, "Should match UMULL pattern");

        match &exprs[0].operands[1] {
            PassIlOperand::Expr(mp_mul) => {
                assert_eq!(mp_mul.op, "LLIL_MpMul");
                assert!(mp_mul
                    .extra
                    .iter()
                    .any(|(k, v)| k == "mp_op" && v == "umull"));
            }
            _ => panic!("Expected MpMul expression"),
        }
    }

    #[test]
    fn test_widen_mul_smull() {
        let setreg = make_widen_mul_setreg("x0#1", "LLIL_Sx", "w1", "w2");
        let mut exprs = vec![setreg];

        let changed = MultiPrecisionPass::scan_widen_mul(&mut exprs);
        assert!(changed, "Should match SMULL pattern");

        match &exprs[0].operands[1] {
            PassIlOperand::Expr(mp_mul) => {
                assert_eq!(mp_mul.op, "LLIL_MpMul");
                assert!(mp_mul
                    .extra
                    .iter()
                    .any(|(k, v)| k == "mp_op" && v == "smull"));
            }
            _ => panic!("Expected MpMul expression"),
        }
    }

    #[test]
    fn test_widen_mul_not_wide_no_match() {
        let mul = make_expr("LLIL_Mul", vec![reg("x1"), reg("x2")]);
        let setreg = make_setreg("x0#1", mul);
        let mut exprs = vec![setreg];

        assert!(!MultiPrecisionPass::scan_widen_mul(&mut exprs));
    }

    #[test]
    fn test_widen_mul_wrong_size_no_match() {
        let mul = PassIlExpr {
            op: "LLIL_Mul".to_string(),
            size: 4,
            pc: 0x1000,
            operands: vec![
                expr("LLIL_Zx", vec![reg("w1")]),
                expr("LLIL_Zx", vec![reg("w2")]),
            ],
            extra: vec![],
        };
        let setreg = PassIlExpr {
            op: "LLIL_SetReg".to_string(),
            size: 4,
            pc: 0x1000,
            operands: vec![
                PassIlOperand::Var("w0#1".to_string()),
                PassIlOperand::Expr(Box::new(mul)),
            ],
            extra: vec![],
        };
        let mut exprs = vec![setreg];

        assert!(!MultiPrecisionPass::scan_widen_mul(&mut exprs));
    }

    // =========================================================================
    // CarryFlag annotation tests
    // =========================================================================

    #[test]
    fn test_carry_flag_annotation() {
        let flag_src = make_expr("LLIL_Add", vec![reg("x0"), reg("x1")]);
        let setflag = make_setflag("C", flag_src);
        let adc_src = make_expr(
            "LLIL_Add",
            vec![expr("LLIL_Add", vec![reg("x2"), reg("x3")]), reg("C")],
        );
        let adc = make_setreg("x4#1", adc_src);
        let ret = make_expr("LLIL_Ret", vec![reg("x4#1")]);
        let mut exprs = vec![setflag, adc, ret];

        let changed = MultiPrecisionPass::annotate_carry_chains(&mut exprs);
        assert!(changed);
        assert!(exprs[0].extra.iter().any(|(k, _)| k == "mp_carry_def"));
        assert!(exprs[1].extra.iter().any(|(k, _)| k == "mp_carry_use"));
    }

    #[test]
    fn test_is_carry_flag_variants() {
        assert!(is_carry_flag(&PassIlOperand::Var("C".to_string())));
        assert!(is_carry_flag(&PassIlOperand::Var("CF".to_string())));
        assert!(is_carry_flag(&PassIlOperand::Var("carry".to_string())));
        assert!(!is_carry_flag(&PassIlOperand::Var("N".to_string())));
        assert!(!is_carry_flag(&PassIlOperand::Var("Z".to_string())));
    }

    // =========================================================================
    // Full pass integration tests
    // =========================================================================

    #[test]
    fn test_pass_full_128bit_add() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_setreg("x0#1", make_expr("LLIL_Add", vec![reg("x2"), reg("x4")])),
            make_setreg(
                "x1#1",
                make_expr(
                    "LLIL_Add",
                    vec![expr("LLIL_Add", vec![reg("x3"), reg("x5")]), reg("C")],
                ),
            ),
            make_expr("LLIL_Ret", vec![reg("x1#1")]),
        ];

        let pass = MultiPrecisionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 3,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed(), "Pass should detect 128-bit add");
        assert_eq!(exprs.exprs.len(), 2);
        assert!(exprs.exprs[0]
            .extra
            .iter()
            .any(|(k, v)| k == "mp_fusion" && v == "add128"));
    }

    #[test]
    fn test_pass_full_128bit_sub() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_setreg("x0#1", make_expr("LLIL_Sub", vec![reg("x2"), reg("x4")])),
            make_setreg(
                "x1#1",
                make_expr(
                    "LLIL_Sub",
                    vec![expr("LLIL_Sub", vec![reg("x3"), reg("x5")]), reg("C")],
                ),
            ),
            make_expr("LLIL_Ret", vec![reg("x1#1")]),
        ];

        let pass = MultiPrecisionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 3,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed(), "Pass should detect 128-bit sub");
        assert_eq!(exprs.exprs.len(), 2);
        assert!(exprs.exprs[0]
            .extra
            .iter()
            .any(|(k, v)| k == "mp_fusion" && v == "sub128"));
    }

    #[test]
    fn test_pass_all_patterns() {
        let mut exprs = PassIlExprs::new("test", "llil");

        let lo = make_setreg(
            "w0#1",
            make_expr("LLIL_And", vec![reg("x10"), imm(0xFFFFFFFF)]),
        );
        let hi = make_setreg("w1#1", make_expr("LLIL_Lsr", vec![reg("x10"), imm(32)]));
        let adds_expr = make_setreg("x0#1", make_expr("LLIL_Add", vec![reg("x2"), reg("x4")]));
        let adc_expr = make_setreg(
            "x1#1",
            make_expr(
                "LLIL_Add",
                vec![expr("LLIL_Add", vec![reg("x3"), reg("x5")]), reg("C")],
            ),
        );
        let umull = make_widen_mul_setreg("x5#1", "LLIL_Zx", "w20", "w21");

        exprs.exprs = vec![
            lo,
            hi,
            adds_expr,
            adc_expr,
            umull,
            make_expr("LLIL_Ret", vec![reg("x1#1")]),
        ];

        let pass = MultiPrecisionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 3,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());

        // split_varnode annotations (2), mp_add (1), mp_mul (1), ret (1) = 5
        assert_eq!(
            exprs.exprs.len(),
            5,
            "Expected 5 exprs, got {}",
            exprs.exprs.len()
        );
    }

    #[test]
    fn test_pass_no_patterns_no_change() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_setreg("x0#1", make_expr("LLIL_Add", vec![reg("x1"), imm(42)])),
            make_setreg("x2#1", make_expr("LLIL_Mul", vec![reg("x3"), reg("x4")])),
            make_expr("LLIL_Ret", vec![reg("x2#1")]),
        ];

        let pass = MultiPrecisionPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 3,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(!result.is_changed());
        assert_eq!(exprs.exprs.len(), 3);
    }

    // =========================================================================
    // Helper function tests
    // =========================================================================

    #[test]
    fn test_contains_carry_flag() {
        let with_carry = make_expr(
            "LLIL_Add",
            vec![expr("LLIL_Add", vec![reg("x3"), reg("x5")]), reg("C")],
        );
        assert!(contains_carry_flag(&with_carry));

        let without_carry = make_expr("LLIL_Add", vec![reg("x0"), reg("x1")]);
        assert!(!contains_carry_flag(&without_carry));

        let deep = make_expr(
            "LLIL_Sub",
            vec![reg("x0"), expr("LLIL_Add", vec![reg("x1"), reg("C")])],
        );
        assert!(contains_carry_flag(&deep));
    }

    #[test]
    fn test_match_adds_setreg() {
        let adds = make_setreg("x0#1", make_expr("LLIL_Add", vec![reg("x2"), reg("x4")]));
        let result = MultiPrecisionPass::match_adds_setreg(&adds);
        assert!(result.is_some());
        let (a, b, _) = result.unwrap();
        match (&a, &b) {
            (PassIlOperand::Var(va), PassIlOperand::Var(vb)) => {
                assert_eq!(va, "x2");
                assert_eq!(vb, "x4");
            }
            _ => panic!("Expected Var operands"),
        }
    }

    #[test]
    fn test_match_adds_setreg_with_carry_rejected() {
        let adc_like = make_expr(
            "LLIL_Add",
            vec![expr("LLIL_Add", vec![reg("x3"), reg("x5")]), reg("C")],
        );
        let setreg = make_setreg("x1#1", adc_like);
        let result = MultiPrecisionPass::match_adds_setreg(&setreg);
        assert!(
            result.is_none(),
            "Expression with carry should not match as adds"
        );
    }

    #[test]
    fn test_match_adc_src_canonical() {
        let adc = make_expr(
            "LLIL_Add",
            vec![expr("LLIL_Add", vec![reg("x3"), reg("x5")]), reg("C")],
        );
        let result = MultiPrecisionPass::match_adc_src(&adc, true);
        assert!(result.is_some());
        let (a, b) = result.unwrap();
        match (&a, &b) {
            (PassIlOperand::Var(va), PassIlOperand::Var(vb)) => {
                assert_eq!(va, "x3");
                assert_eq!(vb, "x5");
            }
            _ => panic!("Expected Var operands"),
        }
    }

    #[test]
    fn test_match_adc_src_carry_on_left() {
        let adc = make_expr(
            "LLIL_Add",
            vec![reg("C"), expr("LLIL_Add", vec![reg("x3"), reg("x5")])],
        );
        let result = MultiPrecisionPass::match_adc_src(&adc, true);
        assert!(result.is_some());
    }

    #[test]
    fn test_match_sbc_src_canonical() {
        let sbc = make_expr(
            "LLIL_Sub",
            vec![expr("LLIL_Sub", vec![reg("x3"), reg("x5")]), reg("C")],
        );
        let result = MultiPrecisionPass::match_sbc_src(&sbc, true);
        assert!(result.is_some());
        let (a, b) = result.unwrap();
        match (&a, &b) {
            (PassIlOperand::Var(va), PassIlOperand::Var(vb)) => {
                assert_eq!(va, "x3");
                assert_eq!(vb, "x5");
            }
            _ => panic!("Expected Var operands"),
        }
    }

    #[test]
    fn test_match_sbc_src_sub_add_carry() {
        let sbc = make_expr(
            "LLIL_Sub",
            vec![reg("x3"), expr("LLIL_Add", vec![reg("x5"), reg("C")])],
        );
        let result = MultiPrecisionPass::match_sbc_src(&sbc, true);
        assert!(result.is_some());
    }
}
