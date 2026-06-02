//! Bitfield extraction/insertion pass (ARM64 UBFX/SBFX/BFI pattern detection).
//!
//! Detects common ARM64 bitfield instruction patterns in LLIL and replaces
//! them with canonical bf_extract/bf_insert expressions.
//!
//! Patterns detected (matching the lifter output in llil/lift.rs):
//!
//!   UBFX (unsigned field extract):
//!     And(Lsr(src, #lsb), #mask)   where mask = (1<<width)-1
//!     → bf_extract(src, lsb, width, unsigned)
//!
//!   SBFX (signed field extract):
//!     Asr(Lsl(And(Lsr(src, #lsb), #mask), #sh), #sh)
//!     where mask = (1<<width)-1, sh = 64-width
//!     → bf_extract(src, lsb, width, signed)
//!
//!   BFI (bitfield insert):
//!     Or(And(dst, #mask_clear), And(Lsl(src, #lsb), #mask_insert))
//!     where mask_insert = ((1<<width)-1) << lsb, mask_clear = ~mask_insert
//!     → bf_insert(dst, src, lsb, width)
//!
//! This pass runs in Phase 3 (high-level simplification) after main loop
//! fixpoint has already simplified basic arithmetic.

use super::pass::{
    Pass, PassContext, PassIlExpr, PassIlExprs, PassIlOperand, PassInfo, PassResult,
};

// ============================================================================
// Helpers
// ============================================================================

/// Extract an i64 constant from any operand type.
fn const_val(op: &PassIlOperand) -> Option<i64> {
    match op {
        PassIlOperand::Imm(v) => Some(*v),
        PassIlOperand::U64(v) => Some(*v as i64),
        _ => None,
    }
}

/// Check whether a mask has the form `(1 << width) - 1` (contiguous 1 bits
/// starting from bit 0). Returns the width (number of 1 bits), or None.
///
/// Example: 0b1111 → Some(4), 0x3FF → Some(10), 0x7 → Some(3)
///           0b1010 → None (non-contiguous), 0 → None (empty)
fn mask_width_low(mask: i64, size: u8) -> Option<i64> {
    if mask <= 0 {
        // mask=0 means zero width, not meaningful
        return None;
    }
    // mask is non-negative, so high bits are zero in signed repr
    let m = mask as u64;
    let w = m + 1;
    if w.is_power_of_two() {
        let width = w.trailing_zeros() as i64;
        let size_bits = (size as i64) * 8;
        if width > 0 && width < size_bits {
            return Some(width);
        }
    }
    None
}

/// Check whether a mask has the form `((1 << width) - 1) << lsb` (contiguous
/// 1 bits starting at position `lsb`). Returns Some((lsb, width)) or None.
///
/// Example: 0x70 (0b...0111_0000) → Some((4, 3))
///           0x1F00 → Some((8, 5))
fn mask_width_at_pos(mask: i64, size: u8) -> Option<(i64, i64)> {
    if mask <= 0 {
        return None;
    }
    let m = mask as u64;
    let lsb = m.trailing_zeros() as i64;
    // Shift right by lsb to get low mask
    let shifted = m >> lsb;
    let sw = shifted + 1;
    if sw.is_power_of_two() {
        let width = sw.trailing_zeros() as i64;
        let size_bits = (size as i64) * 8;
        if width > 0 && lsb + width <= size_bits {
            // Verify the shifted value is exactly (1<<width)-1 (all 1s, no gaps)
            let expected = (1u64 << width) - 1;
            if shifted == expected {
                return Some((lsb, width));
            }
        }
    }
    None
}

/// Test whether an operand is a constant zero.
fn is_zero(op: &PassIlOperand) -> bool {
    matches!(op, PassIlOperand::Imm(0) | PassIlOperand::U64(0))
}

/// Test whether an operand is a constant -1 (all-ones for the size).
fn is_neg_one(op: &PassIlOperand) -> bool {
    matches!(op, PassIlOperand::Imm(-1))
}

/// Clone an operand.
fn clone_op(op: &PassIlOperand) -> PassIlOperand {
    match op {
        PassIlOperand::Expr(e) => PassIlOperand::Expr(e.clone()),
        PassIlOperand::Var(v) => PassIlOperand::Var(v.clone()),
        PassIlOperand::Imm(v) => PassIlOperand::Imm(*v),
        PassIlOperand::U64(v) => PassIlOperand::U64(*v),
        PassIlOperand::Str(s) => PassIlOperand::Str(s.clone()),
    }
}

// ============================================================================
// BitFieldTransformPass
// ============================================================================

#[derive(Debug)]
pub struct BitFieldTransformPass;

impl BitFieldTransformPass {
    // ------------------------------------------------------------------
    // UBFX: And(Lsr(src, #lsb), #mask)  mask = (1<<width)-1
    // → bf_extract(src, lsb, width, unsigned)
    // ------------------------------------------------------------------

    /// Try to match UBFX at the given expression.
    fn try_ubfx(expr: &PassIlExpr) -> Option<PassIlExpr> {
        if expr.op != "LLIL_And" || expr.operands.len() != 2 {
            return None;
        }
        // Try both operand orders: (Lsr, mask) and (mask, Lsr)
        for (shift_idx, mask_idx) in [(0usize, 1usize), (1, 0)] {
            let shift_op = &expr.operands[shift_idx];
            let mask_op = &expr.operands[mask_idx];
            if let PassIlOperand::Expr(shift) = shift_op {
                if shift.op == "LLIL_Lsr" && shift.operands.len() == 2 {
                    let lsb = const_val(&shift.operands[1])?;
                    if lsb < 0 {
                        continue;
                    }
                    let mask_val = const_val(mask_op)?;
                    let width = mask_width_low(mask_val, expr.size)?;
                    let size_bits = (expr.size as i64) * 8;
                    if lsb + width > size_bits {
                        continue;
                    }
                    return Some(Self::make_bf_extract(
                        clone_op(&shift.operands[0]),
                        lsb,
                        width,
                        false,
                        expr.size,
                        expr.pc,
                    ));
                }
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // SBFX: Asr(Lsl(And(Lsr(src, #lsb), #mask), #sh), #sh)
    //        mask = (1<<width)-1, sh = 64-width
    // → bf_extract(src, lsb, width, signed)
    //
    // Also handles the lsb==0 case:
    //   Asr(Lsl(And(src, #mask), #sh), #sh)
    //   mask = (1<<width)-1, sh = 64-width
    // ------------------------------------------------------------------

    fn try_sbfx(expr: &PassIlExpr) -> Option<PassIlExpr> {
        // Detect the sign-extension envelope: Asr(Lsl(x, #sh), #sh)
        if expr.op != "LLIL_Asr" || expr.operands.len() != 2 {
            return None;
        }
        let sh_outer = const_val(&expr.operands[1])?;
        let lsl_inner = match &expr.operands[0] {
            PassIlOperand::Expr(e) => e,
            _ => return None,
        };
        if lsl_inner.op != "LLIL_Lsl" || lsl_inner.operands.len() != 2 {
            return None;
        }
        let sh_inner = const_val(&lsl_inner.operands[1])?;
        if sh_outer != sh_inner || sh_outer <= 0 {
            return None;
        }
        let sh = sh_outer;
        let size_bits = (expr.size as i64) * 8;
        if sh >= size_bits {
            return None;
        }
        let width = size_bits - sh;
        // The inner expression should be: And(Lsr(src, #lsb), #mask) or And(src, #mask)
        let inner = &lsl_inner.operands[0];
        let (_and_expr, src, lsb) = match inner {
            PassIlOperand::Expr(e) if e.op == "LLIL_And" && e.operands.len() == 2 => {
                // Look for Lsr(src, #lsb) in either operand of the And
                let (a, b) = (&e.operands[0], &e.operands[1]);
                let mask_val_left = const_val(a);
                let mask_val_right = const_val(b);
                let expected_mask = (1u64 << width) - 1;
                if mask_val_left == Some(expected_mask as i64) {
                    // b is the shift-related operand
                    match b {
                        PassIlOperand::Expr(shift)
                            if shift.op == "LLIL_Lsr" && shift.operands.len() == 2 =>
                        {
                            let lsb_val = const_val(&shift.operands[1])?;
                            if lsb_val < 0 {
                                return None;
                            }
                            (e, clone_op(&shift.operands[0]), lsb_val)
                        }
                        PassIlOperand::Var(_) | PassIlOperand::Expr(_) => {
                            // src without shift (lsb=0)
                            (e, clone_op(b), 0)
                        }
                        _ => return None,
                    }
                } else if mask_val_right == Some(expected_mask as i64) {
                    // a is the shift-related operand
                    match a {
                        PassIlOperand::Expr(shift)
                            if shift.op == "LLIL_Lsr" && shift.operands.len() == 2 =>
                        {
                            let lsb_val = const_val(&shift.operands[1])?;
                            if lsb_val < 0 {
                                return None;
                            }
                            (e, clone_op(&shift.operands[0]), lsb_val)
                        }
                        PassIlOperand::Var(_) | PassIlOperand::Expr(_) => {
                            // src without shift (lsb=0)
                            (e, clone_op(a), 0)
                        }
                        _ => return None,
                    }
                } else {
                    // Neither operand is the expected mask — check if either mask
                    // has the expected width
                    let width_from_left = mask_val_left.and_then(|v| mask_width_low(v, expr.size));
                    let width_from_right =
                        mask_val_right.and_then(|v| mask_width_low(v, expr.size));
                    if let Some(w) = width_from_left {
                        if w == width {
                            match b {
                                PassIlOperand::Expr(shift)
                                    if shift.op == "LLIL_Lsr" && shift.operands.len() == 2 =>
                                {
                                    let lsb_val = const_val(&shift.operands[1])?;
                                    if lsb_val < 0 {
                                        return None;
                                    }
                                    (e, clone_op(&shift.operands[0]), lsb_val)
                                }
                                _ => (e, clone_op(b), 0),
                            }
                        } else {
                            return None;
                        }
                    } else if let Some(w) = width_from_right {
                        if w == width {
                            match a {
                                PassIlOperand::Expr(shift)
                                    if shift.op == "LLIL_Lsr" && shift.operands.len() == 2 =>
                                {
                                    let lsb_val = const_val(&shift.operands[1])?;
                                    if lsb_val < 0 {
                                        return None;
                                    }
                                    (e, clone_op(&shift.operands[0]), lsb_val)
                                }
                                _ => (e, clone_op(a), 0),
                            }
                        } else {
                            return None;
                        }
                    } else {
                        return None;
                    }
                }
            }
            _ => return None,
        };

        if lsb + width > size_bits {
            return None;
        }

        Some(Self::make_bf_extract(
            src, lsb, width, true, expr.size, expr.pc,
        ))
    }

    // ------------------------------------------------------------------
    // BFI: Or(And(dst, #mask_clear), And(Lsl(src, #lsb), #mask_insert))
    //      mask_insert = ((1<<width)-1) << lsb, mask_clear = ~mask_insert
    // → bf_insert(dst, src, lsb, width)
    // ------------------------------------------------------------------

    fn try_bfi(expr: &PassIlExpr) -> Option<PassIlExpr> {
        if expr.op != "LLIL_Or" || expr.operands.len() != 2 {
            return None;
        }
        let (_a, _b) = (&expr.operands[0], &expr.operands[1]);

        // Try: Or(And(dst, mask_clear), And(Lsl(src, lsb), mask_insert))
        for (and_clear_idx, and_insert_idx) in [(0usize, 1usize), (1, 0)] {
            let and_clear = match &expr.operands[and_clear_idx] {
                PassIlOperand::Expr(e) if e.op == "LLIL_And" && e.operands.len() == 2 => e,
                _ => continue,
            };
            let and_insert = match &expr.operands[and_insert_idx] {
                PassIlOperand::Expr(e) if e.op == "LLIL_And" && e.operands.len() == 2 => e,
                _ => continue,
            };

            // Extract mask_clear and identify dst operand
            let (dst, mask_clear_val) = {
                let (l, r) = (&and_clear.operands[0], &and_clear.operands[1]);
                if let Some(v) = const_val(l) {
                    if is_neg_one(l) {
                        // ~0 & dst → just check if v is a negated mask
                        (clone_op(r), v)
                    } else {
                        (clone_op(r), v)
                    }
                } else if let Some(v) = const_val(r) {
                    (clone_op(l), v)
                } else {
                    continue;
                }
            };

            // Extract mask_insert, lsb, and src
            let (src, lsl_lsb, mask_insert_val) = {
                let (l, r) = (&and_insert.operands[0], &and_insert.operands[1]);
                // One operand is Lsl(src, #lsb), the other is mask_insert
                if let PassIlOperand::Expr(lsl) = l {
                    if lsl.op == "LLIL_Lsl" && lsl.operands.len() == 2 {
                        let lsb_val = match const_val(&lsl.operands[1]) {
                            Some(v) => v,
                            None => continue,
                        };
                        let mask_val = match const_val(r) {
                            Some(v) => v,
                            None => continue,
                        };
                        (clone_op(&lsl.operands[0]), lsb_val, mask_val)
                    } else if let Some(_mask_val) = const_val(r) {
                        // r is mask, l is something else — check if l is Lsl
                        continue; // l must be the Lsl
                    } else {
                        continue;
                    }
                } else if let PassIlOperand::Expr(lsl_inner) = r {
                    if lsl_inner.op == "LLIL_Lsl" && lsl_inner.operands.len() == 2 {
                        let lsb_val = match const_val(&lsl_inner.operands[1]) {
                            Some(v) => v,
                            None => continue,
                        };
                        let mask_val = match const_val(l) {
                            Some(v) => v,
                            None => continue,
                        };
                        (clone_op(&lsl_inner.operands[0]), lsb_val, mask_val)
                    } else {
                        continue;
                    }
                } else {
                    // No Lsl in either operand — check if src is shifted zero
                    // i.e., Lsl is implicit when lsb=0
                    // But we need at least a mask on one side
                    if let Some(mask_val) = const_val(l) {
                        if let Some(_lsb_val) = const_val(r) {
                            // This could be non-standard, skip
                            continue;
                        }
                        // r is the src without Lsl (lsb=0 assumed)
                        (clone_op(r), 0i64, mask_val)
                    } else if let Some(mask_val) = const_val(r) {
                        (clone_op(l), 0i64, mask_val)
                    } else {
                        continue;
                    }
                }
            };

            // Validate: mask_insert should have the form ((1<<width)-1) << lsb
            let (mask_lsb, width) = match mask_width_at_pos(mask_insert_val, expr.size) {
                Some(v) => v,
                None => continue,
            };
            if mask_lsb != lsl_lsb {
                // mask position doesn't match Lsl shift amount — check
                // if mask is at position 0 (i.e., src is not shifted)
                // Actually if lsb matches lsl_lsb, that's correct
                continue;
            }

            // Validate: mask_clear should be ~mask_insert for the given size
            let mask_insert_u64 = mask_insert_val as u64;
            let expected_clear = if expr.size == 8 {
                !mask_insert_u64
            } else {
                let size_mask = (1u64 << ((expr.size as u64) * 8)) - 1;
                (!mask_insert_u64) & size_mask
            };
            if mask_clear_val as u64 != expected_clear {
                // May also be represented as explicit NOT
                // If it doesn't match, skip
                continue;
            }

            return Some(Self::make_bf_insert(
                dst, src, lsl_lsb, width, expr.size, expr.pc,
            ));
        }

        // Simpler pattern: Or(And(dst, ~mask_insert), Lsl(src, lsb))
        // where the second And is omitted (masking done by lsl overflow)
        // This is less common but we try it as a fallback
        for (and_clear_idx, lsl_idx) in [(0usize, 1usize), (1, 0)] {
            let and_clear = match &expr.operands[and_clear_idx] {
                PassIlOperand::Expr(e) if e.op == "LLIL_And" && e.operands.len() == 2 => e,
                _ => continue,
            };
            let lsl_expr = match &expr.operands[lsl_idx] {
                PassIlOperand::Expr(e) if e.op == "LLIL_Lsl" && e.operands.len() == 2 => e,
                _ => continue,
            };

            let lsb = match const_val(&lsl_expr.operands[1]) {
                Some(v) => v,
                None => continue,
            };
            if lsb < 0 {
                continue;
            }
            let src = clone_op(&lsl_expr.operands[0]);

            // Extract dst and mask_clear from and_clear
            let (dst, mask_clear_val) = {
                let (l, r) = (&and_clear.operands[0], &and_clear.operands[1]);
                let mc = match const_val(l).or_else(|| const_val(r)) {
                    Some(v) => v,
                    None => continue,
                };
                if const_val(l).is_some() {
                    (clone_op(r), mc)
                } else {
                    (clone_op(l), mc)
                }
            };

            // The mask_clear should be all ones except at position lsb..lsb+width
            // But without knowing width, we can infer it from the clear mask
            let mask_clear_u64 = mask_clear_val as u64;
            let size_mask = if expr.size == 8 {
                !0u64
            } else {
                (1u64 << ((expr.size as u64) * 8)) - 1
            };
            // Inverted clear mask gives us the insert mask
            let insert_mask = (!mask_clear_u64) & size_mask;
            if insert_mask == 0 {
                continue;
            }
            // Check if insert_mask is contiguous 1 bits
            let (pos, width) = match mask_width_at_pos(insert_mask as i64, expr.size) {
                Some(v) => v,
                None => continue,
            };
            if pos != lsb {
                continue;
            }

            return Some(Self::make_bf_insert(
                dst, src, lsb, width, expr.size, expr.pc,
            ));
        }

        None
    }

    /// Scan an expression and its sub-expressions for bitfield patterns.
    /// Returns Some(new_expr) if any sub-expression matched, None otherwise.
    fn apply_recursive(expr: &PassIlExpr) -> Option<PassIlExpr> {
        // --- Phase A: Try multi-layer SBFX pattern BEFORE recursion ---
        // SBFX is Asr(Lsl(And(Lsr(src, #lsb), #mask), #sh), #sh).
        // In contrast, UBFX matches the inner And(Lsr, mask) in isolation.
        // If we recurse bottom-up, UBFX replaces the inner And, destroying
        // the nested structure SBFX needs. Thus: try SBFX top-down first.
        if let Some(result) = Self::try_sbfx(expr) {
            return Some(result);
        }

        // Phase B: Recurse into sub-expressions
        let mut new_operands: Vec<PassIlOperand> = expr.operands.clone();
        let mut operand_changed = false;
        for (j, op) in expr.operands.iter().enumerate() {
            if let PassIlOperand::Expr(child) = op {
                if let Some(new_child) = Self::apply_recursive(child) {
                    new_operands[j] = PassIlOperand::Expr(Box::new(new_child));
                    operand_changed = true;
                }
            }
        }

        let current = if operand_changed {
            PassIlExpr {
                op: expr.op.clone(),
                size: expr.size,
                pc: expr.pc,
                operands: new_operands,
                extra: expr.extra.clone(),
            }
        } else {
            expr.clone()
        };

        // Phase C: Try single-layer UBFX on the (possibly simplified) current node
        if let Some(result) = Self::try_ubfx(&current) {
            return Some(result);
        }
        // BFI pattern is applied later in the window scan, not here
        // (it spans multiple expressions)

        if operand_changed {
            Some(current)
        } else {
            None
        }
    }

    /// Scan for BFI patterns across expression windows.
    /// BFI typically spans 2-3 consecutive SetReg expressions.
    fn scan_bfi_windows(exprs: &mut Vec<PassIlExpr>) -> bool {
        let mut changed = false;
        let mut i = 0;
        while i < exprs.len() {
            if let Some((n, replacement)) = Self::try_bfi_window(&exprs[i..]) {
                // Replace the matched expressions
                // Find the indices of the matched sub-expressions and replace
                // the first one, mark others for deletion
                if n > 0 && i + n <= exprs.len() {
                    // Insert the bf_insert into the first SetReg-like wrapper
                    // The first expression should be a SetReg wrapping the Or
                    if let Some(new_top) = Self::wrap_in_setreg_if_needed(&exprs[i], &replacement) {
                        exprs[i] = new_top;
                    } else {
                        // Fallback: push the bf_insert as a standalone expression
                        // But bf_insert should produce a result, so we need SetReg
                        let size = replacement.size;
                        let pc = replacement.pc;
                        // Check if any of the window has the destination register
                        let dest = Self::find_bfi_dest(&exprs[i..i + n]);
                        let dest_op =
                            dest.unwrap_or_else(|| PassIlOperand::Var("bfi_result".to_string()));
                        exprs[i] = PassIlExpr {
                            op: "LLIL_SetReg".to_string(),
                            size,
                            pc,
                            operands: vec![dest_op, PassIlOperand::Expr(Box::new(replacement))],
                            extra: vec![("bf_op".to_string(), "bfi".to_string())],
                        };
                    }
                    // Mark the other matched expressions as dead
                    for j in (i + 1)..(i + n) {
                        if j < exprs.len() {
                            exprs[j]
                                .extra
                                .push(("bf_folded".to_string(), "dead".to_string()));
                        }
                    }
                    changed = true;
                    i += n;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }

        // Remove dead expressions
        if changed {
            exprs.retain(|e| !e.extra.iter().any(|(k, v)| k == "bf_folded" && v == "dead"));
        }

        changed
    }

    /// Try to match a BFI window starting at `exprs[0]`.
    /// Returns Some((num_exprs_consumed, bf_insert_expr)) or None.
    fn try_bfi_window(window: &[PassIlExpr]) -> Option<(usize, PassIlExpr)> {
        if window.len() < 2 {
            return None;
        }

        // Pattern 1: Two SetReg followed by an Or-style SetReg
        //   SetReg(t1, And(dst, mask_clear))
        //   SetReg(t2, Lsl(src, lsb))          [or And(Lsl(src, lsb), mask_insert)]
        //   SetReg(result, Or(t1, t2))
        //
        // Try to match 3 consecutive SetReg expressions
        if window.len() >= 3 {
            if let Some(result) = Self::try_bfi_3expr_window(&window[0], &window[1], &window[2]) {
                return Some((3, result));
            }
        }
        // Pattern 2: BFI is a single deeply-nested Or expression in a SetReg
        //   SetReg(result, Or(And(dst, mask_clear), And(Lsl(src, lsb), mask_insert)))
        if !window.is_empty() {
            let expr = &window[0];
            if expr.op == "LLIL_SetReg" && expr.operands.len() >= 2 {
                if let PassIlOperand::Expr(inner) = &expr.operands[1] {
                    if let Some(bfi) = Self::try_bfi(inner) {
                        return Some((1, bfi));
                    }
                }
            }
        }

        None
    }

    /// Try to match BFI across 3 consecutive expressions.
    fn try_bfi_3expr_window(
        e0: &PassIlExpr,
        e1: &PassIlExpr,
        e2: &PassIlExpr,
    ) -> Option<PassIlExpr> {
        // e0 = SetReg(t1, And(dst, mask_clear))
        // e1 = SetReg(t2, Lsl(src, lsb))   or SetReg(t2, And(Lsl(src, lsb), mask_insert))
        // e2 = SetReg(result, Or(t1_or_t2, t1_or_t2))
        if e0.op != "LLIL_SetReg" || e1.op != "LLIL_SetReg" || e2.op != "LLIL_SetReg" {
            return None;
        }
        let t1_var = Self::setreg_dest_var(e0)?;
        let t2_var = Self::setreg_dest_var(e1)?;

        // Validate e2 uses Or of t1 and t2
        let e2_inner = Self::setreg_src_expr(e2)?;
        if e2_inner.op != "LLIL_Or" || e2_inner.operands.len() != 2 {
            return None;
        }
        let (or_left, or_right) = (&e2_inner.operands[0], &e2_inner.operands[1]);
        let uses_t1_t2 = Self::is_var_ref(or_left, &t1_var) && Self::is_var_ref(or_right, &t2_var)
            || Self::is_var_ref(or_left, &t2_var) && Self::is_var_ref(or_right, &t1_var);
        if !uses_t1_t2 {
            return None;
        }

        // Extract from e0: And(dst, mask_clear)
        let e0_inner = Self::setreg_src_expr(e0)?;
        if e0_inner.op != "LLIL_And" || e0_inner.operands.len() != 2 {
            return None;
        }
        let (e0_a, e0_b) = (&e0_inner.operands[0], &e0_inner.operands[1]);
        let (dst, mask_clear_val) = if let Some(v) = const_val(e0_a) {
            (clone_op(e0_b), v)
        } else if let Some(v) = const_val(e0_b) {
            (clone_op(e0_a), v)
        } else {
            return None;
        };

        // Extract from e1: Lsl(src, lsb) or And(Lsl(src, lsb), mask_insert)
        let e1_inner = Self::setreg_src_expr(e1)?;
        let (src, lsb, mask_insert_val_opt) =
            if e1_inner.op == "LLIL_Lsl" && e1_inner.operands.len() == 2 {
                let lsb_val = const_val(&e1_inner.operands[1])?;
                (clone_op(&e1_inner.operands[0]), lsb_val, None::<i64>)
            } else if e1_inner.op == "LLIL_And" && e1_inner.operands.len() == 2 {
                // And(Lsl(src, lsb), mask_insert) or And(mask_insert, Lsl(src, lsb))
                let (ea, eb) = (&e1_inner.operands[0], &e1_inner.operands[1]);
                if let PassIlOperand::Expr(lsl) = ea {
                    if lsl.op == "LLIL_Lsl" && lsl.operands.len() == 2 {
                        let lsb_val = const_val(&lsl.operands[1])?;
                        let mask_val = const_val(eb);
                        (clone_op(&lsl.operands[0]), lsb_val, mask_val)
                    } else {
                        return None;
                    }
                } else if let PassIlOperand::Expr(lsl) = eb {
                    if lsl.op == "LLIL_Lsl" && lsl.operands.len() == 2 {
                        let lsb_val = const_val(&lsl.operands[1])?;
                        let mask_val = const_val(ea);
                        (clone_op(&lsl.operands[0]), lsb_val, mask_val)
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            } else {
                return None;
            };

        // Determine width from mask_clear
        let mask_clear_u64 = mask_clear_val as u64;
        let size_mask = if e0.size == 8 {
            !0u64
        } else {
            (1u64 << ((e0.size as u64) * 8)) - 1
        };
        let insert_mask = (!mask_clear_u64) & size_mask;
        if insert_mask == 0 {
            return None;
        }
        let (mask_pos, width) = mask_width_at_pos(insert_mask as i64, e0.size)?;
        if mask_pos != lsb {
            return None;
        }

        // If mask_insert_val is provided, verify it matches
        if let Some(mi) = mask_insert_val_opt {
            if mi as u64 != insert_mask {
                return None;
            }
        }

        Some(Self::make_bf_insert(dst, src, lsb, width, e0.size, e0.pc))
    }

    /// Extract the destination variable name from a SetReg expression.
    fn setreg_dest_var(expr: &PassIlExpr) -> Option<String> {
        if expr.op == "LLIL_SetReg" {
            match expr.operands.first() {
                Some(PassIlOperand::Var(name)) => Some(name.clone()),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Extract the source sub-expression from a SetReg expression.
    fn setreg_src_expr(expr: &PassIlExpr) -> Option<&PassIlExpr> {
        if expr.op == "LLIL_SetReg" && expr.operands.len() >= 2 {
            match &expr.operands[1] {
                PassIlOperand::Expr(e) => Some(e),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Check if an operand is a Var reference with a specific name.
    fn is_var_ref(op: &PassIlOperand, name: &str) -> bool {
        match op {
            PassIlOperand::Var(v) => v == name,
            _ => false,
        }
    }

    /// Find the destination variable from a window of BFI expressions.
    fn find_bfi_dest(window: &[PassIlExpr]) -> Option<PassIlOperand> {
        for expr in window {
            if expr.op == "LLIL_SetReg" {
                if let Some(PassIlOperand::Var(name)) = expr.operands.first() {
                    return Some(PassIlOperand::Var(name.clone()));
                }
            }
        }
        None
    }

    /// Wrap a bf_insert expression in a SetReg if the parent expression is a SetReg.
    fn wrap_in_setreg_if_needed(parent: &PassIlExpr, repl: &PassIlExpr) -> Option<PassIlExpr> {
        if parent.op == "LLIL_SetReg" {
            if let Some(PassIlOperand::Var(dest)) = parent.operands.first() {
                return Some(PassIlExpr {
                    op: "LLIL_SetReg".to_string(),
                    size: repl.size,
                    pc: repl.pc,
                    operands: vec![
                        PassIlOperand::Var(dest.clone()),
                        PassIlOperand::Expr(Box::new(repl.clone())),
                    ],
                    extra: repl.extra.clone(),
                });
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Constructors for canoncal IL expressions
    // ------------------------------------------------------------------

    /// Create a bf_extract IL expression node.
    fn make_bf_extract(
        src: PassIlOperand,
        lsb: i64,
        width: i64,
        signed: bool,
        size: u8,
        pc: u64,
    ) -> PassIlExpr {
        let (op, arm_op) = if signed {
            ("LLIL_BfExtractS", "sbfx")
        } else {
            ("LLIL_BfExtractU", "ubfx")
        };
        PassIlExpr {
            op: op.to_string(),
            size,
            pc,
            operands: vec![src, PassIlOperand::Imm(lsb), PassIlOperand::Imm(width)],
            extra: vec![
                ("bf_op".to_string(), arm_op.to_string()),
                ("bf_lsb".to_string(), lsb.to_string()),
                ("bf_width".to_string(), width.to_string()),
            ],
        }
    }

    /// Create a bf_insert IL expression node.
    fn make_bf_insert(
        dst: PassIlOperand,
        src: PassIlOperand,
        lsb: i64,
        width: i64,
        size: u8,
        pc: u64,
    ) -> PassIlExpr {
        PassIlExpr {
            op: "LLIL_BfInsert".to_string(),
            size,
            pc,
            operands: vec![dst, src, PassIlOperand::Imm(lsb), PassIlOperand::Imm(width)],
            extra: vec![
                ("bf_op".to_string(), "bfi".to_string()),
                ("bf_lsb".to_string(), lsb.to_string()),
                ("bf_width".to_string(), width.to_string()),
            ],
        }
    }
}

// ============================================================================
// Pass trait implementation
// ============================================================================

impl Pass for BitFieldTransformPass {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "BitFieldTransform",
            description:
                "Detect ARM64 bitfield patterns (UBFX/SBFX/BFI) and replace with canonical bf_extract/bf_insert",
            phase: 3,
            requires: &[],
            invalidates: &["DeadCodeElim"],
            repeat_until_fixpoint: true,
        }
    }

    fn run(&self, _ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let mut changed = false;

        // Phase 1: Recursive pattern matching on individual expressions (UBFX, SBFX)
        for i in 0..exprs.exprs.len() {
            if let Some(new_expr) = Self::apply_recursive(&exprs.exprs[i]) {
                exprs.exprs[i] = new_expr;
                changed = true;
            }
        }

        // Phase 2: Window-based pattern matching (BFI)
        if Self::scan_bfi_windows(&mut exprs.exprs) {
            changed = true;
        }

        if changed {
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
    // UBFX pattern tests
    // =========================================================================

    #[test]
    fn test_ubfx_basic() {
        // ubfx x0, x1, #2, #4 → And(Lsr(x1, 2), 0xF)
        // mask = (1<<4)-1 = 15
        let and_expr = make_expr(
            "LLIL_And",
            vec![expr("LLIL_Lsr", vec![reg("x1"), imm(2)]), imm(15)],
        );
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_ubfx(&and_expr);
        assert!(result.is_some(), "Should match UBFX pattern");
        let r = result.unwrap();
        assert_eq!(r.op, "LLIL_BfExtractU");
        assert_eq!(r.operands.len(), 3);
        // src
        match &r.operands[0] {
            PassIlOperand::Var(v) => assert_eq!(v, "x1"),
            _ => panic!("Expected Var for src"),
        }
        // lsb
        match &r.operands[1] {
            PassIlOperand::Imm(v) => assert_eq!(*v, 2),
            _ => panic!("Expected Imm for lsb"),
        }
        // width
        match &r.operands[2] {
            PassIlOperand::Imm(v) => assert_eq!(*v, 4),
            _ => panic!("Expected Imm for width"),
        }
        // extra metadata
        assert!(r.extra.iter().any(|(k, v)| k == "bf_op" && v == "ubfx"));
    }

    #[test]
    fn test_ubfx_swapped_operands() {
        // mask first, then Lsr: And(15, Lsr(x1, 2))
        let and_expr = make_expr(
            "LLIL_And",
            vec![imm(15), expr("LLIL_Lsr", vec![reg("x1"), imm(2)])],
        );
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_ubfx(&and_expr);
        assert!(result.is_some(), "Should match swapped UBFX pattern");
        let r = result.unwrap();
        assert_eq!(r.op, "LLIL_BfExtractU");
    }

    #[test]
    fn test_ubfx_8byte_mask() {
        // ubfx x0, x1, #16, #32 → And(Lsr(x1, 16), 0xFFFFFFFF)
        let mask = (1i64 << 32) - 1; // 0xFFFFFFFF
        let and_expr = make_expr(
            "LLIL_And",
            vec![expr("LLIL_Lsr", vec![reg("x1"), imm(16)]), imm(mask)],
        );
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_ubfx(&and_expr);
        assert!(result.is_some(), "Should match 32-bit UBFX");
        let r = result.unwrap();
        match &r.operands[1] {
            PassIlOperand::Imm(v) => assert_eq!(*v, 16),
            _ => panic!("Expected lsb"),
        }
        match &r.operands[2] {
            PassIlOperand::Imm(v) => assert_eq!(*v, 32),
            _ => panic!("Expected width"),
        }
    }

    #[test]
    fn test_ubfx_no_match_non_mask() {
        // And(Lsr(x1, 2), 42) — 42 is not a (1<<width)-1 mask
        let and_expr = make_expr(
            "LLIL_And",
            vec![expr("LLIL_Lsr", vec![reg("x1"), imm(2)]), imm(42)],
        );
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_ubfx(&and_expr);
        assert!(result.is_none(), "42 is not a contiguous mask from bit 0");
    }

    #[test]
    fn test_ubfx_no_match_not_lsr() {
        // And(x1, 15) — no shift, just a plain AND
        let and_expr = make_expr("LLIL_And", vec![reg("x1"), imm(15)]);
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_ubfx(&and_expr);
        // No Lsr found, so not a bitfield extract
        assert!(result.is_none());
    }

    #[test]
    fn test_ubfx_no_match_zero_mask() {
        // And(Lsr(x1, 2), 0) — zero mask
        let and_expr = make_expr(
            "LLIL_And",
            vec![expr("LLIL_Lsr", vec![reg("x1"), imm(2)]), imm(0)],
        );
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_ubfx(&and_expr);
        assert!(result.is_none(), "zero mask should not match");
    }

    #[test]
    fn test_ubfx_no_match_negative_lsb() {
        let and_expr = make_expr(
            "LLIL_And",
            vec![expr("LLIL_Lsr", vec![reg("x1"), imm(-1)]), imm(15)],
        );
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_ubfx(&and_expr);
        assert!(result.is_none(), "negative lsb should not match");
    }

    // =========================================================================
    // SBFX pattern tests
    // =========================================================================

    #[test]
    fn test_sbfx_basic() {
        // sbfx x0, x1, #2, #4
        // LLIL: Asr(Lsl(And(Lsr(x1, 2), 0xF), 60), 60)
        // width=4, sh=64-4=60, mask=(1<<4)-1=15
        let inner = expr(
            "LLIL_Lsl",
            vec![
                expr(
                    "LLIL_And",
                    vec![expr("LLIL_Lsr", vec![reg("x1"), imm(2)]), imm(15)],
                ),
                imm(60),
            ],
        );
        let outer = make_expr("LLIL_Asr", vec![inner, imm(60)]);
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_sbfx(&outer);
        assert!(result.is_some(), "Should match SBFX pattern");
        let r = result.unwrap();
        assert_eq!(r.op, "LLIL_BfExtractS");
        // src
        match &r.operands[0] {
            PassIlOperand::Var(v) => assert_eq!(v, "x1"),
            _ => panic!("Expected Var for src"),
        }
        // lsb
        match &r.operands[1] {
            PassIlOperand::Imm(v) => assert_eq!(*v, 2),
            _ => panic!("Expected Imm for lsb"),
        }
        // width
        match &r.operands[2] {
            PassIlOperand::Imm(v) => assert_eq!(*v, 4),
            _ => panic!("Expected Imm for width"),
        }
        assert!(r.extra.iter().any(|(k, v)| k == "bf_op" && v == "sbfx"));
    }

    #[test]
    fn test_sbfx_lsb_zero() {
        // sbfx x0, x1, #0, #8 — no Lsr needed (lsb=0)
        // LLIL: Asr(Lsl(And(x1, 0xFF), 56), 56)
        // width=8, sh=64-8=56
        let inner = expr(
            "LLIL_Lsl",
            vec![expr("LLIL_And", vec![reg("x1"), imm(0xFF)]), imm(56)],
        );
        let outer = make_expr("LLIL_Asr", vec![inner, imm(56)]);
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_sbfx(&outer);
        assert!(result.is_some(), "Should match SBFX with lsb=0");
        let r = result.unwrap();
        match &r.operands[1] {
            PassIlOperand::Imm(v) => assert_eq!(*v, 0, "lsb should be 0"),
            _ => panic!("Expected Imm"),
        }
        match &r.operands[2] {
            PassIlOperand::Imm(v) => assert_eq!(*v, 8, "width should be 8"),
            _ => panic!("Expected Imm"),
        }
    }

    #[test]
    fn test_sbfx_no_match_wrong_shift() {
        // Asr(Lsl(..., 60), 50) — mismatched shift amounts
        let inner = expr(
            "LLIL_Lsl",
            vec![
                expr(
                    "LLIL_And",
                    vec![expr("LLIL_Lsr", vec![reg("x1"), imm(2)]), imm(15)],
                ),
                imm(60),
            ],
        );
        let outer = make_expr("LLIL_Asr", vec![inner, imm(50)]);
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_sbfx(&outer);
        assert!(result.is_none(), "Mismatched shifts should not match");
    }

    #[test]
    fn test_sbfx_no_match_no_lsl() {
        // Just Asr(x, 60) — not a sign-extended extract
        let outer = make_expr("LLIL_Asr", vec![reg("x1"), imm(60)]);
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_sbfx(&outer);
        assert!(result.is_none());
    }

    // =========================================================================
    // BFI pattern tests (single-expression nested Or)
    // =========================================================================

    #[test]
    fn test_bfi_single_expr() {
        // BFI x0, x1, #8, #4
        // Or(And(x0, 0xFFFFFFFFFFFFF0FF), And(Lsl(x1, 8), 0xF00))
        // mask_insert = ((1<<4)-1) << 8 = 0xF00
        // mask_clear = ~0xF00 = 0xFFFFFFFFFFFFF0FF (in 8 bytes)
        let mask_insert = ((1i64 << 4) - 1) << 8; // 0xF00 = 3840
        let mask_clear = !mask_insert; // ~3840
        let or_expr = make_expr(
            "LLIL_Or",
            vec![
                expr("LLIL_And", vec![reg("x0"), imm(mask_clear)]),
                expr(
                    "LLIL_And",
                    vec![expr("LLIL_Lsl", vec![reg("x1"), imm(8)]), imm(mask_insert)],
                ),
            ],
        );
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_bfi(&or_expr);
        assert!(result.is_some(), "Should match BFI pattern");
        let r = result.unwrap();
        assert_eq!(r.op, "LLIL_BfInsert");
        assert_eq!(r.operands.len(), 4);
        // dst
        match &r.operands[0] {
            PassIlOperand::Var(v) => assert_eq!(v, "x0"),
            _ => panic!("Expected Var for dst"),
        }
        // src
        match &r.operands[1] {
            PassIlOperand::Var(v) => assert_eq!(v, "x1"),
            _ => panic!("Expected Var for src"),
        }
        // lsb
        match &r.operands[2] {
            PassIlOperand::Imm(v) => assert_eq!(*v, 8),
            _ => panic!("Expected Imm for lsb"),
        }
        // width
        match &r.operands[3] {
            PassIlOperand::Imm(v) => assert_eq!(*v, 4),
            _ => panic!("Expected Imm for width"),
        }
    }

    #[test]
    fn test_bfi_swapped_operands() {
        // Swapped Or operands: Or(And(Lsl(src, lsb), mask), And(dst, ~mask))
        let mask_insert = 0xF00i64;
        let mask_clear = !mask_insert;
        let or_expr = make_expr(
            "LLIL_Or",
            vec![
                expr(
                    "LLIL_And",
                    vec![expr("LLIL_Lsl", vec![reg("x1"), imm(8)]), imm(mask_insert)],
                ),
                expr("LLIL_And", vec![reg("x0"), imm(mask_clear)]),
            ],
        );
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_bfi(&or_expr);
        assert!(result.is_some(), "Should match swapped BFI pattern");
    }

    #[test]
    fn test_bfi_no_match_non_contiguous_mask() {
        // Mask is not contiguous: 0x505 (non-contiguous bits)
        let or_expr = make_expr(
            "LLIL_Or",
            vec![
                expr("LLIL_And", vec![reg("x0"), imm(!0x505i64)]),
                expr(
                    "LLIL_And",
                    vec![expr("LLIL_Lsl", vec![reg("x1"), imm(8)]), imm(0x505)],
                ),
            ],
        );
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_bfi(&or_expr);
        assert!(result.is_none(), "Non-contiguous mask should not match");
    }

    // =========================================================================
    // BFI 3-expression window tests
    // =========================================================================

    #[test]
    fn test_bfi_3expr_window() {
        // t1 = x0 & 0xFFFFFFFFFFFFF0FF   (clear destination bits)
        // t2 = x1 << 8                     (shift source)
        // result = t1 | t2                 (combine)
        let mask_clear = !3840i64; // ~0xF00
        let e0 = make_setreg(
            "t1",
            make_expr("LLIL_And", vec![reg("x0"), imm(mask_clear)]),
        );
        let e1 = make_setreg("t2", make_expr("LLIL_Lsl", vec![reg("x1"), imm(8)]));
        let e2 = make_setreg("x0", make_expr("LLIL_Or", vec![reg("t1"), reg("t2")]));
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_bfi_3expr_window(&e0, &e1, &e2);
        assert!(result.is_some(), "Should match 3-expr BFI window");
        let r = result.unwrap();
        assert_eq!(r.op, "LLIL_BfInsert");
        match &r.operands[2] {
            PassIlOperand::Imm(v) => assert_eq!(*v, 8, "lsb=8"),
            _ => panic!("Expected Imm"),
        }
        match &r.operands[3] {
            PassIlOperand::Imm(v) => assert_eq!(*v, 4, "width=4"),
            _ => panic!("Expected Imm"),
        }
    }

    #[test]
    fn test_bfi_3expr_with_mask_on_src() {
        // t1 = x0 & ~0xF00               (clear destination bits)
        // t2 = (x1 << 8) & 0xF00         (shift and mask source)
        // result = t1 | t2
        let mask_insert = 0xF00i64;
        let mask_clear = !mask_insert;
        let e0 = make_setreg(
            "t1",
            make_expr("LLIL_And", vec![reg("x0"), imm(mask_clear)]),
        );
        let e1 = make_setreg(
            "t2",
            make_expr(
                "LLIL_And",
                vec![expr("LLIL_Lsl", vec![reg("x1"), imm(8)]), imm(mask_insert)],
            ),
        );
        let e2 = make_setreg("x0", make_expr("LLIL_Or", vec![reg("t1"), reg("t2")]));
        let pass = BitFieldTransformPass;
        let result = BitFieldTransformPass::try_bfi_3expr_window(&e0, &e1, &e2);
        assert!(result.is_some(), "Should match 3-expr BFI with mask on src");
    }

    // =========================================================================
    // Full Pass integration tests
    // =========================================================================

    #[test]
    fn test_pass_ubfx_in_setreg() {
        // SetReg(x0, And(Lsr(x1, 3), 0x1F))
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_setreg(
                "x0#1",
                make_expr(
                    "LLIL_And",
                    vec![expr("LLIL_Lsr", vec![reg("x1"), imm(3)]), imm(0x1F)],
                ),
            ),
            make_expr("LLIL_Ret", vec![reg("x0#1")]),
        ];
        let pass = BitFieldTransformPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 3,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed(), "Pass should detect UBFX");
        // The SetReg source should now be a bf_extract
        match &exprs.exprs[0].operands[1] {
            PassIlOperand::Expr(e) => {
                assert_eq!(e.op, "LLIL_BfExtractU", "Expected BfExtractU");
            }
            _ => panic!("Expected Expr for SetReg source"),
        }
    }

    #[test]
    fn test_pass_no_bitfield_no_change() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_setreg("x0#1", make_expr("LLIL_Add", vec![reg("x1"), imm(1)])),
            make_expr("LLIL_Ret", vec![reg("x0#1")]),
        ];
        let pass = BitFieldTransformPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 3,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(
            !result.is_changed(),
            "No bitfield pattern, should be unchanged"
        );
    }

    #[test]
    fn test_pass_sbfx_in_setreg() {
        // SetReg(x0, Asr(Lsl(And(Lsr(x1, 5), 0x7F), 57), 57))
        // width=7, lsb=5, sh=64-7=57
        let inner = expr(
            "LLIL_Lsl",
            vec![
                expr(
                    "LLIL_And",
                    vec![expr("LLIL_Lsr", vec![reg("x1"), imm(5)]), imm(0x7F)],
                ),
                imm(57),
            ],
        );
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_setreg("x0#1", make_expr("LLIL_Asr", vec![inner, imm(57)])),
            make_expr("LLIL_Ret", vec![reg("x0#1")]),
        ];
        let pass = BitFieldTransformPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 3,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed(), "Pass should detect SBFX");
        match &exprs.exprs[0].operands[1] {
            PassIlOperand::Expr(e) => {
                assert_eq!(e.op, "LLIL_BfExtractS", "Expected BfExtractS");
            }
            _ => panic!("Expected Expr"),
        }
    }

    #[test]
    fn test_pass_bfi_3expr_window_full() {
        // Full BFI across 3 SetReg expressions
        let mask_insert = 0x3F00i64; // width=6, lsb=8
        let mask_clear = !mask_insert;
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_setreg(
                "t1#1",
                make_expr("LLIL_And", vec![reg("x0"), imm(mask_clear)]),
            ),
            make_setreg(
                "t2#1",
                make_expr(
                    "LLIL_And",
                    vec![expr("LLIL_Lsl", vec![reg("x1"), imm(8)]), imm(mask_insert)],
                ),
            ),
            make_setreg("x0#2", make_expr("LLIL_Or", vec![reg("t1#1"), reg("t2#1")])),
            make_expr("LLIL_Ret", vec![reg("x0#2")]),
        ];
        let pass = BitFieldTransformPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 3,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed(), "Pass should detect BFI 3-expr window");
        // Should have 2 expressions left: the bf_insert SetReg + Ret
        assert_eq!(exprs.exprs.len(), 2, "Expected 2 exprs after BFI folding");
        // First expression should contain BfInsert
        match &exprs.exprs[0].operands[1] {
            PassIlOperand::Expr(e) => {
                assert_eq!(e.op, "LLIL_BfInsert", "Expected BfInsert, got {}", e.op);
            }
            _ => panic!("Expected Expr"),
        }
    }

    #[test]
    fn test_pass_bfi_single_expr_nested() {
        // BFI as a deeply nested single expression
        let mask_insert = 0x1F00i64; // width=5, lsb=8
        let mask_clear = !mask_insert;
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_setreg(
                "x0#1",
                make_expr(
                    "LLIL_Or",
                    vec![
                        expr("LLIL_And", vec![reg("x0"), imm(mask_clear)]),
                        expr(
                            "LLIL_And",
                            vec![expr("LLIL_Lsl", vec![reg("x1"), imm(8)]), imm(mask_insert)],
                        ),
                    ],
                ),
            ),
            make_expr("LLIL_Ret", vec![reg("x0#1")]),
        ];
        let pass = BitFieldTransformPass;
        let ctx = PassContext {
            function_name: "test",
            phase: 3,
            verbose: false,
        };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed(), "Should detect nested single-expr BFI");
        match &exprs.exprs[0].operands[1] {
            PassIlOperand::Expr(e) => {
                assert_eq!(e.op, "LLIL_BfInsert");
            }
            _ => panic!("Expected Expr"),
        }
    }

    // =========================================================================
    // Helper function tests
    // =========================================================================

    #[test]
    fn test_mask_width_low_power_of_two_minus_one() {
        assert_eq!(mask_width_low(0xFF, 8), Some(8)); // 0xFF = (1<<8)-1
        assert_eq!(mask_width_low(0x7FFF, 8), Some(15)); // (1<<15)-1
        assert_eq!(mask_width_low(1, 8), Some(1)); // width=1
        assert_eq!(mask_width_low(3, 8), Some(2)); // width=2
    }

    #[test]
    fn test_mask_width_low_non_contiguous() {
        assert_eq!(mask_width_low(0x55, 8), None); // 0b01010101 — non-contiguous
        assert_eq!(mask_width_low(10, 8), None); // 0b1010 — non-contiguous
        assert_eq!(mask_width_low(0, 8), None); // zero
        assert_eq!(mask_width_low(-1, 8), None); // all ones, not meaningful
    }

    #[test]
    fn test_mask_width_at_pos() {
        assert_eq!(mask_width_at_pos(0xFF00, 8), Some((8, 8))); // ((1<<8)-1)<<8
        assert_eq!(mask_width_at_pos(0x70, 8), Some((4, 3))); // ((1<<3)-1)<<4
        assert_eq!(mask_width_at_pos(0x3F, 8), Some((0, 6))); // at pos 0
        assert_eq!(mask_width_at_pos(0xFF00000000, 4), None); // lsb=36, width=8, 36+8=44 > 32 bits
    }

    #[test]
    fn test_mask_width_at_pos_non_contiguous() {
        assert_eq!(mask_width_at_pos(0xA0, 8), None); // 0b10100000 — 2 bits, not contiguous
        assert_eq!(mask_width_at_pos(0, 8), None);
    }
}
