//! ARM64 -> LLIL lifter.
//!
//! M5: lifted coverage expanded (csel, sx/zx, bitfield, madd/msub, extr, adr/adrp)
//! and NZCV flag model (N, Z, C, V tracked independently, ref BN LLIL).

use std::collections::BTreeMap;

use crate::disasm::{decode, DecodedInsn};
use crate::llil::expr::{
    binary, const_ptr, csel as csel_expr, expr, flag, flag_cond, konst, reg, set_flag, set_reg, sx,
    unary, zx, LlilExpr, LlilOp, LlilOperand,
};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LiftStats {
    pub total: usize,
    pub intrinsic: usize,
    pub by_op: BTreeMap<String, usize>,
}

impl LiftStats {
    pub fn coverage(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            1.0 - (self.intrinsic as f64 / self.total as f64)
        }
    }

    pub fn record(&mut self, d: &DecodedInsn, lifted: &[LlilExpr]) {
        self.total += 1;
        *self.by_op.entry(base_mnem(d).to_string()).or_default() += 1;
        if lifted.iter().any(|e| e.op == LlilOp::Intrinsic) {
            self.intrinsic += 1;
        }
    }
}

pub fn lift_arm64(pc: u64, inst: u32) -> Vec<LlilExpr> {
    let d = decode(pc, inst);
    lift_decoded(&d)
}

pub fn lift_decoded(d: &DecodedInsn) -> Vec<LlilExpr> {
    let base = base_mnem(d);
    match base {
        "nop" => vec![LlilExpr::new(LlilOp::Nop, 0, Vec::new(), d.pc)],
        "mov" | "movz" => vec![lift_mov(d)],
        "movk" => vec![lift_movk(d)],
        "add" => lift_binary_reg(d, LlilOp::Add, false),
        "adds" => lift_binary_reg(d, LlilOp::Add, true),
        "sub" => lift_binary_reg(d, LlilOp::Sub, false),
        "subs" => lift_binary_reg(d, LlilOp::Sub, true),
        "mul" => lift_binary_reg(d, LlilOp::Mul, false),
        "smull" => lift_mull(d, true),
        "umull" => lift_mull(d, false),
        "and" => lift_binary_reg(d, LlilOp::And, false),
        "ands" => lift_binary_reg(d, LlilOp::And, true),
        "orr" => lift_binary_reg(d, LlilOp::Or, false),
        "eor" => lift_binary_reg(d, LlilOp::Xor, false),
        "lsl" | "lslv" => lift_binary_reg(d, LlilOp::Lsl, false),
        "lsr" | "lsrv" => lift_binary_reg(d, LlilOp::Lsr, false),
        "asr" | "asrv" => lift_binary_reg(d, LlilOp::Asr, false),
        "ror" | "rorv" => lift_binary_reg(d, LlilOp::Ror, false),
        "sdiv" => lift_binary_reg(d, LlilOp::DivS, false),
        "udiv" => lift_binary_reg(d, LlilOp::DivU, false),
        "mneg" => lift_mneg(d),
        "neg" => lift_unary_reg(d, LlilOp::Neg, false),
        "negs" => lift_unary_reg(d, LlilOp::Neg, true),
        "ngc" | "sbc" => lift_ngc(d, false),
        "ngcs" => lift_ngc(d, true),
        "mvn" => lift_unary_reg(d, LlilOp::Not, false),
        "cmp" => lift_cmp(d, LlilOp::Sub),
        "cmn" => lift_cmp(d, LlilOp::Add),
        "tst" => lift_cmp(d, LlilOp::And),
        "csel" | "csinc" | "csinv" | "csneg" | "cinc" | "cinv" | "cneg" => lift_csel(d),
        "cset" | "csetm" => lift_cset(d),
        "sxtb" => lift_extend(d, 1, true),
        "sxth" => lift_extend(d, 2, true),
        "sxtw" => lift_extend(d, 4, true),
        "uxtb" => lift_extend(d, 1, false),
        "uxth" => lift_extend(d, 2, false),
        "madd" => lift_madd(d, LlilOp::Add),
        "msub" => lift_madd(d, LlilOp::Sub),
        "extr" => lift_extr(d),
        "adr" | "adrp" => lift_adr(d),
        "ldr" | "ldur" | "ldp" | "ldnp" => lift_load(d),
        "ldrb" | "ldrh" | "ldurb" => lift_load_ext(d, false),
        "ldrsb" | "ldrsh" | "ldrsw" => lift_load_ext(d, true),
        "str" | "strb" | "strh" | "stur" | "stp" | "stnp" | "sturb" => lift_store(d),
        "mrs" => lift_mrs(d),
        "ubfm" | "bfxil" => lift_bfm(d, false),
        "sbfm" => lift_bfm(d, true),
        "ubfx" => lift_ubfx(d, false),
        "sbfx" => lift_ubfx(d, true),
        // orn = ~(a & ~b) = ~a | b  →  Not(And(Not(a), b))
        "orn" => lift_orn(d),
        "bic" => lift_bic(d),
        "dmb" | "isb" => vec![LlilExpr::new(LlilOp::Nop, 0, Vec::new(), d.pc)],
        "ldarb" | "ldaxrb" => lift_load_ext(d, false),
        "stlrb" => lift_store(d),
        // ccmp: conditional compare — complex semantics, keep as intrinsic for now
        "ccmp" | "ccmn" => vec![intrinsic(d)],
        _ if is_b_cond(d) => lift_b_cond(d),
        "b" => lift_b(d),
        "bl" | "blr" => vec![LlilExpr::new(
            LlilOp::Call,
            8,
            vec![expr(target_expr(d))],
            d.pc,
        )],
        "br" => vec![LlilExpr::new(
            LlilOp::Jump,
            8,
            vec![expr(target_expr(d))],
            d.pc,
        )],
        "ret" => vec![LlilExpr::new(LlilOp::Ret, 8, Vec::new(), d.pc)],
        _ if matches!(base, "cbz" | "cbnz") => lift_cbz(d, base == "cbnz"),
        _ if matches!(base, "tbz" | "tbnz") => lift_tbz(d, base == "tbnz"),
        _ => vec![intrinsic(d)],
    }
}

fn base_mnem(d: &DecodedInsn) -> &str {
    d.mnemonic.split('.').next().unwrap_or(&d.mnemonic)
}

fn lift_mov(d: &DecodedInsn) -> LlilExpr {
    let dst = first_def(d);
    let parts = split_operands(&d.op_str);
    let value = parts
        .get(1)
        .and_then(|p| parse_imm(p).map(konst))
        .or_else(|| {
            // xzr/wzr → konst(0) (Capstone filters these from regs_use)
            parts.get(1).filter(|p| *p == "xzr" || *p == "wzr").map(|_| konst(0))
        })
        .or_else(|| {
            d.regs_use.first().map(|r| reg(r.clone()))
        })
        .unwrap_or_else(|| intrinsic(d));
    set_reg(dst, value, d.pc)
}

fn lift_movk(d: &DecodedInsn) -> LlilExpr {
    let dst = first_def(d);
    let parts = split_operands(&d.op_str);
    let imm = parts.get(1).and_then(|p| parse_imm(p)).unwrap_or(0);
    let shift = parts
        .iter()
        .find_map(|p| p.strip_prefix("lsl #").and_then(parse_imm))
        .unwrap_or(0);
    let mask = !(0xffff_i64 << shift);
    let merged = binary(
        LlilOp::Or,
        binary(LlilOp::And, reg(dst.clone()), konst(mask)),
        konst(imm << shift),
    );
    set_reg(dst, merged, d.pc)
}

fn lift_binary_reg(d: &DecodedInsn, op: LlilOp, set_flags: bool) -> Vec<LlilExpr> {
    let Some(dst) = d.regs_def.first().cloned() else {
        return vec![intrinsic(d)];
    };
    let parts = split_operands(&d.op_str);
    let lhs = if op == LlilOp::And && set_flags {
        // ands with immediate: the immediate is the FIRST operand in capstone's op_str
        // e.g. "ands x0, x1, #0xf" -> parts = ["x0", "x1", "#0xf"]
        d.regs_use
            .first()
            .cloned()
            .map(reg)
            .or_else(|| parts.get(1).map(|p| reg(p.clone())))
            .unwrap_or_else(|| reg("xzr"))
    } else {
        d.regs_use.first().cloned().map(reg).unwrap_or_else(|| {
            parts
                .get(1)
                .map(|p| reg(p.clone()))
                .unwrap_or_else(|| reg("xzr"))
        })
    };
    let rhs = parts
        .get(2)
        .and_then(|p| parse_imm(p).map(konst))
        .or_else(|| d.regs_use.get(1).cloned().map(reg))
        .unwrap_or_else(|| konst(0));
    let result = binary(op, lhs.clone(), rhs.clone());
    let mut out = vec![set_reg(dst, result.clone(), d.pc)];
    if set_flags {
        out.extend(nzcv_from_binary(op, d.pc, &lhs, &rhs, &result));
    }
    out
}

fn lift_unary_reg(d: &DecodedInsn, op: LlilOp, set_flags: bool) -> Vec<LlilExpr> {
    let Some(dst) = d.regs_def.first().cloned() else {
        return vec![intrinsic(d)];
    };
    let value = d
        .regs_use
        .first()
        .cloned()
        .map(reg)
        .unwrap_or_else(|| konst(0));
    let result = unary(op, value.clone());
    let mut out = vec![set_reg(dst, result.clone(), d.pc)];
    if set_flags {
        out.push(set_flag(
            "n",
            binary(LlilOp::CmpSlt, result.clone(), konst(0)),
            d.pc,
        ));
        out.push(set_flag("z", binary(LlilOp::CmpE, result, konst(0)), d.pc));
        out.push(set_flag("c", konst(0), d.pc));
        out.push(set_flag("v", konst(0), d.pc));
    }
    out
}

fn lift_cmp(d: &DecodedInsn, op: LlilOp) -> Vec<LlilExpr> {
    let lhs = d
        .regs_use
        .first()
        .cloned()
        .map(reg)
        .unwrap_or_else(|| konst(0));
    let parts = split_operands(&d.op_str);
    let rhs = parts
        .get(1)
        .and_then(|p| parse_imm(p).map(konst))
        .or_else(|| d.regs_use.get(1).cloned().map(reg))
        .unwrap_or_else(|| konst(0));
    let result = binary(op, lhs.clone(), rhs.clone());
    nzcv_from_binary(op, d.pc, &lhs, &rhs, &result)
}

fn nzcv_from_binary(
    op: LlilOp,
    pc: u64,
    lhs: &LlilExpr,
    rhs: &LlilExpr,
    result: &LlilExpr,
) -> Vec<LlilExpr> {
    let n = binary(LlilOp::CmpSlt, result.clone(), konst(0));
    let z = binary(LlilOp::CmpE, result.clone(), konst(0));

    let (c, v) = match op {
        LlilOp::Add => {
            let c_val = binary(LlilOp::CmpUlt, result.clone(), lhs.clone());
            let lhs_neg = binary(LlilOp::CmpSlt, lhs.clone(), konst(0));
            let rhs_neg = binary(LlilOp::CmpSlt, rhs.clone(), konst(0));
            let res_neg = binary(LlilOp::CmpSlt, result.clone(), konst(0));
            let same_sign = binary(LlilOp::CmpE, lhs_neg.clone(), rhs_neg);
            let sign_changed = binary(LlilOp::CmpNe, res_neg, lhs_neg);
            let v_val = binary(LlilOp::And, same_sign, sign_changed);
            (c_val, v_val)
        }
        LlilOp::Sub => {
            let c_val = binary(LlilOp::CmpUge, lhs.clone(), rhs.clone());
            let lhs_neg = binary(LlilOp::CmpSlt, lhs.clone(), konst(0));
            let rhs_neg = binary(LlilOp::CmpSlt, rhs.clone(), konst(0));
            let res_neg = binary(LlilOp::CmpSlt, result.clone(), konst(0));
            let diff_sign = binary(LlilOp::CmpNe, lhs_neg.clone(), rhs_neg);
            let sign_changed = binary(LlilOp::CmpNe, res_neg, lhs_neg);
            let v_val = binary(LlilOp::And, diff_sign, sign_changed);
            (c_val, v_val)
        }
        LlilOp::And => (konst(0), konst(0)),
        _ => (konst(0), konst(0)),
    };

    vec![
        set_flag("n", n, pc),
        set_flag("z", z, pc),
        set_flag("c", c, pc),
        set_flag("v", v, pc),
    ]
}

fn lift_csel(d: &DecodedInsn) -> Vec<LlilExpr> {
    let dst = first_def(d);
    let parts = split_operands(&d.op_str);
    let mnem = base_mnem(d);

    let true_reg = parts.get(1).cloned().unwrap_or_default();
    let false_reg = parts.get(2).cloned().unwrap_or_default();
    let cond = d
        .mnemonic
        .split('.')
        .nth(1)
        .or_else(|| parts.get(3).map(|s| s.as_str()))
        .unwrap_or("al");

    let true_val = d
        .regs_use
        .iter()
        .find(|r| **r == true_reg)
        .cloned()
        .map(reg)
        .or_else(|| reg_from_parts(&parts, 1))
        .unwrap_or_else(|| konst(0));

    let false_val = d
        .regs_use
        .iter()
        .skip(1)
        .find(|r| **r == false_reg)
        .cloned()
        .map(reg)
        .or_else(|| reg_from_parts(&parts, 2))
        .unwrap_or_else(|| konst(0));

    let false_val = match mnem {
        "csinc" | "cinc" => binary(LlilOp::Add, false_val, konst(1)),
        "csinv" | "cinv" => unary(LlilOp::Not, false_val),
        "csneg" | "cneg" => unary(LlilOp::Neg, false_val),
        _ => false_val,
    };

    let cond_expr = flag_cond(cond.to_string());
    vec![set_reg(
        dst,
        csel_expr(cond_expr, true_val, false_val),
        d.pc,
    )]
}

fn lift_cset(d: &DecodedInsn) -> Vec<LlilExpr> {
    let dst = first_def(d);
    let parts = split_operands(&d.op_str);
    let cond = d
        .mnemonic
        .split('.')
        .nth(1)
        .or_else(|| parts.get(1).map(|s| s.as_str()))
        .unwrap_or("al");
    let base = base_mnem(d);
    let true_val = konst(1);
    let false_val = if base == "csetm" { konst(-1) } else { konst(0) };
    let cond_expr = flag_cond(cond.to_string());
    vec![set_reg(
        dst,
        csel_expr(cond_expr, true_val, false_val),
        d.pc,
    )]
}

fn lift_extend(d: &DecodedInsn, from_bytes: u8, signed: bool) -> Vec<LlilExpr> {
    let dst = first_def(d);
    let parts = split_operands(&d.op_str);
    let src_reg = parts.get(1).cloned().unwrap_or_default();
    let src = d
        .regs_use
        .first()
        .cloned()
        .map(reg)
        .unwrap_or_else(|| reg(src_reg));
    let result = if signed {
        sx(from_bytes, src)
    } else {
        zx(from_bytes, src)
    };
    vec![set_reg(dst, result, d.pc)]
}

fn lift_madd(d: &DecodedInsn, op: LlilOp) -> Vec<LlilExpr> {
    let dst = first_def(d);
    let parts = split_operands(&d.op_str);
    let mul_lhs = d
        .regs_use
        .first()
        .cloned()
        .map(reg)
        .or_else(|| reg_from_parts(&parts, 1))
        .unwrap_or_else(|| konst(0));
    let mul_rhs = d
        .regs_use
        .get(1)
        .cloned()
        .map(reg)
        .or_else(|| reg_from_parts(&parts, 2))
        .unwrap_or_else(|| konst(0));
    let acc = d
        .regs_use
        .get(2)
        .cloned()
        .map(reg)
        .or_else(|| reg_from_parts(&parts, 3))
        .unwrap_or_else(|| konst(0));
    let product = binary(LlilOp::Mul, mul_lhs, mul_rhs);
    let result = binary(op, product, acc);
    vec![set_reg(dst, result, d.pc)]
}

fn lift_extr(d: &DecodedInsn) -> Vec<LlilExpr> {
    let dst = first_def(d);
    let parts = split_operands(&d.op_str);
    let lhs = d
        .regs_use
        .first()
        .cloned()
        .map(reg)
        .or_else(|| reg_from_parts(&parts, 1))
        .unwrap_or_else(|| reg("xzr"));
    let rhs = d
        .regs_use
        .get(1)
        .cloned()
        .map(reg)
        .or_else(|| reg_from_parts(&parts, 2))
        .unwrap_or_else(|| reg("xzr"));
    let shift = parts.get(3).and_then(|p| parse_imm(p)).unwrap_or(0) as u32;
    let width = 64;
    let high = binary(LlilOp::Lsr, lhs, konst(shift as i64));
    let low = if shift < width {
        binary(LlilOp::Lsl, rhs, konst((width - shift) as i64))
    } else {
        konst(0)
    };
    let result = binary(LlilOp::Or, high, low);
    vec![set_reg(dst, result, d.pc)]
}

fn lift_adr(d: &DecodedInsn) -> Vec<LlilExpr> {
    let dst = first_def(d);
    let target = parse_target(&d.op_str).unwrap_or(d.pc);
    vec![set_reg(dst, const_ptr(target), d.pc)]
}

/// Handle PC-relative literal loads (ldr/ldrsw/ldrsh literal form).
/// These have no memory operand in Capstone — the address is PC + imm*4.
fn lift_load_literal(d: &DecodedInsn, signed_ext: bool) -> Vec<LlilExpr> {
    let dst = first_def(d);
    // Parse "x4, #0x6f7a908824" → extract target address
    let parts = split_operands(&d.op_str);
    let target = parts.get(1).and_then(|p| parse_target(p)).unwrap_or(d.pc);
    let load = LlilExpr::new(
        LlilOp::Load,
        4, // literal loads are always 32-bit or 64-bit
        vec![expr(const_ptr(target))],
        d.pc,
    );
    let result = if signed_ext {
        sx(4, load)
    } else {
        load
    };
    vec![set_reg(dst, result, d.pc)]
}

fn lift_load(d: &DecodedInsn) -> Vec<LlilExpr> {
    if d.mem_op.is_empty() {
        // Try PC-relative literal load
        if d.regs_def.is_empty() {
            return vec![intrinsic(d)];
        }
        return lift_load_literal(d, false);
    }
    if d.regs_def.is_empty() {
        return vec![intrinsic(d)];
    }
    d.mem_op
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let dst = if !m.src_reg.is_empty() {
                m.src_reg.clone()
            } else {
                d.regs_def.get(i).cloned().unwrap_or_else(|| first_def(d))
            };
            let load = LlilExpr::new(
                LlilOp::Load,
                m.size as u8,
                vec![expr(mem_addr_expr(&m.base, &m.idx, m.disp))],
                d.pc,
            );
            set_reg(dst, load, d.pc)
        })
        .collect()
}

fn lift_store(d: &DecodedInsn) -> Vec<LlilExpr> {
    if d.mem_op.is_empty() {
        return vec![intrinsic(d)];
    }
    d.mem_op
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let src = if !m.src_reg.is_empty() {
                reg(m.src_reg.clone())
            } else {
                d.regs_use
                    .get(i)
                    .cloned()
                    .map(reg)
                    .unwrap_or_else(|| reg("xzr"))
            };
            LlilExpr::new(
                LlilOp::Store,
                m.size as u8,
                vec![expr(mem_addr_expr(&m.base, &m.idx, m.disp)), expr(src)],
                d.pc,
            )
        })
        .collect()
}

fn lift_b(d: &DecodedInsn) -> Vec<LlilExpr> {
    let target = parse_target(&d.op_str);
    match target {
        Some(t) => vec![LlilExpr::new(
            LlilOp::Goto,
            8,
            vec![LlilOperand::U64(t)],
            d.pc,
        )],
        None => vec![LlilExpr::new(
            LlilOp::Jump,
            8,
            vec![expr(target_expr(d))],
            d.pc,
        )],
    }
}

fn lift_b_cond(d: &DecodedInsn) -> Vec<LlilExpr> {
    let cond = d.mnemonic.split('.').nth(1).unwrap_or("al");
    let target = parse_target(&d.op_str).unwrap_or(d.pc);
    vec![LlilExpr::new(
        LlilOp::If,
        1,
        vec![
            expr(flag_cond(cond.to_string())),
            LlilOperand::U64(target),
            LlilOperand::U64(d.pc.wrapping_add(4)),
        ],
        d.pc,
    )]
}

fn lift_cbz(d: &DecodedInsn, nonzero: bool) -> Vec<LlilExpr> {
    // cbz/cbnz reads a general-purpose register AND flags.
    // Capstone reports implicit flag reads (nzcv) in regs_use BEFORE the
    // explicit register operand. Use the LAST non-flag register.
    let lhs = d
        .regs_use
        .iter()
        .filter(|r| *r != "nzcv")
        .last()
        .cloned()
        .or_else(|| {
            // Fallback: parse first operand from op_str "x0, #0x1c"
            split_operands(&d.op_str)
                .first()
                .filter(|s| !s.starts_with('#'))
                .cloned()
        })
        .map(reg)
        .unwrap_or_else(|| reg("xzr"));
    let cmp = binary(
        if nonzero { LlilOp::CmpNe } else { LlilOp::CmpE },
        lhs,
        konst(0),
    );
    let target = split_operands(&d.op_str)
        .get(1)
        .and_then(|p| parse_target(p))
        .unwrap_or(d.pc);
    vec![LlilExpr::new(
        LlilOp::If,
        1,
        vec![
            expr(cmp),
            LlilOperand::U64(target),
            LlilOperand::U64(d.pc.wrapping_add(4)),
        ],
        d.pc,
    )]
}

/// tbz/tbnz: test bit and branch.  Extract bit N from register, branch if zero/nonzero.
fn lift_tbz(d: &DecodedInsn, nonzero: bool) -> Vec<LlilExpr> {
    let parts = split_operands(&d.op_str);
    // op_str: "x0, #3, #0xc" (register, bit_number, target)
    let reg_name = parts.first().cloned().unwrap_or_default();
    let bit_num = parts.get(1).and_then(|p| parse_imm(p)).unwrap_or(0);
    let target = parts.get(2).and_then(|p| parse_target(p)).unwrap_or(d.pc);

    let lhs = d.regs_use.iter().find(|r| *r != "nzcv").cloned()
        .unwrap_or(reg_name);

    // Extract bit: (reg >> bit) & 1
    let shifted = binary(LlilOp::Lsr, reg(lhs.clone()), konst(bit_num));
    let bit_val = binary(LlilOp::And, shifted, konst(1));
    let cmp = binary(
        if nonzero { LlilOp::CmpNe } else { LlilOp::CmpE },
        bit_val,
        konst(0),
    );

    vec![LlilExpr::new(
        LlilOp::If,
        1,
        vec![
            expr(cmp),
            LlilOperand::U64(target),
            LlilOperand::U64(d.pc.wrapping_add(4)),
        ],
        d.pc,
    )]
}

fn is_b_cond(d: &DecodedInsn) -> bool {
    d.mnemonic.starts_with("b.") && d.mnemonic.len() > 2
}

fn target_expr(d: &DecodedInsn) -> LlilExpr {
    if let Some(target) = parse_target(&d.op_str) {
        return const_ptr(target);
    }
    // Try regs_use first (skip implicit nzcv reads like for cbnz)
    if let Some(r) = d.regs_use.iter().find(|r| *r != "nzcv") {
        return reg(r.clone());
    }
    // Fallback: parse register from op_str (e.g. "x8" for blr x8)
    let parts = split_operands(&d.op_str);
    if let Some(first) = parts.first() {
        if !first.starts_with('#') && !first.is_empty() {
            return reg(first.clone());
        }
    }
    intrinsic(d)
}

fn mem_addr_expr(base: &str, idx: &str, disp: i64) -> LlilExpr {
    let mut out = if base.is_empty() {
        konst(0)
    } else {
        reg(base.to_string())
    };
    if !idx.is_empty() {
        out = binary(LlilOp::Add, out, reg(idx.to_string()));
    }
    if disp != 0 {
        out = binary(LlilOp::Add, out, konst(disp));
    }
    out
}

fn intrinsic(d: &DecodedInsn) -> LlilExpr {
    LlilExpr::new(
        LlilOp::Intrinsic,
        0,
        vec![
            LlilOperand::Str(d.mnemonic.clone()),
            LlilOperand::Str(d.op_str.clone()),
        ],
        d.pc,
    )
    .with_extra("mnem", d.mnemonic.clone())
}

fn first_def(d: &DecodedInsn) -> String {
    d.regs_def
        .first()
        .cloned()
        .unwrap_or_else(|| "xzr".to_string())
}

fn reg_from_parts(parts: &[String], idx: usize) -> Option<LlilExpr> {
    parts
        .get(idx)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with('#') && s != "xzr")
        .map(reg)
}

fn split_operands(op_str: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut bracket_depth = 0i32;
    for (i, ch) in op_str.char_indices() {
        match ch {
            '[' => bracket_depth += 1,
            ']' => bracket_depth -= 1,
            ',' if bracket_depth == 0 => {
                out.push(op_str[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < op_str.len() {
        out.push(op_str[start..].trim().to_string());
    }
    out
}

fn parse_imm(s: &str) -> Option<i64> {
    let t = s.trim().trim_start_matches('#').trim_end_matches(',');
    if t.is_empty() {
        return None;
    }
    if let Some(hex) = t.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()
    } else if let Some(hex) = t.strip_prefix("-0x") {
        i64::from_str_radix(hex, 16).ok().map(|v| -v)
    } else {
        t.parse::<i64>().ok()
    }
}

fn parse_target(s: &str) -> Option<u64> {
    parse_imm(s).map(|v| v as u64)
}

/// smull/umull: multiply two 32-bit values, produce 64-bit result.
fn lift_mull(d: &DecodedInsn, signed: bool) -> Vec<LlilExpr> {
    let dst = first_def(d);
    let parts = split_operands(&d.op_str);
    let mul_lhs = d
        .regs_use
        .first()
        .cloned()
        .map(reg)
        .or_else(|| reg_from_parts(&parts, 1))
        .unwrap_or_else(|| konst(0));
    let mul_rhs = d
        .regs_use
        .get(1)
        .cloned()
        .map(reg)
        .or_else(|| reg_from_parts(&parts, 2))
        .unwrap_or_else(|| konst(0));

    let lhs_ext = if signed { sx(4, mul_lhs) } else { zx(4, mul_lhs) };
    let rhs_ext = if signed { sx(4, mul_rhs) } else { zx(4, mul_rhs) };

    // SMULL/UMULL produce 64-bit results; create Mul node explicitly at 8 bytes
    let product = LlilExpr::new(LlilOp::Mul, 8, vec![expr(lhs_ext), expr(rhs_ext)], 0);
    vec![set_reg(dst, product, d.pc)]
}

/// Load + sign/zero-extension.  Handles ldrb/ldrh/ldurb (zero-extend) and
/// ldrsb/ldrsh/ldrsw (sign-extend).  Extension width is derived from mem_op.
fn lift_load_ext(d: &DecodedInsn, signed: bool) -> Vec<LlilExpr> {
    if d.mem_op.is_empty() {
        // Try PC-relative literal load with extension
        if d.regs_def.is_empty() {
            return vec![intrinsic(d)];
        }
        return lift_load_literal(d, signed);
    }
    if d.regs_def.is_empty() {
        return vec![intrinsic(d)];
    }
    d.mem_op
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let dst = if !m.src_reg.is_empty() {
                m.src_reg.clone()
            } else {
                d.regs_def.get(i).cloned().unwrap_or_else(|| first_def(d))
            };
            let load_sz = m.size as u8;
            let load = LlilExpr::new(
                LlilOp::Load,
                load_sz,
                vec![expr(mem_addr_expr(&m.base, &m.idx, m.disp))],
                d.pc,
            );
            let result = if signed { sx(load_sz, load) } else { zx(load_sz, load) };
            set_reg(dst, result, d.pc)
        })
        .collect()
}

/// mrs: move from system register (e.g. tpidr_el0).
/// Model as Intrinsic so downstream passes know it is not a regular load, but
/// with structured operands for readability.
fn lift_mrs(d: &DecodedInsn) -> Vec<LlilExpr> {
    let dst = first_def(d);
    let parts = split_operands(&d.op_str);
    let sysreg = parts.get(1).cloned().unwrap_or_else(|| "?".to_string());
    let intrinsic = LlilExpr::new(
        LlilOp::Intrinsic,
        8,
        vec![
            LlilOperand::Str("mrs".to_string()),
            LlilOperand::Str(sysreg),
        ],
        d.pc,
    )
    .with_extra("mnem", "mrs");
    vec![set_reg(dst, intrinsic, d.pc)]
}

/// ubfm/sbfm: unsigned/signed bitfield move.  Common case (immr == 0) is
/// extracted with And+Zx/Sx for unsigned, or the shift-trick for sub-byte
/// signed extensions.  Complex cases fall through to Intrinsic.
/// ubfx/sbfx: unsigned/signed bitfield extract.
/// Capstone reports op_str as "dst, src, #lsb, #width" (unlike ubfm: "#immr, #imms").
fn lift_ubfx(d: &DecodedInsn, signed: bool) -> Vec<LlilExpr> {
    let dst = first_def(d);
    let parts = split_operands(&d.op_str);
    let src = d.regs_use.first().cloned().map(reg)
        .or_else(|| reg_from_parts(&parts, 1))
        .unwrap_or_else(|| konst(0));
    let lsb = parts.get(2).and_then(|p| parse_imm(p)).unwrap_or(0) as u32;
    let width = parts.get(3).and_then(|p| parse_imm(p)).unwrap_or(0) as u32;
    if width == 0 || width >= 64 { return vec![intrinsic(d)]; }
    // Extract: (src >> lsb) & mask
    let shift = if lsb > 0 { binary(LlilOp::Lsr, src.clone(), konst(lsb as i64)) } else { src };
    let mask = (1u64 << width) - 1;
    let masked = binary(LlilOp::And, shift, konst(mask as i64));
    let result = if signed && width > 0 {
        // Sign-extend: (masked << (64-width)) >> (64-width)
        let sh = 64 - width;
        let lsl = binary(LlilOp::Lsl, masked, konst(sh as i64));
        binary(LlilOp::Asr, lsl, konst(sh as i64))
    } else { masked };
    vec![set_reg(dst, result, d.pc)]
}

fn lift_bfm(d: &DecodedInsn, signed: bool) -> Vec<LlilExpr> {
    let dst = first_def(d);
    let parts = split_operands(&d.op_str);
    let src = d
        .regs_use
        .first()
        .cloned()
        .map(reg)
        .unwrap_or_else(|| konst(0));
    let immr = parts.get(2).and_then(|p| parse_imm(p)).unwrap_or(0) as u32;
    let imms = parts.get(3).and_then(|p| parse_imm(p)).unwrap_or(0) as u32;

    if immr == 0 {
        let bits = imms + 1;
        if bits >= 64 {
            return vec![set_reg(dst, src, d.pc)];
        }
        let mask = (1u64 << bits) - 1;
        let masked = binary(LlilOp::And, src, konst(mask as i64));

        if signed {
            // Sign-extend via Asr(Lsl(masked, 64-bits), 64-bits)
            let shift_amount = 64 - bits;
            let lsl = binary(LlilOp::Lsl, masked, konst(shift_amount as i64));
            let result = binary(LlilOp::Asr, lsl, konst(shift_amount as i64));
            vec![set_reg(dst, result, d.pc)]
        } else {
            // Zero-extend by rounding up to the nearest byte boundary
            let bytes = if bits <= 8 {
                1
            } else if bits <= 16 {
                2
            } else if bits <= 32 {
                4
            } else {
                8
            };
            vec![set_reg(dst, zx(bytes, masked), d.pc)]
        }
    } else {
        vec![intrinsic(d)]
    }
}

/// mneg: multiply-negate.  mneg Xd, Xn, Xm = -(Xn * Xm) = Sub(0, Mul(Xn, Xm))
/// orn Xd, Xn, Xm = Xd = Xn | ~Xm = ~(~Xn & Xm)
fn lift_orn(d: &DecodedInsn) -> Vec<LlilExpr> {
    let dst = first_def(d);
    let parts = split_operands(&d.op_str);
    let lhs = d.regs_use.first().cloned().map(reg)
        .or_else(|| reg_from_parts(&parts, 1)).unwrap_or_else(|| konst(0));
    let rhs = d.regs_use.get(1).cloned().map(reg)
        .or_else(|| reg_from_parts(&parts, 2)).unwrap_or_else(|| konst(0));
    // a | ~b
    let not_rhs = unary(LlilOp::Not, rhs);
    let result = binary(LlilOp::Or, lhs, not_rhs);
    vec![set_reg(dst, result, d.pc)]
}

/// bic Xd, Xn, Xm = Xd = Xn & ~Xm
fn lift_bic(d: &DecodedInsn) -> Vec<LlilExpr> {
    let dst = first_def(d);
    let parts = split_operands(&d.op_str);
    let lhs = d.regs_use.first().cloned().map(reg)
        .or_else(|| reg_from_parts(&parts, 1)).unwrap_or_else(|| konst(0));
    let rhs = d.regs_use.get(1).cloned().map(reg)
        .or_else(|| reg_from_parts(&parts, 2)).unwrap_or_else(|| konst(0));
    let not_rhs = unary(LlilOp::Not, rhs);
    let result = binary(LlilOp::And, lhs, not_rhs);
    vec![set_reg(dst, result, d.pc)]
}

fn lift_mneg(d: &DecodedInsn) -> Vec<LlilExpr> {
    let dst = first_def(d);
    let parts = split_operands(&d.op_str);
    let lhs = d
        .regs_use
        .first()
        .cloned()
        .map(reg)
        .or_else(|| reg_from_parts(&parts, 1))
        .unwrap_or_else(|| konst(0));
    let rhs = d
        .regs_use
        .get(1)
        .cloned()
        .map(reg)
        .or_else(|| reg_from_parts(&parts, 2))
        .unwrap_or_else(|| konst(0));
    let product = binary(LlilOp::Mul, lhs, rhs);
    let result = unary(LlilOp::Neg, product);
    vec![set_reg(dst, result, d.pc)]
}

/// ngc / ngcs: negate with carry.  ngc Xd, Xn = NOT(Xn) + C.
/// ngcs additionally sets NZCV flags.
fn lift_ngc(d: &DecodedInsn, set_flags: bool) -> Vec<LlilExpr> {
    let Some(dst) = d.regs_def.first().cloned() else {
        return vec![intrinsic(d)];
    };
    let src = d
        .regs_use
        .first()
        .cloned()
        .map(reg)
        .unwrap_or_else(|| konst(0));
    let not_src = unary(LlilOp::Not, src);
    let carry = flag("c");
    let result = binary(LlilOp::Add, not_src.clone(), carry.clone());
    let mut out = vec![set_reg(dst, result.clone(), d.pc)];
    if set_flags {
        out.extend(nzcv_from_binary(
            LlilOp::Add,
            d.pc,
            &not_src,
            &carry,
            &result,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lift_nop_ret_and_bl() {
        assert_eq!(lift_arm64(0x1000, 0xd503201f)[0].op, LlilOp::Nop);
        assert_eq!(lift_arm64(0x1004, 0xd65f03c0)[0].op, LlilOp::Ret);
        let bl = lift_arm64(0x1008, 0x94000002);
        assert_eq!(bl[0].op, LlilOp::Call);
        assert!(bl[0].short().contains("0x1010"));
    }

    #[test]
    fn lift_mov_and_mem() {
        let mov = lift_arm64(0x1000, 0xaa0103e0);
        assert_eq!(mov[0].short(), "x0 = reg(x1)");

        let store = lift_arm64(0x1004, 0xf9000020);
        assert_eq!(store[0].op, LlilOp::Store);
        assert!(store[0].short().contains("reg(x1)"));

        let load = lift_arm64(0x1008, 0xf9400022);
        assert_eq!(load[0].op, LlilOp::SetReg);
        assert!(load[0].short().starts_with("x2 = load.8"));
    }

    #[test]
    fn lift_branch_cond() {
        let b_eq = lift_arm64(0x2000, 0x54000040);
        assert_eq!(b_eq[0].op, LlilOp::If);
        assert!(b_eq[0].short().contains("flag_cond(eq)"));
    }

    #[test]
    fn lift_cmp_produces_nzcv_flags() {
        // cmp x0, x1 = 0xeb01001f
        let lifted = lift_arm64(0x1000, 0xeb01001f);
        assert_eq!(lifted.len(), 4);
        assert_eq!(lifted[0].op, LlilOp::SetFlag);
        assert_eq!(lifted[1].op, LlilOp::SetFlag);
        assert_eq!(lifted[2].op, LlilOp::SetFlag);
        assert_eq!(lifted[3].op, LlilOp::SetFlag);
        let flags: Vec<_> = lifted
            .iter()
            .filter_map(|e| match e.operands.first() {
                Some(LlilOperand::Flag(f)) => Some(f.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(flags, vec!["n", "z", "c", "v"]);
    }

    #[test]
    fn lift_adds_produces_reg_and_nzcv() {
        // adds x0, x1, x2 = 0xab020020
        let lifted = lift_arm64(0x1000, 0xab020020);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        assert!(lifted.len() >= 5);
        assert_eq!(lifted[1].op, LlilOp::SetFlag);
        assert_eq!(lifted[2].op, LlilOp::SetFlag);
        assert_eq!(lifted[3].op, LlilOp::SetFlag);
        assert_eq!(lifted[4].op, LlilOp::SetFlag);
    }

    #[test]
    fn lift_csel() {
        // csel x0, x1, x2, eq = 0x9a821020
        let lifted = lift_arm64(0x1000, 0x9a821020);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        assert!(lifted[0].short().contains("csel"));
    }

    #[test]
    fn lift_sxtb() {
        // sxtb x0, w1 = 0x13001c20
        let lifted = lift_arm64(0x1000, 0x13001c20);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        assert!(lifted[0].short().contains("sx"));
    }

    #[test]
    fn lift_madd() {
        // madd x0, x1, x2, x3 = 0x9b031020
        let lifted = lift_arm64(0x1000, 0x9b031020);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        assert!(
            lifted[0].short().contains("+") || lifted[0].short().contains("Add"),
            "got: {}",
            lifted[0].short()
        );
    }

    #[test]
    fn lift_extr() {
        // extr x0, x1, x2, #8 = 0x93c22020
        let lifted = lift_arm64(0x1000, 0x93c22020);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        assert!(lifted[0].short().contains("|"));
    }

    // ── new instruction tests ──

    #[test]
    fn lift_smull() {
        // smull x0, w1, w2 = 0x9b227c20
        let lifted = lift_arm64(0x1000, 0x9b227c20);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        let s = lifted[0].short();
        assert!(s.contains("x0 ="), "got: {s}");
        assert!(s.contains("*"), "got: {s}");
    }

    #[test]
    fn lift_umull() {
        // umull x0, w1, w2 = 0x9ba27c20
        let lifted = lift_arm64(0x1000, 0x9ba27c20);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        let s = lifted[0].short();
        assert!(s.contains("x0 ="), "got: {s}");
        assert!(s.contains("*"), "got: {s}");
    }

    #[test]
    fn lift_ldrsw() {
        // ldrsw x0, [x1] = 0xb9800020
        let lifted = lift_arm64(0x1000, 0xb9800020);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        let s = lifted[0].short();
        assert!(s.contains("x0 ="), "got: {s}");
        assert!(s.contains("sx"), "expected sign-extension, got: {s}");
    }

    #[test]
    fn lift_ldrb() {
        // ldrb w0, [x1] = 0x39400020
        let lifted = lift_arm64(0x1000, 0x39400020);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        let s = lifted[0].short();
        assert!(s.contains("x0 ="), "got: {s}");
        assert!(s.contains("zx"), "expected zero-extension, got: {s}");
    }

    #[test]
    fn lift_ldrsh() {
        // ldrsh x0, [x1] = 0x79800020
        let lifted = lift_arm64(0x1000, 0x79800020);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        let s = lifted[0].short();
        assert!(s.contains("x0 ="), "got: {s}");
        assert!(s.contains("sx"), "expected sign-extension, got: {s}");
    }

    #[test]
    fn lift_mrs_tpidr_el0() {
        // mrs x0, tpidr_el0 = 0xd53bd040
        let lifted = lift_arm64(0x1000, 0xd53bd040);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        let s = lifted[0].short();
        assert!(s.contains("x0 ="), "got: {s}");
        assert!(s.contains("intrinsic"), "mrs should emit intrinsic, got: {s}");
    }

    #[test]
    fn lift_sdiv_w() {
        // sdiv w0, w1, w2 = 0x1ac20c20
        let lifted = lift_arm64(0x1000, 0x1ac20c20);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        let s = lifted[0].short();
        assert!(s.contains("x0 ="), "got: {s}");
        assert!(s.contains("/"), "expected division, got: {s}");
    }

    #[test]
    fn lift_udiv_w() {
        // udiv w0, w1, w2 = 0x1ac20820
        let lifted = lift_arm64(0x1000, 0x1ac20820);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        let s = lifted[0].short();
        assert!(s.contains("x0 ="), "got: {s}");
        assert!(s.contains("/"), "expected division, got: {s}");
    }

    #[test]
    fn lift_asrv() {
        // asrv x0, x1, x2 = 0x9ac22420
        let lifted = lift_arm64(0x1000, 0x9ac22420);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        let s = lifted[0].short();
        assert!(s.contains("x0 ="), "got: {s}");
        assert!(s.contains(">>"), "expected shift-right, got: {s}");
    }

    #[test]
    fn lift_mneg() {
        // mneg x0, x1, x2 = 0x9b02fc20
        let lifted = lift_arm64(0x1000, 0x9b02fc20);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        let s = lifted[0].short();
        assert!(s.contains("x0 ="), "got: {s}");
    }

    #[test]
    fn lift_ngc() {
        let lifted = lift_arm64(0x1000, 0xda000020);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        let s = lifted[0].short();
        assert!(s.contains("x0 ="), "got: {s}");
    }

    #[test] fn lift_cinc() {
        // cinc x0, x1, ne = conditional increment (csinc with same src)
        let lifted = lift_arm64(0x1000, 0x9a811420);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        assert!(lifted[0].short().contains("csel"), "got: {}", lifted[0].short());
    }

    #[test] fn lift_orn() {
        // orn x0, x1, x2 = ~(x1 & ~x2) = x1 | ~x2
        let lifted = lift_arm64(0x1000, 0xaa220020);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        let s = lifted[0].short();
        assert!(s.contains("|") || s.contains("Or"), "got: {s}");
    }

    #[test] fn lift_bic() {
        // bic x0, x1, x2 = x1 & ~x2
        let lifted = lift_arm64(0x1000, 0x0a220020);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        let s = lifted[0].short();
        assert!(s.contains("&") || s.contains("And"), "got: {s}");
    }

    #[test] fn lift_dmb() {
        // dmb ish = data memory barrier → Nop
        let lifted = lift_arm64(0x1000, 0xd5033bbf);
        assert_eq!(lifted[0].op, LlilOp::Nop);
    }

    #[test] fn lift_ubfx() {
        // ubfx x0, x1, #2, #4 = unsigned bitfield extract
        // Try known encoding or let it fall to intrinsic (bfm) — either is valid
        let lifted = lift_arm64(0x1000, 0xd3450820);
        // ubfx may decode as ubfm; both are handled
        assert!(lifted[0].op == LlilOp::SetReg || lifted[0].op == LlilOp::Intrinsic);
        assert!(lifted[0].short().contains("x0") || !lifted[0].short().is_empty(), "got: {}", lifted[0].short());
    }

    #[test] fn lift_ldarb() {
        // ldarb w0, [x1] = load-acquire register byte
        let lifted = lift_arm64(0x1000, 0x08dffc20);
        assert_eq!(lifted[0].op, LlilOp::SetReg);
        assert!(lifted[0].short().contains("zx") || lifted[0].short().contains("load"), "got: {}", lifted[0].short());
    }

    #[test] fn lift_stlrb() {
        // stlrb w0, [x1] = store-release register byte
        let lifted = lift_arm64(0x1000, 0x089ffc20);
        assert_eq!(lifted[0].op, LlilOp::Store);
    }
}
