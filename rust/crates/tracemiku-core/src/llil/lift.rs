//! ARM64 -> LLIL lifter.
//!
//! M5: lifted coverage expanded (csel, sx/zx, bitfield, madd/msub, extr, adr/adrp)
//! and NZCV flag model (N, Z, C, V tracked independently, ref BN LLIL).

use std::collections::BTreeMap;

use crate::disasm::{decode, DecodedInsn};
use crate::llil::expr::{
    binary, const_ptr, csel as csel_expr, expr, flag_cond, konst, reg, set_flag, set_reg, sx,
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
        "neg" => lift_unary_reg(d, LlilOp::Neg, false),
        "negs" => lift_unary_reg(d, LlilOp::Neg, true),
        "mvn" => lift_unary_reg(d, LlilOp::Not, false),
        "cmp" => lift_cmp(d, LlilOp::Sub),
        "cmn" => lift_cmp(d, LlilOp::Add),
        "tst" => lift_cmp(d, LlilOp::And),
        "csel" | "csinc" | "csinv" | "csneg" => lift_csel(d),
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
        "ldr" | "ldrb" | "ldrh" | "ldur" | "ldp" | "ldnp" => lift_load(d),
        "str" | "strb" | "strh" | "stur" | "stp" | "stnp" => lift_store(d),
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
        .unwrap_or_else(|| {
            d.regs_use
                .first()
                .map(|r| reg(r.clone()))
                .unwrap_or_else(|| intrinsic(d))
        });
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
        .find(|r| **r == true_reg || true_reg.contains(r.as_str()))
        .cloned()
        .map(reg)
        .or_else(|| reg_from_parts(&parts, 1))
        .unwrap_or_else(|| konst(0));

    let false_val = d
        .regs_use
        .iter()
        .skip(1)
        .find(|r| **r == false_reg || false_reg.contains(r.as_str()))
        .cloned()
        .map(reg)
        .or_else(|| reg_from_parts(&parts, 2))
        .unwrap_or_else(|| konst(0));

    let false_val = match mnem {
        "csinc" => binary(LlilOp::Add, false_val, konst(1)),
        "csinv" => unary(LlilOp::Not, false_val),
        "csneg" => unary(LlilOp::Neg, false_val),
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

fn lift_load(d: &DecodedInsn) -> Vec<LlilExpr> {
    if d.mem_op.is_empty() || d.regs_def.is_empty() {
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
    let lhs = d
        .regs_use
        .first()
        .cloned()
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

fn is_b_cond(d: &DecodedInsn) -> bool {
    d.mnemonic.starts_with("b.") && d.mnemonic.len() > 2
}

fn target_expr(d: &DecodedInsn) -> LlilExpr {
    if let Some(target) = parse_target(&d.op_str) {
        return const_ptr(target);
    }
    d.regs_use
        .first()
        .cloned()
        .map(reg)
        .unwrap_or_else(|| intrinsic(d))
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
}
