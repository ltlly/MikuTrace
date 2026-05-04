//! ARM64 -> LLIL lifter MVP.

use std::collections::BTreeMap;

use crate::disasm::{decode, DecodedInsn};
use crate::llil::expr::{
    binary, const_ptr, expr, flag_cond, konst, reg, set_flag, set_reg, unary, LlilExpr, LlilOp,
    LlilOperand,
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
        "add" | "adds" => lift_binary_reg(d, LlilOp::Add),
        "sub" | "subs" => lift_binary_reg(d, LlilOp::Sub),
        "mul" => lift_binary_reg(d, LlilOp::Mul),
        "and" | "ands" => lift_binary_reg(d, LlilOp::And),
        "orr" => lift_binary_reg(d, LlilOp::Or),
        "eor" => lift_binary_reg(d, LlilOp::Xor),
        "lsl" | "lslv" => lift_binary_reg(d, LlilOp::Lsl),
        "lsr" | "lsrv" => lift_binary_reg(d, LlilOp::Lsr),
        "asr" | "asrv" => lift_binary_reg(d, LlilOp::Asr),
        "ror" | "rorv" => lift_binary_reg(d, LlilOp::Ror),
        "sdiv" => lift_binary_reg(d, LlilOp::DivS),
        "udiv" => lift_binary_reg(d, LlilOp::DivU),
        "neg" | "negs" => lift_unary_reg(d, LlilOp::Neg),
        "mvn" => lift_unary_reg(d, LlilOp::Not),
        "cmp" => lift_cmp(d, LlilOp::Sub),
        "cmn" => lift_cmp(d, LlilOp::Add),
        "tst" => lift_cmp(d, LlilOp::And),
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

fn lift_binary_reg(d: &DecodedInsn, op: LlilOp) -> Vec<LlilExpr> {
    let Some(dst) = d.regs_def.first().cloned() else {
        return vec![intrinsic(d)];
    };
    let parts = split_operands(&d.op_str);
    let lhs = d.regs_use.first().cloned().map(reg).unwrap_or_else(|| {
        parts
            .get(1)
            .map(|p| reg(p.clone()))
            .unwrap_or_else(|| reg("xzr"))
    });
    let rhs = parts
        .get(2)
        .and_then(|p| parse_imm(p).map(konst))
        .or_else(|| d.regs_use.get(1).cloned().map(reg))
        .unwrap_or_else(|| konst(0));
    vec![set_reg(dst, binary(op, lhs, rhs), d.pc)]
}

fn lift_unary_reg(d: &DecodedInsn, op: LlilOp) -> Vec<LlilExpr> {
    let Some(dst) = d.regs_def.first().cloned() else {
        return vec![intrinsic(d)];
    };
    let value = d
        .regs_use
        .first()
        .cloned()
        .map(reg)
        .unwrap_or_else(|| konst(0));
    vec![set_reg(dst, unary(op, value), d.pc)]
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
    vec![set_flag("cmp_result", binary(op, lhs, rhs), d.pc)]
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
}
