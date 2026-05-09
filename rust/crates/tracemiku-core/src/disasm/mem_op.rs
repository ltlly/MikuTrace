//! MemOp = (base, idx, shift, disp, size, is_write, src_reg).
//!
//! Direct port of `viewer/disasm.py:100-134` + `viewer/trace.py:131-138`.
//! `shift` holds scaled register-index addressing such as `[x25, x15, lsl #3]`.
//! `src_reg` holds the source/dest reg for stp/ldp pair-split entries; empty
//! for non-pair insns (consumers fall back to `regs_use[0]` / `regs_def[0]`).

use capstone::arch::arm64::{Arm64OperandType, Arm64Shift};
use capstone::arch::DetailsArchInsn;
use capstone::Capstone;
use serde::Serialize;

use crate::disasm::regs::normalize_disasm_reg;
use crate::trace::Record;

/// One memory operand of an ARM64 instruction. The byte range touched is
/// `[addr_of(rec, &op), addr_of(rec, &op) + op.size)` where `addr_of` resolves
/// `base + (idx << shift) + disp` against a trace record.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct MemOp {
    /// Canonical base reg name (e.g. `"x1"`, `"sp"`, `"fp"`). May be empty
    /// when capstone reports REG_INVALID (rare PC-relative form).
    pub base: String,
    /// Canonical index reg name; empty when no scaled index is present.
    pub idx: String,
    /// Left shift applied to `idx` in register-index addressing.
    pub shift: u32,
    /// Signed displacement in bytes (negative for pre/post-decrement forms).
    pub disp: i64,
    /// Access size in bytes (1/2/4/8). Derived from mnemonic suffix and
    /// the size of the source/dest reg operand.
    pub size: u32,
    /// `true` for stores; `false` for loads.
    pub is_write: bool,
    /// Per-half source/dest reg for stp/ldp pair-split entries; empty for
    /// non-pair insns.
    pub src_reg: String,
}

const STORE_BASES: &[&str] = &[
    "str", "strb", "strh", "stur", "sturb", "sturh", "stp", "stnp", "stxr", "stxrb", "stxrh",
    "stxp", "stlr", "stlrb", "stlrh", "stlxr", "stlxrb", "stlxrh", "stlxp",
];

fn is_store(mnem_base: &str) -> bool {
    STORE_BASES.contains(&mnem_base)
}

fn is_exclusive_store_style(mnem: &str) -> bool {
    let base = mnem.split('.').next().unwrap_or(mnem);
    matches!(
        base,
        "stxr" | "stxrb" | "stxrh" | "stxp" | "stlxr" | "stlxrb" | "stlxrh" | "stlxp"
    )
}

/// Determine size from the mnemonic + operand register class. Mirrors the
/// Python heuristic in `viewer/disasm.py:108-112`.
fn op_size(mnem_base: &str, ins: &capstone::Insn, cs: &Capstone) -> u32 {
    if mnem_base.ends_with('b') {
        return 1;
    }
    if mnem_base.ends_with('h') {
        return 2;
    }
    let head = &mnem_base[..mnem_base.len().min(4)];
    if head.contains('w') {
        return 4;
    }
    // Look at register operands to detect 32-bit form (any operand starts with 'w').
    if let Ok(detail) = cs.insn_detail(ins) {
        let arch = detail.arch_detail();
        if let Some(arm64) = arch.arm64() {
            for op in arm64.operands() {
                if let Arm64OperandType::Reg(reg) = op.op_type {
                    if let Some(name) = cs.reg_name(reg) {
                        if name.starts_with('w') {
                            return 4;
                        }
                    }
                }
            }
        }
    }
    8
}

fn reg_access_size(name: &str) -> u32 {
    if name.starts_with('w') {
        4
    } else {
        8
    }
}

/// Extract the list of MemOps from one capstone-decoded instruction.
/// Caller passes the already-normalized mnemonic (e.g. `"stp"` not `"stp.4s"`).
pub fn extract(cs: &Capstone, ins: &capstone::Insn, mnem: &str) -> Vec<MemOp> {
    let mnem_base = mnem.split('.').next().unwrap_or(mnem);
    let is_w = is_store(mnem_base);
    let sz = op_size(mnem_base, ins, cs);
    let mut out: Vec<MemOp> = Vec::new();
    let detail = match cs.insn_detail(ins) {
        Ok(d) => d,
        Err(_) => return out,
    };
    let arch = detail.arch_detail();
    let arm64 = match arch.arm64() {
        Some(a) => a,
        None => return out,
    };
    // Collect Reg operand names ahead of time for stp/ldp pair-split. Keep the
    // raw capstone names (we need the `w`-prefix to detect 32-bit pair size).
    let mut reg_operand_names: Vec<String> = Vec::new();
    for op in arm64.operands() {
        if let Arm64OperandType::Reg(reg) = op.op_type {
            if let Some(name) = cs.reg_name(reg) {
                reg_operand_names.push(name);
            }
        }
    }
    for op in arm64.operands() {
        if let Arm64OperandType::Mem(m) = op.op_type {
            let base_id = m.base();
            let base = if base_id.0 != 0 {
                cs.reg_name(base_id).unwrap_or_default()
            } else {
                String::new()
            };
            let idx_id = m.index();
            let idx = if idx_id.0 != 0 {
                cs.reg_name(idx_id).unwrap_or_default()
            } else {
                String::new()
            };
            let base_norm = if base.is_empty() {
                String::new()
            } else {
                normalize_disasm_reg(&base)
            };
            let idx_norm = if idx.is_empty() {
                String::new()
            } else {
                normalize_disasm_reg(&idx)
            };
            let shift = match op.shift {
                Arm64Shift::Lsl(bits) => bits,
                _ => 0,
            };
            out.push(MemOp {
                base: base_norm,
                idx: idx_norm,
                shift,
                disp: m.disp() as i64,
                size: sz,
                is_write: is_w,
                src_reg: String::new(),
            });
        }
    }
    // STP/LDP pair-split: capstone reports 1 mem_op but the actual access is
    // 2 contiguous halves (8+8 or 4+4 bytes). Split if mnem is in the pair set
    // AND we have ≥2 reg operands + exactly 1 mem_op recorded.
    if matches!(
        mnem_base,
        "stp" | "ldp" | "stnp" | "ldnp" | "ldpsw" | "ldxp" | "ldaxp"
    ) && out.len() == 1
        && reg_operand_names.len() >= 2
    {
        let pair_sz: u32 = if mnem_base == "ldpsw" {
            4
        } else {
            reg_access_size(&reg_operand_names[0])
        };
        let r0 = normalize_disasm_reg(&reg_operand_names[0]);
        let r1 = normalize_disasm_reg(&reg_operand_names[1]);
        let base_op = out.remove(0);
        out.push(MemOp {
            size: pair_sz,
            src_reg: r0,
            ..base_op.clone()
        });
        out.push(MemOp {
            disp: base_op.disp + pair_sz as i64,
            size: pair_sz,
            src_reg: r1,
            ..base_op
        });
    }
    // Exclusive stores have a status destination as operand 0 and one or two
    // real store sources after it. Fill `src_reg` so MemShadow does not fall
    // back to the status register.
    if matches!(
        mnem_base,
        "stxr" | "stxrb" | "stxrh" | "stlxr" | "stlxrb" | "stlxrh"
    ) && out.len() == 1
        && reg_operand_names.len() >= 2
    {
        out[0].src_reg = normalize_disasm_reg(&reg_operand_names[1]);
        if !matches!(mnem_base, "stxrb" | "stxrh" | "stlxrb" | "stlxrh") {
            out[0].size = reg_access_size(&reg_operand_names[1]);
        }
    }
    if matches!(mnem_base, "stxp" | "stlxp") && out.len() == 1 && reg_operand_names.len() >= 3 {
        let pair_sz: u32 = reg_access_size(&reg_operand_names[1]);
        let r0 = normalize_disasm_reg(&reg_operand_names[1]);
        let r1 = normalize_disasm_reg(&reg_operand_names[2]);
        let base_op = out.remove(0);
        out.push(MemOp {
            size: pair_sz,
            src_reg: r0,
            ..base_op.clone()
        });
        out.push(MemOp {
            disp: base_op.disp + pair_sz as i64,
            size: pair_sz,
            src_reg: r1,
            ..base_op
        });
    }
    // Normal stores also have a data source in the first register operand.
    // Fill it so taint can distinguish address-only uses from stored data
    // even for forms like `str x0, [x0]` where source and base are identical.
    if is_w
        && !is_exclusive_store_style(mnem)
        && out.len() == 1
        && out[0].src_reg.is_empty()
        && !reg_operand_names.is_empty()
    {
        out[0].src_reg = normalize_disasm_reg(&reg_operand_names[0]);
    }
    out
}

/// Compute effective address from a record and a MemOp, mirroring
/// `viewer/trace.py:addr_of` (base + (idx << shift) + disp, modulo 2^64). Unknown
/// register names resolve to 0 — matching Python's `if reg in ALL_REGS else 0`.
pub fn addr_of(rec: &Record, op: &MemOp) -> u64 {
    let bv = rec.reg_by_name(&op.base).unwrap_or(0);
    let iv = if op.idx.is_empty() {
        0
    } else {
        rec.reg_by_name(&op.idx).unwrap_or(0)
    };
    let iv = iv.checked_shl(op.shift).unwrap_or(0);
    bv.wrapping_add(iv).wrapping_add(op.disp as u64)
}
