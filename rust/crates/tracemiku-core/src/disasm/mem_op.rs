//! MemOp = (base, idx, disp, size, is_write, src_reg).
//!
//! Direct port of `viewer/disasm.py:100-134` + `viewer/trace.py:131-138`.
//! `src_reg` holds the source/dest reg for stp/ldp pair-split entries; empty
//! for non-pair insns (consumers fall back to `regs_use[0]` / `regs_def[0]`).

use capstone::arch::arm64::Arm64OperandType;
use capstone::arch::DetailsArchInsn;
use capstone::Capstone;
use serde::Serialize;

use crate::disasm::regs::normalize_disasm_reg;
use crate::trace::Record;

/// One memory operand of an ARM64 instruction. The byte range touched is
/// `[addr_of(rec, &op), addr_of(rec, &op) + op.size)` where `addr_of` resolves
/// `base + idx + disp` against a trace record.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct MemOp {
    /// Canonical base reg name (e.g. `"x1"`, `"sp"`, `"fp"`). May be empty
    /// when capstone reports REG_INVALID (rare PC-relative form).
    pub base: String,
    /// Canonical index reg name; empty when no scaled index is present.
    pub idx: String,
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
    "stlr", "stlrb", "stlrh", "stlxr", "stlxrb", "stlxrh",
];

fn is_store(mnem_base: &str) -> bool {
    STORE_BASES.contains(&mnem_base)
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
            out.push(MemOp {
                base: base_norm,
                idx: idx_norm,
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
    if matches!(mnem_base, "stp" | "ldp" | "stnp" | "ldnp")
        && out.len() == 1
        && reg_operand_names.len() >= 2
    {
        let pair_sz: u32 = if reg_operand_names[0].starts_with('w') {
            4
        } else {
            8
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
    out
}

/// Compute effective address from a record and a MemOp, mirroring
/// `viewer/trace.py:addr_of` (base + idx + disp, modulo 2^64). Unknown
/// register names resolve to 0 — matching Python's `if reg in ALL_REGS else 0`.
pub fn addr_of(rec: &Record, op: &MemOp) -> u64 {
    let bv = rec.reg_by_name(&op.base).unwrap_or(0);
    let iv = if op.idx.is_empty() {
        0
    } else {
        rec.reg_by_name(&op.idx).unwrap_or(0)
    };
    bv.wrapping_add(iv).wrapping_add(op.disp as u64)
}
