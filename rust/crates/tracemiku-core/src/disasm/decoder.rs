//! capstone-rs wrapper. Provides decode() returning DecodedInsn with mnemonic,
//! op_str, branch/call/ret classification, and (M2-γ) register def/use lists.

use std::cell::RefCell;

use capstone::arch::arm64;
use capstone::arch::arm64::Arm64OperandType;
use capstone::arch::{BuildsCapstone, DetailsArchInsn};
use capstone::Capstone;
use serde::Serialize;

use crate::disasm::classify::{is_branch_mnem, is_call_mnem, is_ret_mnem};
use crate::disasm::mem_op::{self, MemOp};
use crate::disasm::regs::normalize_disasm_reg;

#[derive(Debug, Clone, Serialize)]
pub struct DecodedInsn {
    pub pc: u64,
    pub inst: u32,
    pub mnemonic: String,
    pub op_str: String,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_ret: bool,
    /// Registers written by this instruction, normalized to canonical names.
    pub regs_def: Vec<String>,
    /// Registers read by this instruction, normalized to canonical names.
    pub regs_use: Vec<String>,
    /// Memory operands. STP/LDP/STNP/LDNP are split into 2 contiguous halves
    /// with per-half `src_reg`; other insns leave `src_reg` empty.
    pub mem_op: Vec<MemOp>,
}

impl DecodedInsn {
    pub fn bad(pc: u64, inst: u32) -> Self {
        Self {
            pc,
            inst,
            mnemonic: "<bad>".to_string(),
            op_str: format!("{inst:08x}"),
            is_branch: false,
            is_call: false,
            is_ret: false,
            regs_def: Vec::new(),
            regs_use: Vec::new(),
            mem_op: Vec::new(),
        }
    }
}

thread_local! {
    static CS: RefCell<Capstone> = RefCell::new(
        Capstone::new()
            .arm64()
            .mode(arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .expect("capstone arm64 init failed — bundled build broken?"),
    );
}

/// Subset of mnemonics where capstone misidentifies the first operand as written.
/// For these instructions only nzcv is written; operands are all reads.
/// Mirrors `viewer/disasm.py:84-98`.
fn is_compare_style(mnem: &str) -> bool {
    let base = mnem.split('.').next().unwrap_or(mnem);
    matches!(
        base,
        "cmp" | "tst" | "cmn" | "ccmn" | "ccmp" | "fcmp" | "fccmp" | "fccmpe"
    )
}

/// Store-style instructions: first Reg operand is the source, not destination.
fn is_store_style(mnem: &str) -> bool {
    let base = mnem.split('.').next().unwrap_or(mnem);
    matches!(
        base,
        "str"
            | "strb"
            | "strh"
            | "stur"
            | "sturb"
            | "sturh"
            | "stp"
            | "stnp"
            | "stxp"
            | "stxr"
            | "stxrb"
            | "stxrh"
            | "stlxp"
            | "stlr"
            | "stlrb"
            | "stlrh"
            | "stlxr"
            | "stlxrb"
            | "stlxrh"
    )
}

fn is_exclusive_store_style(mnem: &str) -> bool {
    let base = mnem.split('.').next().unwrap_or(mnem);
    matches!(
        base,
        "stxr" | "stxrb" | "stxrh" | "stlxr" | "stlxrb" | "stlxrh" | "stxp" | "stlxp"
    )
}

fn is_load_pair_style(mnem: &str) -> bool {
    let base = mnem.split('.').next().unwrap_or(mnem);
    matches!(base, "ldp" | "ldnp" | "ldpsw" | "ldxp" | "ldaxp")
}

/// Deduplicate a list of strings, preserving order.
fn dedup_preserve_order(v: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    v.into_iter().filter(|s| seen.insert(s.clone())).collect()
}

/// Build reg def/use lists from capstone instruction detail.
///
/// Strategy (mirrors Python viewer/disasm.py via cs_regs_access semantics):
/// 1. Implicit regs from `InsnDetail.regs_read()` / `regs_write()` (e.g., nzcv, sp).
/// 2. Explicit Reg operands: first is written (unless store/compare-style), rest are read.
/// 3. Memory operands: base and index regs are reads.
/// 4. cmp-style fix: move any non-nzcv defs to uses.
fn build_reg_accesses(
    cs: &Capstone,
    ins: &capstone::Insn,
    mnem: &str,
) -> (Vec<String>, Vec<String>) {
    let detail = match cs.insn_detail(ins) {
        Ok(d) => d,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    // 1. Implicit registers
    let mut regs_use: Vec<String> = detail
        .regs_read()
        .iter()
        .filter_map(|reg| cs.reg_name(*reg))
        .map(|name| normalize_disasm_reg(&name))
        .filter(|s| !s.is_empty())
        .collect();
    let mut regs_def: Vec<String> = detail
        .regs_write()
        .iter()
        .filter_map(|reg| cs.reg_name(*reg))
        .map(|name| normalize_disasm_reg(&name))
        .filter(|s| !s.is_empty())
        .collect();

    // 2. Explicit operands
    let arch_det = detail.arch_detail();
    if let Some(arm64_det) = arch_det.arm64() {
        let store = is_store_style(mnem);
        let load_pair = is_load_pair_style(mnem);
        // Pre/post-indexed addressing modes (e.g. `ldr x0, [x1, #8]!` or
        // `ldr x0, [x1], #8`) writeback the computed address to the base
        // reg — so the base reg is BOTH a read AND a write. Capstone-rs
        // exposes this as an instruction-level `writeback()` flag; Python
        // gets the same info via `ins.regs_access()` returning the base
        // in regs_write. Mirrors viewer/disasm.py:75 parity. Caught by
        // M3-β parity gate on a real 469k-record trace where ldrh
        // w0,[x21,#0x20]! defs both x0 AND x21.
        let writeback = arm64_det.writeback();

        let mut reg_op_index: usize = 0;
        for op in arm64_det.operands() {
            match op.op_type {
                Arm64OperandType::Reg(reg_id) => {
                    let name = match cs.reg_name(reg_id) {
                        Some(n) => n,
                        None => {
                            reg_op_index += 1;
                            continue;
                        }
                    };
                    let normalized = normalize_disasm_reg(&name);
                    if normalized.is_empty() || normalized == "xzr" {
                        reg_op_index += 1;
                        continue;
                    }
                    // First explicit Reg operand is the destination for most insns.
                    // Normal stores read all explicit register operands.
                    // Exclusive stores (`stxr`, `stxp`, `stlxr`, `stlxp`, ...)
                    // are special: operand 0 is the status destination, while
                    // later register operands are store sources.
                    if (load_pair && reg_op_index < 2)
                        || (reg_op_index == 0 && (!store || is_exclusive_store_style(mnem)))
                    {
                        if !regs_def.contains(&normalized) {
                            regs_def.push(normalized);
                        }
                    } else if !regs_use.contains(&normalized) {
                        regs_use.push(normalized);
                    }
                    reg_op_index += 1;
                }
                Arm64OperandType::Mem(mem) => {
                    // Base register is always read; under writeback it's
                    // ALSO written.
                    let base_id = mem.base();
                    if base_id.0 != 0 {
                        if let Some(name) = cs.reg_name(base_id) {
                            let normalized = normalize_disasm_reg(&name);
                            if !normalized.is_empty() && normalized != "xzr" {
                                if !regs_use.contains(&normalized) {
                                    regs_use.push(normalized.clone());
                                }
                                if writeback && !regs_def.contains(&normalized) {
                                    regs_def.push(normalized);
                                }
                            }
                        }
                    }
                    // Index register is always read
                    let idx_id = mem.index();
                    if idx_id.0 != 0 {
                        if let Some(name) = cs.reg_name(idx_id) {
                            let normalized = normalize_disasm_reg(&name);
                            if !normalized.is_empty()
                                && normalized != "xzr"
                                && !regs_use.contains(&normalized)
                            {
                                regs_use.push(normalized);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // 3. cmp-style fix: capstone may put xzr / operand reg in defs; only nzcv is correct.
    if is_compare_style(mnem) {
        let nzcv_def = regs_def.iter().any(|r| r == "nzcv");
        let falsely_def: Vec<String> = regs_def.iter().filter(|r| *r != "nzcv").cloned().collect();
        regs_def = if nzcv_def {
            vec!["nzcv".to_string()]
        } else {
            Vec::new()
        };
        for r in falsely_def {
            if !regs_use.contains(&r) {
                regs_use.push(r);
            }
        }
    }

    (
        dedup_preserve_order(regs_use),
        dedup_preserve_order(regs_def),
    )
}

pub fn raw_decode(pc: u64, inst: u32) -> DecodedInsn {
    let bytes = inst.to_le_bytes();
    CS.with(|cs| {
        let cs = cs.borrow();
        let insns = match cs.disasm_all(&bytes, pc) {
            Ok(i) => i,
            Err(_) => return DecodedInsn::bad(pc, inst),
        };
        let Some(ins) = insns.iter().next() else {
            return DecodedInsn::bad(pc, inst);
        };
        let mnem = ins.mnemonic().unwrap_or("<bad>").to_string();
        let op_str = ins.op_str().unwrap_or("").to_string();

        let (regs_use, regs_def) = build_reg_accesses(&cs, ins, &mnem);
        let mem_op = mem_op::extract(&cs, ins, &mnem);

        DecodedInsn {
            pc,
            inst,
            is_branch: is_branch_mnem(&mnem),
            is_call: is_call_mnem(&mnem),
            is_ret: is_ret_mnem(&mnem),
            mnemonic: mnem,
            op_str,
            regs_def,
            regs_use,
            mem_op,
        }
    })
}
