//! capstone-rs wrapper. M2-β provides decode() returning DecodedInsn with
//! mnemonic + op_str + branch/call/ret classification. Register def/use,
//! branch_target, mem_op come in M2-γ when Index needs them.

use std::cell::RefCell;

use capstone::arch::{arm64, BuildsCapstone};
use capstone::Capstone;
use serde::Serialize;

use crate::disasm::classify::{is_branch_mnem, is_call_mnem, is_ret_mnem};

/// Decoded ARM64 instruction. Wire-compatible with Python `viewer.disasm.Decoded`
/// for the fields M2-β consumes; remaining fields filled in M2-γ.
#[derive(Debug, Clone, Serialize)]
pub struct DecodedInsn {
    pub pc: u64,
    pub inst: u32,
    pub mnemonic: String,
    pub op_str: String,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_ret: bool,
}

impl DecodedInsn {
    /// Construct a decode-failure placeholder. Mirrors Python's
    /// `Decoded(pc, inst, "<bad>", f"{inst:08x}")`.
    pub fn bad(pc: u64, inst: u32) -> Self {
        Self {
            pc,
            inst,
            mnemonic: "<bad>".to_string(),
            op_str: format!("{inst:08x}"),
            is_branch: false,
            is_call: false,
            is_ret: false,
        }
    }
}

thread_local! {
    /// Each thread keeps its own Capstone handle. Capstone instances are
    /// `!Send` (per capstone-rs docs), so thread-local is mandatory.
    static CS: RefCell<Capstone> = RefCell::new(
        Capstone::new()
            .arm64()
            .mode(arm64::ArchMode::Arm)
            .detail(false)  // M2-β: no operand details needed; M2-γ flips this on for def_use
            .build()
            .expect("capstone arm64 init failed — bundled build broken?"),
    );
}

/// Decode a single 4-byte ARM64 instruction at the given PC.
/// On decode failure (e.g. invalid bytes), returns [`DecodedInsn::bad`].
///
/// Cold path — no caching. For repeat decodes prefer [`crate::disasm::decode`].
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
        DecodedInsn {
            pc,
            inst,
            is_branch: is_branch_mnem(&mnem),
            is_call: is_call_mnem(&mnem),
            is_ret: is_ret_mnem(&mnem),
            mnemonic: mnem,
            op_str,
        }
    })
}
