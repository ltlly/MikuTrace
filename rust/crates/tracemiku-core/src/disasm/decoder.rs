//! capstone-rs wrapper. M2-β provides decode() returning DecodedInsn with
//! mnemonic + op_str + branch/call/ret classification. Register def/use,
//! branch_target, mem_op come in M2-γ when Index needs them.

use serde::Serialize;

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
