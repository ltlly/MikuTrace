//! TDD for tracemiku-core::disasm::raw_decode.
//!
//! Reference instruction encodings (ARM64 little-endian u32):
//!   nop:                0xd503201f
//!   ret:                0xd65f03c0
//!   bl <pc + 0x100>:    0x94000040 from PC 0x100000 → "bl 0x100100"
//!   b  +0x8:            0x14000002 from PC 0x100000 → "b 0x100008"
//!   b.eq +0:            0x54000000 from PC 0x100000 → "b.eq 0x100000"
//!   bad bytes:          0x00000000

use tracemiku_core::disasm::{decoder::raw_decode, DecodedInsn};

#[test]
fn decodes_nop() {
    let d: DecodedInsn = raw_decode(0x100000, 0xd503201f);
    assert_eq!(d.pc, 0x100000);
    assert_eq!(d.inst, 0xd503201f);
    assert_eq!(d.mnemonic, "nop");
    assert!(!d.is_branch);
    assert!(!d.is_call);
    assert!(!d.is_ret);
}

#[test]
fn decodes_ret() {
    let d = raw_decode(0x100008, 0xd65f03c0);
    assert_eq!(d.mnemonic, "ret");
    assert!(d.is_branch);
    assert!(!d.is_call);
    assert!(d.is_ret);
}

#[test]
fn decodes_bl_as_call_and_branch() {
    let d = raw_decode(0x100000, 0x94000040);
    assert_eq!(d.mnemonic, "bl");
    assert!(d.is_branch);
    assert!(d.is_call);
    assert!(!d.is_ret);
    assert!(
        d.op_str.contains("0x100100") || d.op_str.contains("100100"),
        "op_str should resolve target, got: {:?}",
        d.op_str
    );
}

#[test]
fn decodes_b_unconditional_as_branch_not_call() {
    let d = raw_decode(0x100000, 0x14000002);
    assert_eq!(d.mnemonic, "b");
    assert!(d.is_branch);
    assert!(!d.is_call);
    assert!(!d.is_ret);
}

#[test]
fn decodes_b_dot_eq_as_branch() {
    let d = raw_decode(0x100000, 0x54000000);
    assert!(
        d.mnemonic.starts_with("b."),
        "expected b.cond, got {:?}",
        d.mnemonic
    );
    assert!(d.is_branch, "b.eq must be classified as a branch");
    assert!(!d.is_call);
}

#[test]
fn decodes_unknown_bytes_yields_bad() {
    let d = raw_decode(0x100000, 0x00000000);
    assert!(
        d.mnemonic == "udf" || d.mnemonic == "<bad>",
        "unexpected mnemonic for invalid inst: {:?}",
        d.mnemonic
    );
}
