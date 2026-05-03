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

// ── Classifier sweep ───────────────────────────────────────────────────────

use tracemiku_core::disasm::classify::{is_branch_mnem, is_call_mnem, is_ret_mnem};

#[test]
fn classifier_branch_set() {
    for m in [
        "b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz", "b.eq", "b.ne", "b.gt",
        "b.lt", "b.al",
    ] {
        assert!(is_branch_mnem(m), "{m} should be a branch");
    }
}

#[test]
fn classifier_call_set() {
    for m in ["bl", "blr"] {
        assert!(is_call_mnem(m), "{m} should be a call");
    }
    for m in ["b", "br", "ret", "cbz", "b.eq"] {
        assert!(!is_call_mnem(m), "{m} should NOT be a call");
    }
}

#[test]
fn classifier_ret_set() {
    assert!(is_ret_mnem("ret"));
    for m in ["b", "bl", "br", "blr", "cbz", "b.eq"] {
        assert!(!is_ret_mnem(m), "{m} should NOT be a ret");
    }
}

#[test]
fn classifier_negatives() {
    for m in ["nop", "mov", "add", "sub", "ldr", "str", "cmp", "beep"] {
        // "beep" must NOT match starts_with("b.") — verify the "." matters
        let expected_branch = m.starts_with("b.")
            || matches!(
                m,
                "b" | "bl" | "br" | "blr" | "ret" | "cbz" | "cbnz" | "tbz" | "tbnz"
            );
        assert_eq!(
            is_branch_mnem(m),
            expected_branch,
            "branch classify of {m:?}"
        );
    }
}

#[test]
fn classifier_beep_not_a_branch() {
    // Regression: ensure starts_with("b.") doesn't accidentally match "beep" or "br"
    // (br is in the explicit set; "beep" must be false).
    assert!(!is_branch_mnem("beep"));
    assert!(!is_branch_mnem("blob"));
    assert!(!is_branch_mnem("bx")); // not present in ARM64 (it's ARM32)
    assert!(is_branch_mnem("br")); // explicit set
}
