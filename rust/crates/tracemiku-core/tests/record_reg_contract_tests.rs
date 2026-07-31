//! Contract tests: `Record::reg` and `Record::reg_by_name` must agree on
//! every canonical name. They are two public lookups for the same register
//! file; a divergence (e.g. `reg("x29")` returning None while
//! `reg_by_name("x29")` returns the frame pointer) silently corrupts any
//! analysis that mixes the two APIs.

use tracemiku_core::trace::record::Record;

fn sample() -> Record {
    let mut regs = [0u64; 31];
    for (i, v) in regs.iter_mut().enumerate() {
        *v = (0x100 + i) as u64;
    }
    regs[29] = 0xCAFE; // fp
    regs[30] = 0xBEAD; // lr
    Record {
        pc: 0x100000,
        regs,
        sp: 0x7000,
        nzcv: 0x40000000,
        inst: 0xd503201f,
    }
}

const CANONICAL: [&str; 33] = [
    "pc", "sp", "nzcv", "fp", "lr", "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
    "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22",
    "x23", "x24", "x25", "x26", "x27",
];

#[test]
fn both_apis_agree_on_canonical_names() {
    let r = sample();
    for name in CANONICAL {
        assert_eq!(
            r.reg(name),
            r.reg_by_name(name),
            "reg({name}) and reg_by_name({name}) disagree"
        );
    }
}

#[test]
fn both_apis_agree_on_x28_x29_x30() {
    // x28 (max for reg()), x29=fp, x30=lr — the boundary that used to diverge.
    let r = sample();
    assert_eq!(r.reg("x28"), r.reg_by_name("x28"));
    assert_eq!(r.reg("x29"), r.reg_by_name("x29"));
    assert_eq!(r.reg("x30"), r.reg_by_name("x30"));
    assert_eq!(r.reg("x29"), Some(0xCAFE));
    assert_eq!(r.reg("x30"), Some(0xBEAD));
}

#[test]
fn reg_accepts_w_aliases_like_reg_by_name() {
    // w0..w30 are 32-bit views; both APIs must mask identically.
    let r = sample();
    assert_eq!(r.reg("w0"), r.reg_by_name("w0"));
    assert_eq!(r.reg("w0"), Some(0x100));
    assert_eq!(r.reg("w28"), r.reg_by_name("w28"));
}

#[test]
fn both_apis_reject_unknown_names() {
    let r = sample();
    for name in ["x31", "v0", "q0", "r0", "", "xzr_bad"] {
        assert_eq!(r.reg(name), r.reg_by_name(name), "mismatch for {name}");
    }
}

#[test]
fn zero_registers_agree() {
    let r = sample();
    assert_eq!(r.reg("xzr"), r.reg_by_name("xzr"));
    assert_eq!(r.reg("wzr"), r.reg_by_name("wzr"));
    assert_eq!(r.reg("xzr"), Some(0));
}
