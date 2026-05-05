//! TDD for tracemiku-core::disasm::mem_op.

use tracemiku_core::disasm::{addr_of, decode, MemOp};
use tracemiku_core::trace::Record;

#[test]
fn str_scalar_records_write_with_size_8() {
    // str x0, [x1, #16] = 0xf9000820 (encoding: x0 → [x1+16], 8B store)
    let d = decode(0x100000, 0xf9000820);
    assert_eq!(d.mem_op.len(), 1);
    let op = &d.mem_op[0];
    assert_eq!(op.base, "x1");
    assert_eq!(op.disp, 16);
    assert_eq!(op.size, 8);
    assert!(op.is_write);
}

#[test]
fn ldr_scalar_records_read() {
    // ldr x0, [x1] = 0xf9400020
    let d = decode(0x100000, 0xf9400020);
    assert_eq!(d.mem_op.len(), 1);
    let op = &d.mem_op[0];
    assert_eq!(op.base, "x1");
    assert_eq!(op.size, 8);
    assert!(!op.is_write);
}

#[test]
fn strb_records_size_1() {
    // strb w0, [x1] = 0x39000020
    let d = decode(0x100000, 0x39000020);
    assert_eq!(d.mem_op.len(), 1);
    assert_eq!(d.mem_op[0].size, 1);
    assert!(d.mem_op[0].is_write);
}

#[test]
fn stp_pair_splits_into_two_mem_ops_with_disp_offset() {
    // stp x0, x1, [sp, #16] = 0xa90107e0 (x0+x1 → [sp+16], 8+8B). Encoding:
    // STP signed offset, 64-bit, imm7=2 (× 8 = 16), Rt2=1, Rn=31 (sp), Rt=0.
    let d = decode(0x100000, 0xa90107e0);
    assert_eq!(d.mem_op.len(), 2, "stp must split into 2 mem_ops");
    assert_eq!(d.mem_op[0].size, 8);
    assert_eq!(d.mem_op[1].size, 8);
    assert_eq!(d.mem_op[0].disp + 8, d.mem_op[1].disp);
    assert_eq!(d.mem_op[0].src_reg, "x0");
    assert_eq!(d.mem_op[1].src_reg, "x1");
    assert!(d.mem_op[0].is_write);
    assert!(d.mem_op[1].is_write);
}

#[test]
fn stnp_pair_splits_into_two_write_mem_ops() {
    // stnp x0, x1, [sp, #16] = 0xa80107e0.
    let d = decode(0x100000, 0xa80107e0);
    assert_eq!(d.mnemonic, "stnp");
    assert_eq!(d.mem_op.len(), 2, "stnp must split into 2 mem_ops");
    assert_eq!(d.mem_op[0].size, 8);
    assert_eq!(d.mem_op[1].size, 8);
    assert_eq!(d.mem_op[0].base, "sp");
    assert_eq!(d.mem_op[0].disp + 8, d.mem_op[1].disp);
    assert_eq!(d.mem_op[0].src_reg, "x0");
    assert_eq!(d.mem_op[1].src_reg, "x1");
    assert!(d.mem_op[0].is_write);
    assert!(d.mem_op[1].is_write);
}

#[test]
fn exclusive_store_mem_ops_ignore_status_register_as_value_source() {
    // stxr w8, x0, [sp] = 0xc8087fe0.
    let scalar = decode(0x100000, 0xc8087fe0);
    assert_eq!(scalar.mnemonic, "stxr");
    assert_eq!(scalar.mem_op.len(), 1);
    assert_eq!(scalar.mem_op[0].src_reg, "x0");
    assert_eq!(scalar.mem_op[0].size, 8);
    assert!(scalar.mem_op[0].is_write);

    // stxp w8, x0, x1, [sp] = 0xc82807e0.
    let pair = decode(0x100004, 0xc82807e0);
    assert_eq!(pair.mnemonic, "stxp");
    assert_eq!(pair.mem_op.len(), 2);
    assert_eq!(pair.mem_op[0].src_reg, "x0");
    assert_eq!(pair.mem_op[1].src_reg, "x1");
    assert_eq!(pair.mem_op[0].size, 8);
    assert_eq!(pair.mem_op[1].size, 8);
    assert!(pair.mem_op[0].is_write);
    assert!(pair.mem_op[1].is_write);
}

#[test]
fn ldp_pair_splits_with_dest_regs() {
    // ldp x0, x1, [sp] = 0xa94007e0 (Rt=0, Rt2=1, Rn=31, imm7=0, L=1).
    let d = decode(0x100000, 0xa94007e0);
    assert_eq!(d.mem_op.len(), 2);
    assert!(!d.mem_op[0].is_write);
    assert!(!d.mem_op[1].is_write);
    assert_eq!(d.mem_op[0].src_reg, "x0");
    assert_eq!(d.mem_op[1].src_reg, "x1");
}

#[test]
fn nop_has_no_mem_op() {
    // nop = 0xd503201f
    let d = decode(0x100000, 0xd503201f);
    assert!(d.mem_op.is_empty());
}

#[test]
fn ret_has_no_mem_op() {
    // ret = 0xd65f03c0
    let d = decode(0x100000, 0xd65f03c0);
    assert!(d.mem_op.is_empty());
}

fn synth_record_with_regs(pc: u64, gprs: &[(usize, u64)]) -> Record {
    let mut r = Record::zero(pc);
    for (i, v) in gprs {
        r.set_gpr(*i, *v);
    }
    r
}

#[test]
fn addr_of_base_plus_disp() {
    let r = synth_record_with_regs(0x100000, &[(1, 0x7000)]);
    let op = MemOp {
        base: "x1".to_string(),
        idx: String::new(),
        disp: 16,
        size: 8,
        is_write: true,
        src_reg: "x0".to_string(),
    };
    assert_eq!(addr_of(&r, &op), 0x7010);
}

#[test]
fn addr_of_base_plus_idx_plus_disp() {
    let r = synth_record_with_regs(0x100000, &[(1, 0x7000), (2, 0x40)]);
    let op = MemOp {
        base: "x1".to_string(),
        idx: "x2".to_string(),
        disp: 0,
        size: 8,
        is_write: false,
        src_reg: "x0".to_string(),
    };
    assert_eq!(addr_of(&r, &op), 0x7040);
}

#[test]
fn addr_of_handles_unknown_base_as_zero() {
    let r = synth_record_with_regs(0x100000, &[]);
    let op = MemOp {
        base: "garbage".to_string(),
        idx: String::new(),
        disp: 5,
        size: 8,
        is_write: true,
        src_reg: String::new(),
    };
    assert_eq!(addr_of(&r, &op), 5);
}
