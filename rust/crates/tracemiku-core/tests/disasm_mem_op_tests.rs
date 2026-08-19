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
    assert_eq!(op.src_reg, "x0");
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
fn scaled_register_index_records_shift() {
    // str x19, [x25, x15, lsl #3] = bytes 33 7b 2f f8.
    let d = decode(0x100000, 0xf82f7b33);
    assert_eq!(d.mem_op.len(), 1);
    assert_eq!(d.mem_op[0].base, "x25");
    assert_eq!(d.mem_op[0].idx, "x15");
    assert_eq!(d.mem_op[0].shift, 3);
    assert!(d.mem_op[0].is_write);

    // ldr x20, [x25, x17, lsl #3] = bytes 34 7b 71 f8.
    let d = decode(0x100004, 0xf8717b34);
    assert_eq!(d.mem_op.len(), 1);
    assert_eq!(d.mem_op[0].base, "x25");
    assert_eq!(d.mem_op[0].idx, "x17");
    assert_eq!(d.mem_op[0].shift, 3);
    assert!(!d.mem_op[0].is_write);
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
    assert!(d.regs_def.contains(&"x0".to_string()));
    assert!(d.regs_def.contains(&"x1".to_string()));
}

#[test]
fn ldpsw_pair_splits_as_two_32bit_reads_with_x_defs() {
    // ldpsw x0, x1, [sp] = 0x694007e0. Each half reads 4 bytes and sign-extends
    // into an x-register destination.
    let d = decode(0x100000, 0x694007e0);
    assert_eq!(d.mnemonic, "ldpsw");
    assert_eq!(d.mem_op.len(), 2);
    assert_eq!(d.mem_op[0].size, 4);
    assert_eq!(d.mem_op[1].size, 4);
    assert_eq!(d.mem_op[0].src_reg, "x0");
    assert_eq!(d.mem_op[1].src_reg, "x1");
    assert!(d.regs_def.contains(&"x0".to_string()));
    assert!(d.regs_def.contains(&"x1".to_string()));
}

#[test]
fn ldrsw_records_4_byte_access_not_register_width() {
    // ldrsw x0, [x1] = 0xb9800020。LDRSW 从内存读取 4 字节并符号扩展到
    // x 寄存器（ARM DDI 0487 C4.1.62：access size = 4 bytes）；旧实现按
    // 目的寄存器（x 系）误报 8 字节。
    let d = decode(0x100000, 0xb9800020);
    assert_eq!(d.mnemonic, "ldrsw");
    assert_eq!(d.mem_op.len(), 1);
    assert_eq!(d.mem_op[0].size, 4);
    assert!(!d.mem_op[0].is_write);
}

#[test]
fn swp_size_follows_data_register_class() {
    // swp x0, x1, [x2] = 0xf8208041（64 位交换，8 字节）；swp w0, w1, [x2]
    // = 0xb8208041（32 位交换，4 字节）。旧实现见助记符 head 含 'w' 一律
    // 报 4，把 swp x* 错报成 4 字节。
    let d64 = decode(0x100000, 0xf8208041);
    assert_eq!(d64.mnemonic, "swp");
    assert_eq!(d64.mem_op.len(), 1);
    assert_eq!(d64.mem_op[0].size, 8);
    let d32 = decode(0x100004, 0xb8208041);
    assert_eq!(d32.mnemonic, "swp");
    assert_eq!(d32.mem_op.len(), 1);
    assert_eq!(d32.mem_op[0].size, 4);
}

#[test]
fn simd_ldr_str_sizes_follow_register_class() {
    // FP/SIMD 加载存储的访存宽度由寄存器类决定（ARM DDI 0487 C4.1.60）：
    // q=128b(16B)、d=64b(8B)、s=32b(4B)、h=16b(2B)、b=8b(1B)。
    // 旧实现一律按 8 字节。
    // str q0, [x0] = 0x3d800000; ldr q0, [x0] = 0x3dc00000.
    assert_eq!(decode(0x100000, 0x3d800000).mem_op[0].size, 16);
    assert_eq!(decode(0x100004, 0x3dc00000).mem_op[0].size, 16);
    // str d0, [x0] = 0xfd000000; ldr d0, [x0] = 0xfd400000.
    assert_eq!(decode(0x100008, 0xfd000000).mem_op[0].size, 8);
    assert_eq!(decode(0x10000c, 0xfd400000).mem_op[0].size, 8);
    // str s0, [x0] = 0xbd000000; ldr s0, [x0] = 0xbd400000.
    assert_eq!(decode(0x100010, 0xbd000000).mem_op[0].size, 4);
    assert_eq!(decode(0x100014, 0xbd400000).mem_op[0].size, 4);
    // str h0, [x0] = 0x7d000000; ldr h0, [x0] = 0x7d400000.
    assert_eq!(decode(0x100018, 0x7d000000).mem_op[0].size, 2);
    assert_eq!(decode(0x10001c, 0x7d400000).mem_op[0].size, 2);
    // str b0, [x0] = 0x3d000000; ldr b0, [x0] = 0x3d400000.
    assert_eq!(decode(0x100020, 0x3d000000).mem_op[0].size, 1);
    assert_eq!(decode(0x100024, 0x3d400000).mem_op[0].size, 1);
}

#[test]
fn stp_q_pair_splits_into_two_16_byte_halves() {
    // stp q0, q1, [sp] = 0xad0007e0：两个半区各 16 字节（128-bit SIMD 对）。
    // 旧实现把每半错报为 8 字节。
    let d = decode(0x100000, 0xad0007e0);
    assert_eq!(d.mnemonic, "stp");
    assert_eq!(d.mem_op.len(), 2);
    assert_eq!(d.mem_op[0].size, 16);
    assert_eq!(d.mem_op[1].size, 16);
    assert_eq!(d.mem_op[0].disp + 16, d.mem_op[1].disp);
    assert_eq!(d.mem_op[0].src_reg, "q0");
    assert_eq!(d.mem_op[1].src_reg, "q1");
    assert!(d.mem_op[0].is_write);
}

#[test]
fn ldp_d_pair_splits_into_two_8_byte_halves() {
    // ldp d0, d1, [sp] = 0x6d4007e0：两个半区各 8 字节（64-bit FP 对）。
    let d = decode(0x100000, 0x6d4007e0);
    assert_eq!(d.mnemonic, "ldp");
    assert_eq!(d.mem_op.len(), 2);
    assert_eq!(d.mem_op[0].size, 8);
    assert_eq!(d.mem_op[1].size, 8);
    assert!(!d.mem_op[0].is_write);
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
        shift: 0,
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
        shift: 0,
        disp: 0,
        size: 8,
        is_write: false,
        src_reg: "x0".to_string(),
    };
    assert_eq!(addr_of(&r, &op), 0x7040);
}

#[test]
fn addr_of_base_plus_shifted_idx_plus_disp() {
    let r = synth_record_with_regs(0x100000, &[(1, 0x7000), (2, 0x11)]);
    let op = MemOp {
        base: "x1".to_string(),
        idx: "x2".to_string(),
        shift: 3,
        disp: 0,
        size: 8,
        is_write: true,
        src_reg: "x0".to_string(),
    };
    assert_eq!(addr_of(&r, &op), 0x7088);
}

#[test]
fn addr_of_handles_unknown_base_as_zero() {
    let r = synth_record_with_regs(0x100000, &[]);
    let op = MemOp {
        base: "garbage".to_string(),
        idx: String::new(),
        shift: 0,
        disp: 5,
        size: 8,
        is_write: true,
        src_reg: String::new(),
    };
    assert_eq!(addr_of(&r, &op), 5);
}
