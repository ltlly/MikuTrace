//! Tests the public `decode(pc, inst)` cached entrypoint.

use tracemiku_core::disasm::decode;

#[test]
fn decode_returns_same_result_repeated() {
    let a = decode(0x100000, 0xd503201f);
    let b = decode(0x100000, 0xd503201f);
    // Cached value should be byte-equal (we don't expose hit/miss, just verify
    // semantics: same input -> same output).
    assert_eq!(a.mnemonic, b.mnemonic);
    assert_eq!(a.op_str, b.op_str);
    assert_eq!(a.pc, b.pc);
    assert_eq!(a.inst, b.inst);
}

#[test]
fn decode_distinct_keys_distinct_results() {
    let a = decode(0x100000, 0xd503201f); // nop
    let b = decode(0x100008, 0xd65f03c0); // ret
    assert_eq!(a.mnemonic, "nop");
    assert_eq!(b.mnemonic, "ret");
}

#[test]
fn decode_works_on_many_distinct_pcs() {
    // Exceed a small cache; should still produce correct results.
    for i in 0..1024u64 {
        let d = decode(0x100000 + i * 4, 0xd503201f);
        assert_eq!(d.mnemonic, "nop", "iteration {i}");
        assert_eq!(d.pc, 0x100000 + i * 4);
    }
}

#[test]
fn decode_keeps_high_pc_bits_in_cache_key() {
    // 低 32 位相同、高位不同的两个 PC（ARM64 PAC/高位栈地址常见形态）。
    // 旧实现用 `(pc << 32) | inst` 打包键会丢弃 PC 高 32 位，第二个调用
    // 命中第一个的缓存项并返回错误的 pc 字段。
    let low = decode(0x0010_0000, 0xd503201f);
    let high = decode(0x1_0010_0000, 0xd503201f);
    assert_eq!(low.mnemonic, "nop");
    assert_eq!(high.mnemonic, "nop");
    assert_eq!(low.pc, 0x0010_0000);
    assert_eq!(high.pc, 0x1_0010_0000);
}
