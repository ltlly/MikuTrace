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
