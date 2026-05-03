mod common;

use tracemiku_core::prelude::*;

#[test]
fn loads_synth_meta() {
    let fix = common::synth_meta_only_dir();
    let meta = TraceMeta::load(&fix.call_dir).expect("load synth meta");

    assert_eq!(meta.records, 9);
    assert_eq!(meta.method, "f");
    assert_eq!(meta.cmd, Some(1));
    assert_eq!(meta.fn_addr, Some("0x100000".to_string()));

    let m = meta.module.as_ref().expect("primary module");
    assert_eq!(m.name, "libt.so");
    assert_eq!(m.base, "0x100000");
    assert_eq!(m.size, 0x10000);
    assert_eq!(m.end, "0x110000");

    assert_eq!(meta.modules.len(), 1);
    assert_eq!(meta.modules[0].name, "libt.so");

    // ARM64 register list — 33 names, in canonical order.
    assert_eq!(meta.regs.len(), 33);
    assert_eq!(meta.regs[0], "x0");
    assert_eq!(meta.regs[30], "lr");
    assert_eq!(meta.regs[32], "pc");
}

#[test]
fn missing_meta_yields_clear_error() {
    let tmp = tempfile::tempdir().unwrap();
    let result = TraceMeta::load(tmp.path());
    assert!(result.is_err(), "should fail when no meta.json present");
}

#[test]
fn module_end_computed_from_base_plus_size() {
    let fix = common::synth_meta_only_dir();
    let meta = TraceMeta::load(&fix.call_dir).unwrap();
    let m = meta.module.unwrap();
    // 0x100000 + 0x10000 = 0x110000
    assert_eq!(m.end, "0x110000");
}
