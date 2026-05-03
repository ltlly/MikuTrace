//! TDD for tracemiku-core::index.

#[path = "common/mod.rs"]
mod common;

use tracemiku_core::prelude::*;

#[test]
fn index_records_reg_def_for_mov_record() {
    use std::fs;
    use std::io::Write;

    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_1r_2ms");
    fs::create_dir_all(&cd).unwrap();

    let mut buf = vec![0u8; 272];
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[256..264].copy_from_slice(&0x7000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xaa0103e0u32.to_le_bytes()); // mov x0, x1
    let mut f = fs::File::create(cd.join("trace.bin")).unwrap();
    f.write_all(&buf).unwrap();

    fs::write(
        cd.join("meta.json"),
        r#"{"records":1,"tid":100,"ms":2,"truncated":false}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let t = Trace::load(&cd).unwrap();
    let idx = Index::build(&t);

    let x0_defs = idx.reg_defs.get("x0").expect("x0 must have defs");
    assert_eq!(x0_defs, &vec![0usize]);

    let x1_uses = idx.reg_uses.get("x1").expect("x1 must have uses");
    assert_eq!(x1_uses, &vec![0usize]);

    assert!(idx.reg_uses.get("x0").map(|v| v.is_empty()).unwrap_or(true));
}

#[test]
fn index_empty_trace_yields_empty_index() {
    let fix = common::synth_trace_dir(0);
    let t = Trace::load(&fix.call_dir).unwrap();
    let idx = Index::build(&t);
    assert!(idx.reg_defs.is_empty());
    assert!(idx.reg_uses.is_empty());
}

#[test]
fn index_synth_trace_has_consistent_counts() {
    let fix = common::synth_trace_dir(5);
    let t = Trace::load(&fix.call_dir).unwrap();
    let idx = Index::build(&t);
    let total_def_entries: usize = idx.reg_defs.values().map(|v| v.len()).sum();
    let total_use_entries: usize = idx.reg_uses.values().map(|v| v.len()).sum();
    assert_eq!(
        total_def_entries, 0,
        "nop-only synth trace should have no defs, got: {:?}",
        idx.reg_defs
    );
    assert_eq!(total_use_entries, 0);
}
