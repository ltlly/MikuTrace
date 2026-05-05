//! TDD for tracemiku-core::cfg.

#[path = "common/mod.rs"]
mod common;

use tracemiku_core::prelude::*;

#[test]
fn build_cfg_synth_three_function_trace() {
    use std::fs;
    use std::io::Write;

    let pcs = [
        0x100000u64,
        0x100004,
        0x100100,
        0x100104,
        0x100008,
        0x100200,
        0x100204,
        0x100208,
        0x10000c,
    ];
    let insts: [u32; 9] = [
        0xd503201f, 0x94000040, 0xd503201f, 0xd65f03c0, 0x94000080, 0xd503201f, 0xd503201f,
        0xd65f03c0, 0xd65f03c0,
    ];

    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_9r_2ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 9];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    fs::write(cd.join("meta.json"),
              r#"{"records":9,"tid":100,"ms":2,"truncated":false,"known_offsets":{"0x0":"f_root","0x100":"f_alpha","0x200":"f_beta"}}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let t = Trace::load(&cd).unwrap();
    let cfg = tracemiku_core::cfg::build_cfg(&t);

    // Block count: simple split-at-every-branch yields ≥3, ≤9.
    assert!(
        cfg.block_count() >= 3,
        "expected ≥3 blocks, got {}",
        cfg.block_count()
    );
    assert!(
        cfg.block_count() <= 9,
        "expected ≤9 blocks, got {}",
        cfg.block_count()
    );

    assert!(
        cfg.block(0x100000).is_some(),
        "expected block at 0x100000 (f_root entry)"
    );
    assert!(
        cfg.block(0x100100).is_some(),
        "expected block at 0x100100 (f_alpha entry / branch target)"
    );
    assert!(
        cfg.block(0x100200).is_some(),
        "expected block at 0x100200 (f_beta entry)"
    );
}

#[test]
fn build_cfg_empty_trace() {
    let fix = common::synth_trace_dir(0);
    let t = Trace::load(&fix.call_dir).unwrap();
    let cfg = tracemiku_core::cfg::build_cfg(&t);
    assert_eq!(cfg.block_count(), 0);
    assert_eq!(cfg.edge_count(), 0);
}

#[test]
fn build_cfg_single_nop_one_block() {
    let fix = common::synth_trace_dir(1);
    let t = Trace::load(&fix.call_dir).unwrap();
    let cfg = tracemiku_core::cfg::build_cfg(&t);
    assert_eq!(cfg.block_count(), 1);
    let b = cfg.block(0x100000).expect("block at 0x100000");
    assert_eq!(b.start_pc, 0x100000);
    assert_eq!(b.executions, 1);
}

#[test]
fn build_cfg_block_executions_counted() {
    use std::fs;
    use std::io::Write;
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_5r_2ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 5];
    for i in 0..5 {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&0x100000u64.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    }
    fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":5}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let t = Trace::load(&cd).unwrap();
    let cfg = tracemiku_core::cfg::build_cfg(&t);
    let b = cfg.block(0x100000).unwrap();
    assert_eq!(b.executions, 5);
}

#[test]
fn build_cfg_scc_assigns_ids() {
    use std::fs;
    use std::io::Write;
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_2r_2ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 2];
    for i in 0..2 {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&0x100000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0x14000000u32.to_le_bytes());
    }
    fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":2}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let t = Trace::load(&cd).unwrap();
    let cfg = tracemiku_core::cfg::build_cfg(&t);
    let b = cfg.block(0x100000).unwrap();
    let _ = b.scc_id; // smoke check: field is set
}

#[test]
fn build_cfg_scc_distinct_for_acyclic() {
    let fix = common::synth_trace_dir(5);
    let t = Trace::load(&fix.call_dir).unwrap();
    let cfg = tracemiku_core::cfg::build_cfg(&t);
    let blocks = cfg.blocks();
    let mut scc_ids: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for b in &blocks {
        scc_ids.insert(b.scc_id);
    }
    assert_eq!(
        scc_ids.len(),
        blocks.len(),
        "acyclic CFG should have N distinct SCCs, got {} for {} blocks",
        scc_ids.len(),
        blocks.len()
    );
}
