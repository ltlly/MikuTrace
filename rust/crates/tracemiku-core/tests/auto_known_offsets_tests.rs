//! TDD for auto_known_offsets (bl-target discovery).

#[path = "common/mod.rs"]
mod common;

use tracemiku_core::prelude::*;

#[test]
fn auto_discovers_bl_targets() {
    use std::fs;
    use std::io::Write;
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_9r_2ms");
    fs::create_dir_all(&cd).unwrap();
    // PCs and their instructions.
    // bl from 0x100000 → target 0x100100: offset=0x100, imm26=0x40 → 0x94000040
    // bl from 0x100008 → target 0x100200: offset=0x1F8, imm26=0x7E → 0x9400007E
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
        0x94000040, 0xd503201f, 0xd503201f, 0xd65f03c0, 0x9400007e, 0xd503201f, 0xd503201f,
        0xd65f03c0, 0xd65f03c0,
    ];
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
    fs::write(cd.join("meta.json"), r#"{"records":9,"truncated":false}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let t = Trace::load(&cd).unwrap();
    let auto = tracemiku_core::symbols::auto_known_offsets(&t);

    let names: Vec<&String> = auto.values().collect();
    assert!(
        auto.contains_key(&0x100100),
        "expected absolute bl target 0x100100, got: {names:?}"
    );
    assert!(
        auto.contains_key(&0x100200),
        "expected absolute bl target 0x100200, got: {names:?}"
    );
}

#[test]
fn auto_discovers_with_base_offset_keys() {
    use std::fs;
    use std::io::Write;
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_9r_2ms");
    fs::create_dir_all(&cd).unwrap();
    // bl from 0x100000 → target 0x100100: offset=0x100, imm26=0x40 → 0x94000040
    // bl from 0x100008 → target 0x100200: offset=0x1F8, imm26=0x7E → 0x9400007E
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
        0x94000040, 0xd503201f, 0xd503201f, 0xd65f03c0, 0x9400007e, 0xd503201f, 0xd503201f,
        0xd65f03c0, 0xd65f03c0,
    ];
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
    fs::write(cd.join("meta.json"), r#"{"records":9}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let t = Trace::load(&cd).unwrap();
    let auto = tracemiku_core::symbols::auto_known_offsets_with_base(&t, 0x100000);

    assert!(
        auto.contains_key(&0x100),
        "expected relative offset 0x100, got: {:?}",
        auto
    );
    assert!(
        auto.contains_key(&0x200),
        "expected relative offset 0x200, got: {:?}",
        auto
    );
}

#[test]
fn auto_returns_empty_for_no_calls() {
    let fix = common::synth_trace_dir(5);
    let t = Trace::load(&fix.call_dir).unwrap();
    let auto = tracemiku_core::symbols::auto_known_offsets(&t);
    assert!(
        auto.is_empty(),
        "no bl → empty map, got {} entries",
        auto.len()
    );
}

#[test]
fn auto_naming_convention() {
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
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0x94000040u32.to_le_bytes());
    buf[272..280].copy_from_slice(&0x100100u64.to_le_bytes());
    buf[272 + 268..272 + 272].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
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
    let auto = tracemiku_core::symbols::auto_known_offsets(&t);
    for name in auto.values() {
        assert!(!name.is_empty());
        assert!(!name.contains(' '), "name has space: {name:?}");
        // M3-alpha parity pin: keep IDA/Hex-Rays sub_<hex> naming.
        // This previously regressed during auto-known-offsets porting and would
        // be invisible to shape-only unit tests without this assertion.
        assert!(
            name.starts_with("sub_"),
            "auto-discovered name must use sub_<hex> convention, got {name:?}"
        );
    }
}

#[test]
fn auto_discovers_cross_module_targets_with_target_module_relative_names() {
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
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    // bl 0x200100 from pc 0x100000: imm26=(0x100100 >> 2)=0x40040.
    buf[268..272].copy_from_slice(&0x94040040u32.to_le_bytes());
    buf[272..280].copy_from_slice(&0x200100u64.to_le_bytes());
    buf[272 + 268..272 + 272].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
    fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":2}"#).unwrap();

    let modules = vec![
        ModuleInfo {
            name: "liba.so".to_string(),
            base: "0x100000".to_string(),
            size: 0x1000,
            end: "0x101000".to_string(),
        },
        ModuleInfo {
            name: "libb.so".to_string(),
            base: "0x200000".to_string(),
            size: 0x1000,
            end: "0x201000".to_string(),
        },
    ];
    let t = Trace::load(&cd).unwrap();
    let resolver = ModuleResolver::from_modules(&modules);
    let auto = tracemiku_core::symbols::auto_known_symbols_with_modules(&t, &resolver);

    assert_eq!(
        auto.get(&0x200100).map(String::as_str),
        Some("sub_100"),
        "cross-SO target should be named relative to libb.so, got {auto:?}"
    );
}
