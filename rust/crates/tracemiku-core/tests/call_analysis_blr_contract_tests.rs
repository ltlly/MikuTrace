//! Supplemental black-box contract tests for call-site analysis.
//!
//! Covers the surfaces `call_analysis_contract_tests.rs` does not: the blr
//! (indirect) path through `decode_blr_target_reg`, empty-trace behavior,
//! and the fixed 8-byte AAPCS64 arg shape. These lock behavior so the module
//! cleanup (module-wide allow removal, dead `is_blr` deletion, magic-window
//! replacement) cannot change observable results.

use std::fs;
use std::path::PathBuf;

use tracemiku_core::call_analysis::{analyze_calls, render_calls_json};
use tracemiku_core::symbols::SymbolMap;
use tracemiku_core::trace::record::REC_SIZE;
use tracemiku_core::trace::trace::Trace;

fn write_call_dir(dir: &tempfile::TempDir, insts: &[u32]) -> PathBuf {
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_1r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; REC_SIZE * insts.len()];
    for (i, inst) in insts.iter().enumerate() {
        let off = i * REC_SIZE;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + i as u64 * 4).to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&0x4141u64.to_le_bytes()); // x0
                                                                          // x8 = 0x200000 (blr x8 target); regs[i] lives at offset 8 + 8*i.
        buf[off + 8 + 8 * 8..off + 16 + 8 * 8].copy_from_slice(&0x200000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(
        cd.join("meta.json"),
        format!(r#"{{"records":{}}}"#, insts.len()),
    )
    .unwrap();
    fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":0x10000}}"#,
    )
    .unwrap();
    cd
}

fn empty_symbols() -> SymbolMap {
    SymbolMap::new()
}

#[test]
fn blr_indirect_call_reports_is_indirect_and_reg_target() {
    // blr x8 = 0xD63F0100; target_pc should come from x8 = 0x200000.
    let dir = tempfile::tempdir().unwrap();
    let cd = write_call_dir(&dir, &[0xd63f0100]);
    let trace = Trace::load(&cd).unwrap();
    let analysis = analyze_calls(&trace, &empty_symbols());
    assert_eq!(analysis.stats.total_calls, 1);
    assert_eq!(analysis.stats.indirect_calls, 1);
    assert_eq!(analysis.stats.direct_calls, 0);
    let call = &analysis.calls[0];
    assert!(call.is_indirect);
    assert_eq!(call.target_pc, 0x200000, "blr x8 reads x8 value");
}

#[test]
fn every_arg_is_8_bytes_with_null_hint() {
    // AAPCS64 registers are 8 bytes wide on aarch64; type_hint is
    // intentionally absent until type inference lands.
    let dir = tempfile::tempdir().unwrap();
    let cd = write_call_dir(&dir, &[0x94000002, 0xd503201f]);
    let trace = Trace::load(&cd).unwrap();
    let analysis = analyze_calls(&trace, &empty_symbols());
    let call = &analysis.calls[0];
    assert_eq!(call.args.len(), 8);
    for arg in &call.args {
        assert_eq!(arg.size, 8);
        assert!(arg.type_hint.is_none());
    }
}

#[test]
fn empty_trace_yields_empty_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_0r_1ms");
    fs::create_dir_all(&cd).unwrap();
    fs::write(cd.join("trace.bin"), vec![0u8; 0]).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":0}"#).unwrap();
    fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":0x10000}}"#,
    )
    .unwrap();
    let trace = Trace::load(&cd).unwrap();
    let analysis = analyze_calls(&trace, &empty_symbols());
    assert!(analysis.calls.is_empty());
    assert_eq!(analysis.stats.total_calls, 0);
    assert_eq!(analysis.unique_targets, 0);
}

#[test]
fn render_json_serializes_blr_target() {
    let dir = tempfile::tempdir().unwrap();
    let cd = write_call_dir(&dir, &[0xd63f0100]);
    let trace = Trace::load(&cd).unwrap();
    let analysis = analyze_calls(&trace, &empty_symbols());
    let json = render_calls_json(&analysis);
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    let calls = value.get("calls").and_then(|v| v.as_array()).unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["is_indirect"], serde_json::Value::Bool(true));
}
