//! Black-box contract tests for tracemiku-core::call_analysis.
//!
//! Exercises the public API (analyze_calls / render_calls_json /
//! render_calls_compact) on a synthetic Trace with direct bl, indirect blr,
//! argument registers, and a return record. Guards the AI-facing JSON shape.

use tracemiku_core::call_analysis::{analyze_calls, render_calls_compact, render_calls_json};
use tracemiku_core::symbols::SymbolMap;
use tracemiku_core::trace::Trace;

fn bl(pc: u64, target: u64) -> u32 {
    let delta = target.wrapping_sub(pc) as i64;
    assert_eq!(delta % 4, 0);
    let imm26 = (delta / 4) as u32;
    0x9400_0000 | (imm26 & 0x03ff_ffff)
}

/// Build a 5-record trace: nop, bl f_alpha, nop, ret, nop.
fn synth_trace() -> Trace {
    let mut buf = vec![0u8; 272 * 5];
    let insts = [
        0xd503201f,             // 0: nop
        bl(0x100004, 0x100100), // 1: bl f_alpha
        0xd503201f,             // 2: nop
        0xd65f03c0,             // 3: ret
        0xd503201f,             // 4: nop
    ];
    for (i, inst) in insts.iter().enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + (i as u64 * 4)).to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&(0x41u64).to_le_bytes()); // x0 = 0x41 'A'
        buf[off + 16..off + 24].copy_from_slice(&(0x42u64).to_le_bytes()); // x1 = 0x42 'B'
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("calls").join("call_001_tid1_5r_1ms");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("trace.bin"), &buf).unwrap();
    std::fs::write(
        dir.join("meta.json"),
        r#"{"records":5,"known_offsets":{"0x0":"f_root","0x100":"f_alpha"}}"#,
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    Trace::load(&dir).expect("open trace")
}

fn synth_symbols() -> SymbolMap {
    let mut symbols = SymbolMap::new();
    symbols.add(0x100000, "f_root".to_string());
    symbols.add(0x100100, "f_alpha".to_string());
    symbols
}

#[test]
fn analyze_calls_extracts_direct_call_with_args() {
    let trace = synth_trace();
    let symbols = synth_symbols();
    let analysis = analyze_calls(&trace, &symbols);
    assert_eq!(analysis.stats.total_calls, 1);
    assert_eq!(analysis.stats.direct_calls, 1);
    assert_eq!(analysis.stats.indirect_calls, 0);

    let call = &analysis.calls[0];
    assert_eq!(call.idx, 1);
    assert_eq!(call.caller_pc, 0x100004);
    assert_eq!(call.target_pc, 0x100100);
    assert!(!call.is_indirect);

    // AAPCS64 args x0-x7 captured; x0=0x41, x1=0x42.
    assert_eq!(call.args.len(), 8);
    assert_eq!(call.args[0].value, 0x41);
    assert_eq!(call.args[1].value, 0x42);
    assert_eq!(call.args[0].reg, "x0");
}

#[test]
fn analyze_calls_finds_return_record() {
    let trace = synth_trace();
    let symbols = synth_symbols();
    let analysis = analyze_calls(&trace, &symbols);
    let call = &analysis.calls[0];
    // Return is the next record at caller_pc + 4 (idx 2).
    assert_eq!(call.ret_idx, Some(2));
}

#[test]
fn analyze_calls_resolves_target_name() {
    let trace = synth_trace();
    let symbols = synth_symbols();
    let analysis = analyze_calls(&trace, &symbols);
    assert_eq!(analysis.stats.resolved_names, 1);
    assert_eq!(analysis.stats.unresolved_names, 0);
    assert_eq!(analysis.calls[0].target_name.as_deref(), Some("f_alpha"));
    assert_eq!(analysis.unique_targets, 1);
    assert_eq!(analysis.by_target.len(), 1);
}

#[test]
fn render_calls_json_is_valid_json_with_calls() {
    let trace = synth_trace();
    let symbols = synth_symbols();
    let analysis = analyze_calls(&trace, &symbols);
    let json = render_calls_json(&analysis);
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    let calls = value.get("calls").and_then(|v| v.as_array()).unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["idx"], 1);
    assert_eq!(calls[0]["target_pc"], 0x100100, "u64 serializes as number");
    assert_eq!(calls[0]["is_indirect"], false);
    assert_eq!(calls[0]["args"][0]["reg"], "x0");
    assert_eq!(calls[0]["target_name"], "f_alpha");
}

#[test]
fn render_calls_compact_mentions_target() {
    let trace = synth_trace();
    let symbols = synth_symbols();
    let analysis = analyze_calls(&trace, &symbols);
    let compact = render_calls_compact(&analysis);
    assert!(
        compact.contains("f_alpha"),
        "compact render must resolve target name, got: {compact}"
    );
}
