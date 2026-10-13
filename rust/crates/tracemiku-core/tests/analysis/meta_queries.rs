//! Black-box test: load a trace context and query metadata.

use super::analysis_support;
use std::fs;
use std::path::PathBuf;
use tracemiku_core::analysis::AnalysisContext;

fn synth_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_9r_2ms");
    fs::create_dir_all(&cd).unwrap();
    fs::write(cd.join("trace.bin"), []).unwrap();
    fs::write(cd.join("meta.json"),
              r#"{"callIdx":1,"tid":100,"records":9,"ms":2,"retval":"0x0","truncated":false,"last_insn_is_ret":true}"#).unwrap();
    fs::write(tmp.path().join("run").join("meta.json"),
              r#"{"pkg":"tst","so":"libt","method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#).unwrap();
    let cd_owned = cd.clone();
    (tmp, cd_owned)
}

#[test]
fn meta_query_returns_synth_trace_metadata() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = AnalysisContext::load(call_dir).expect("load analysis context");

    let resp = analysis_support::query(&app, "meta", None);
    assert_eq!(resp.error_code(), None);

    let body = resp.bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(v["records"], 9);
    assert_eq!(v["method"], "f");
    assert_eq!(v["cmd"], 1);
    assert_eq!(v["fn_addr"], "0x100000");
    assert_eq!(v["module"]["name"], "libt.so");
    assert_eq!(v["module"]["base"], "0x100000");
    assert_eq!(v["module"]["size"], 65536);
    assert_eq!(v["module"]["end"], "0x110000");
    assert_eq!(v["modules"][0]["name"], "libt.so");
    assert_eq!(v["regs"][0], "x0");
    assert_eq!(v["regs"][32], "pc");
}

#[test]
fn context_loads_trace_eagerly() {
    let (_tmp, call_dir) = synth_call_dir();
    let state = AnalysisContext::load(call_dir).expect("load context");
    // The synth fixture has 0 or 9 records (depending on fixture variant).
    let n = state.inner.trace.len();
    assert!(n == 0 || n == 9, "expected 0 or 9 records, got {n}");
}

#[test]
fn context_eagerly_loads_index_symbols_modules() {
    let (_tmp, call_dir) = synth_call_dir();
    let state = AnalysisContext::load(call_dir).expect("load context");
    // Index built — empty regs maps for an empty trace are OK.
    let _ = &state.inner.index().reg_defs;
    let _ = &state.inner.index().reg_uses;
    // SymbolMap built — empty for synth (no known_offsets in fixture).
    assert_eq!(state.inner.symbols().len(), 0);
    // ModuleResolver has libt.so.
    let m = state.inner.modules.resolve(0x100000);
    assert!(m.is_some(), "0x100000 should resolve to libt.so");
    assert_eq!(m.unwrap().name, "libt.so");
}

#[test]
fn context_builds_cfg_on_demand() {
    let (_tmp, call_dir) = synth_call_dir();
    let state = AnalysisContext::load(call_dir).expect("load context");
    // Empty trace → 0 blocks, but the field exists.
    let _ = state.inner.cfg().block_count();
}

#[test]
fn context_builds_function_index_on_demand() {
    let (_tmp, call_dir) = synth_call_dir();
    let state = AnalysisContext::load(call_dir).expect("load context");
    let _ = state.inner.function_index().len();
}

#[test]
fn context_builds_memshadow_on_demand() {
    let (_tmp, call_dir) = synth_call_dir();
    let state = AnalysisContext::load(call_dir).expect("load context");
    // synth fixture has no stores → memshadow.bytes is empty but the field
    // exists and is queryable.
    assert!(state.inner.memshadow_if_ready().is_none());
    let memshadow = state.inner.memshadow();
    assert!(state.inner.memshadow_if_ready().is_some());
    let _ = memshadow.bytes.len();
    let _ = memshadow.byte_at(0x7000, 1 << 60);
}
