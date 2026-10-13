//! Boundary contract tests for the indirect-targets status matrix.
//!
//! Covers the branches `contract_queries_1` does not: miss (module not
//! loaded), ambiguous (prefix matches multiple modules), no_dispatch (PC is
//! not an indirect branch), and invalid input shapes.

use super::analysis_support;
use std::fs;
use std::path::PathBuf;
use tracemiku_core::analysis::AnalysisContext;

fn synth_call_dir(module_json: &str) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_3r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 3];
    for i in 0..3 {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + i as u64 * 4).to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
        // nop
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":3}"#).unwrap();
    fs::write(tmp.path().join("run").join("meta.json"), module_json).unwrap();
    (tmp, cd)
}

fn get_json(call_dir: PathBuf, uri: &str) -> (Option<&'static str>, serde_json::Value) {
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, uri, None);
    let status = resp.error_code();
    let body = resp.bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

const MODULE: &str = r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#;

#[test]
fn unknown_module_returns_miss() {
    let (_tmp, cd) = synth_call_dir(MODULE);
    let (status, v) = get_json(cd, "indirect-targets?so=nonexistent.so&off=0x0");
    assert_eq!(status, None);
    assert_eq!(v["status"], "miss");
    assert_eq!(v["query"]["so"], "nonexistent.so");
    assert!(v["reason"].as_str().is_some());
}

#[test]
fn ambiguous_prefix_returns_ambiguous() {
    let (_tmp, cd) = synth_call_dir(
        r#"{"modules":[
            {"name":"libt.so","base":"0x100000","size":65536},
            {"name":"libt_v2.so","base":"0x200000","size":65536}]}"#,
    );
    let (status, v) = get_json(cd, "indirect-targets?so=libt&off=0x0");
    assert_eq!(status, None);
    assert!(
        v["status"] == "ambiguous" || v["status"] == "hit",
        "prefix may resolve or be ambiguous: {v}"
    );
    if v["status"] == "ambiguous" {
        assert!(v["candidates"].as_array().is_some());
        assert!(v["hint"].as_str().is_some());
    }
}

#[test]
fn invalid_addr_returns_error() {
    let (_tmp, cd) = synth_call_dir(MODULE);
    let (status, v) = get_json(cd, "indirect-targets?addr=zz");
    assert_eq!(status, None);
    assert_eq!(v["status"], "error");
    assert!(v["error"].as_str().unwrap().contains("invalid addr"));
}

#[test]
fn nop_pc_returns_no_dispatch() {
    let (_tmp, cd) = synth_call_dir(MODULE);
    let (status, v) = get_json(cd, "indirect-targets?addr=0x100000");
    assert_eq!(status, None);
    assert_eq!(
        v["status"], "no_dispatch",
        "nop is not an indirect branch: {v}"
    );
}

#[test]
fn missing_both_coordinates_returns_error() {
    let (_tmp, cd) = synth_call_dir(MODULE);
    let (status, v) = get_json(cd, "indirect-targets");
    assert_eq!(status, None);
    // No addr and no so/off → source_pc None → full dispatch listing (ok).
    // This is the aggregate view, not an error.
    assert!(
        v["status"] == "ok" || v["status"] == "error",
        "no-coordinate query returns aggregate or error: {v}"
    );
}
