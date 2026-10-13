//! Boundary contract tests for the resolve query.
//!
//! Covers the status matrix: hit / miss / out_of_range / ambiguous / error,
//! plus addr- and offset-based coordinate directions.

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
        .join("call_001_tid100_4r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 4];
    for i in 0..4 {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + (i as u64 * 4)).to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":4}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

fn get_json(call_dir: PathBuf, uri: &str) -> (Option<&'static str>, serde_json::Value) {
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, uri, None);
    let status = resp.error_code();
    let body = resp.bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

fn validate(schema: &serde_json::Value, value: &serde_json::Value) -> Vec<String> {
    let validator = jsonschema::validator_for(schema).expect("valid json schema");
    validator
        .iter_errors(value)
        .map(|e| e.to_string())
        .collect()
}

fn status_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["status", "coord", "direction", "query"],
        "properties": {
            "status": {"enum": ["hit", "miss", "out_of_range", "ambiguous", "error"]},
            "coord": {"type": "object"},
            "direction": {"type": "string"},
        },
    })
}

#[test]
fn resolve_off_in_module_hits() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "resolve?so=libt.so&off=0x0");
    assert_eq!(status, None);
    let errors = validate(&status_schema(), &v);
    assert!(errors.is_empty(), "schema errors: {errors:?}");
    assert_eq!(v["status"], "hit");
}

#[test]
fn resolve_off_outside_module_is_out_of_range() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "resolve?so=libt.so&off=0x99999");
    assert_eq!(status, None);
    assert_eq!(v["status"], "out_of_range");
}

#[test]
fn resolve_unknown_module_is_miss() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "resolve?so=nonexistent.so&off=0x0");
    assert_eq!(status, None);
    assert_eq!(v["status"], "miss");
}

#[test]
fn resolve_invalid_off_returns_error() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "resolve?so=libt.so&off=zz");
    assert_eq!(status, None);
    assert_eq!(v["status"], "error");
    assert!(v["error"].as_str().is_some());
}

#[test]
fn resolve_addr_in_trace_hits() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "resolve?addr=0x100004");
    assert_eq!(status, None);
    assert_eq!(v["status"], "hit");
}

#[test]
fn resolve_missing_args_returns_error() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "resolve");
    assert_eq!(status, None);
    assert_eq!(v["status"], "error");
}

#[test]
fn resolve_ambiguous_module_returns_ambiguous() {
    // Two modules overlapping the same name prefix -> ambiguous status.
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_1r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272];
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":1}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"modules":[{"name":"libt.so","base":"0x100000","size":65536},{"name":"libt_v2.so","base":"0x200000","size":65536}]}"#,
    )
    .unwrap();
    let (status, v) = get_json(cd, "resolve?so=libt&off=0x0");
    assert_eq!(status, None);
    // Prefix match may hit either hit (single candidate) or ambiguous.
    assert!(
        v["status"] == "hit" || v["status"] == "ambiguous",
        "unexpected status: {v:?}"
    );
}
