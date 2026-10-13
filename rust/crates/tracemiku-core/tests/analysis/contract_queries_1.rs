//! Black-box contract tests for core queries that previously had no
//! behavior tests: analysis_index / indirect_targets / mem_export / reg_at.
//!
//! Contract = JSON response validates against the schema defined here,
//! exercised through the typed core query dispatcher.

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
        .join("call_001_tid100_1r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272];
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":1}"#).unwrap();
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

#[test]
fn analysis_index_returns_status_object() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "analysis-index");
    assert_eq!(status, None);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["checkpoint_count", "mem_last_def_count", "sidecar", "summary"],
            "properties": {
                "summary": {"type": "object", "required": ["call_count"]},
            },
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

#[test]
fn indirect_targets_unknown_addr_returns_error_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "indirect-targets?addr=0x999999");
    assert_eq!(status, None);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status"],
            "properties": {"status": {"type": "string"}},
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

#[test]
fn indirect_targets_valid_off_returns_hit_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "indirect-targets?so=libt.so&off=0x0");
    assert_eq!(status, None);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status"],
            "properties": {
                "status": {"enum": ["hit", "miss", "no_dispatch"]},
                "targets": {"type": "array"},
                "distinct_targets": {"type": "integer"},
            },
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

#[test]
fn memory_dump_rejects_missing_address() {
    let (_tmp, cd) = synth_call_dir();
    let (status, _) = get_json(cd, "mem-dump?count=4");
    assert_eq!(status, Some("invalid_argument"));
}

#[test]
fn memory_dump_keeps_unknown_values_and_metadata() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "mem-dump?addr=0x100000&count=4");
    assert_eq!(status, None);
    let errors = validate(
        &serde_json::json!({
            "type":"object", "required":["status","addr","count","requested_count","truncated","completeness","observed_count","bytes"],
            "properties":{"count":{"const":4},"completeness":{"const":0.0},"bytes":{"type":"array","minItems":4,"items":{"type":"object","required":["byte","kind","src_idx"],"properties":{"byte":{"type":"null"}}}}}
        }),
        &v,
    );
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn reg_at_unknown_pc_returns_error_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "reg-at?reg=x0&addr=0x999999");
    assert_eq!(status, None);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status", "reg", "source"],
            "properties": {
                "status": {"enum": ["hit", "no_execution"]},
                "reg": {"type": "string"},
                "source": {"type": "object"},
            },
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
    assert_eq!(v["status"], "no_execution");
}

#[test]
fn reg_at_known_pc_returns_hits_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "reg-at?reg=x0&addr=0x100000");
    assert_eq!(status, None);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status", "reg", "source"],
            "properties": {
                "status": {"enum": ["hit", "no_execution"]},
                "reg": {"type": "string"},
                "source": {"type": "object"},
            },
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}
