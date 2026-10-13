//! Boundary contract tests for timeline_diff queries (reg-timeline / mem-diff).

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
    let insts: [u32; 4] = [0xaa0103e0, 0xaa0203e1, 0xd503201f, 0xd65f03c0];
    let mut buf = vec![0u8; 272 * 4];
    for (i, inst) in insts.iter().enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + (i as u64 * 4)).to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&((i as u64 + 1) * 10).to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
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

#[test]
fn reg_timeline_default_end_covers_trace() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "reg-timeline?reg=x0&start=0");
    assert_eq!(status, None);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["reg", "start", "end", "count", "points", "truncated"],
            "properties": {
                "reg": {"const": "x0"},
                "end": {"const": 4},
                "points": {"type": "array"},
                "truncated": {"type": "boolean"},
            },
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

#[test]
fn reg_timeline_end_beyond_trace_clamps() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "reg-timeline?reg=x0&start=0&end=999");
    assert_eq!(status, None);
    assert_eq!(v["end"], 4, "clamped to trace length");
}

#[test]
fn reg_timeline_start_past_end_returns_empty() {
    let (_tmp, cd) = synth_call_dir();
    // start=3, end=2 -> start clamped to min(end) = 2; empty window.
    let (status, v) = get_json(cd, "reg-timeline?reg=x0&start=3&end=2");
    assert_eq!(status, None);
    assert_eq!(v["start"], 2);
    assert_eq!(v["end"], 2);
}

#[test]
fn reg_timeline_negative_end_means_all() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "reg-timeline?reg=x0&start=0&end=-1");
    assert_eq!(status, None);
    assert_eq!(v["end"], 4, "end=-1 -> full trace");
}

#[test]
fn reg_timeline_max_points_truncates() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "reg-timeline?reg=x0&start=0&max_points=2");
    assert_eq!(status, None);
    assert!(v["points"].as_array().unwrap().len() <= 2);
    assert_eq!(v["truncated"], true, "4 points but max 2");
}

#[test]
fn mem_diff_returns_comparison_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "mem-diff?idx=0&addr=0x2000&size=4");
    assert_eq!(status, None);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status"],
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}
