//! Boundary contract tests for the `output-map` command family.
//!
//! Covers the provenance-analysis edges `contract_output.rs` does not:
//! missing output key (no writer runs), empty groups, and the status/error
//! shape when the requested output never appears in the trace.

mod common;

use common::{run_json, synth_deep_dir};

#[test]
fn output_map_missing_key_fails_with_explanation() {
    use std::process::Command;
    let (_tmp, cd) = synth_deep_dir();
    let out = Command::new(env!("CARGO_BIN_EXE_tracemiku-cli"))
        .args([
            "output-map",
            cd.to_str().unwrap(),
            "--key",
            "no_such_output_key_zz",
            "--summary",
        ])
        .output()
        .expect("run tracemiku-cli");
    // 未知输出 key 必须以结构化错误退出，不能伪造空报告。
    assert!(!out.status.success(), "missing key must fail");
    assert_eq!(out.status.code(), Some(1));
    let failure: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(failure["status"], "error");
    assert_eq!(failure["error"]["code"], "command_failed");
    let message = failure["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("no NewStringUTF key/value pair matched"),
        "error.message explains the miss: {message}"
    );
}

#[test]
fn output_map_empty_key_is_rejected() {
    use std::process::Command;
    let (_tmp, cd) = synth_deep_dir();
    let out = Command::new(env!("CARGO_BIN_EXE_tracemiku-cli"))
        .args(["output-map", cd.to_str().unwrap(), "--key", ""])
        .output()
        .expect("run tracemiku-cli");
    assert!(!out.status.success(), "empty key must fail");
}

#[test]
fn output_map_unknown_source_kind_is_null_safe() {
    let (_tmp, cd) = synth_deep_dir();
    // A key with no writer provenance in the synthetic trace must still
    // produce a well-formed report (source fields present, no panic).
    let value = run_json(&[
        "output-map",
        cd.to_str().unwrap(),
        "--key",
        "apro.oghvalue!",
        "--groups",
        "1",
    ]);
    assert_eq!(value["status"], "ready");
    assert!(
        value["source"].is_object(),
        "source object present: {value}"
    );
    assert!(value["groups"].is_array());
}
