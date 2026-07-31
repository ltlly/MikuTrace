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
    // Contract: an unknown output key is a hard failure with a stderr
    // explanation — never a fabricated empty report.
    assert!(!out.status.success(), "missing key must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no NewStringUTF key/value pair matched"),
        "stderr explains the miss: {stderr}"
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
    assert!(value["source"].is_object(), "source object present: {value}");
    assert!(value["groups"].is_array());
}
