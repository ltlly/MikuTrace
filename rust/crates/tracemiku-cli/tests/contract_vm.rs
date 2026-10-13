//! Black-box contract tests for the vm command family:
//! vm-slice / vm-ops / vm-backstep / vm-backchain / vm-backtree.

mod common;

use common::{assert_valid, run_json, synth_deep_dir};

#[test]
fn vm_slice_matches_schema() {
    let (_tmp, cd) = synth_deep_dir();
    let value = run_json(&[
        "vm-slice",
        "--start",
        "0",
        "--count",
        "12",
        "--vm-slot-bytes",
        "8",
        "--vm-ip-reg",
        "x9",
        "--vm-state-reg",
        "x10",
        "--vm-dispatch-reg",
        "x11",
        cd.to_str().unwrap(),
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "start", "end", "returned", "records", "only_vm", "vm_profile"],
            "properties": {
                "vm_profile": {"type": "object", "required": ["slot_bytes"],
                    "properties": {"slot_bytes": {"type": "integer", "const": 8}}},
                "records": {"type": "array"},
                "only_vm": {"type": "boolean"},
            },
        }),
        &value,
    );
}

#[test]
fn vm_ops_matches_schema() {
    let (_tmp, cd) = synth_deep_dir();
    let value = run_json(&[
        "vm-ops",
        "--start",
        "0",
        "--end",
        "12",
        "--vm-slot-bytes",
        "8",
        "--vm-ip-reg",
        "x9",
        "--vm-state-reg",
        "x10",
        "--vm-dispatch-reg",
        "x11",
        cd.to_str().unwrap(),
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "start", "end", "ops", "ops_returned", "vm_profile", "vm_rows"],
            "properties": {
                "ops": {"type": "array"},
                "ops_returned": {"type": "integer"},
                "vm_rows": {"type": "integer"},
            },
        }),
        &value,
    );
    assert!(value["ops"]
        .as_array()
        .unwrap()
        .iter()
        .any(|op| { op.get("class_counts").and_then(|c| c.as_object()).is_some() }));
}

#[test]
fn vm_backstep_matches_schema() {
    let (_tmp, cd) = synth_deep_dir();
    let value = run_json(&[
        "vm-backstep",
        "--idx",
        "4",
        "--vm-slot-bytes",
        "8",
        "--vm-ip-reg",
        "x9",
        "--vm-state-reg",
        "x10",
        "--vm-dispatch-reg",
        "x11",
        cd.to_str().unwrap(),
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "idx", "target", "source_reg", "source_value", "upstream", "frontier"],
            "properties": {
                "idx": {"type": "integer"},
                "frontier": {"type": "array"},
            },
        }),
        &value,
    );
}

#[test]
fn vm_backchain_matches_schema() {
    let (_tmp, cd) = synth_deep_dir();
    let value = run_json(&[
        "vm-backchain",
        "--idx",
        "4",
        "--vm-slot-bytes",
        "8",
        "--vm-ip-reg",
        "x9",
        "--vm-state-reg",
        "x10",
        "--vm-dispatch-reg",
        "x11",
        cd.to_str().unwrap(),
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "start", "chain", "steps_requested", "steps_returned", "follow_frontier"],
            "properties": {
                "chain": {"type": "array"},
                "steps_returned": {"type": "integer"},
            },
        }),
        &value,
    );
}

#[test]
fn vm_backtree_matches_schema() {
    let (_tmp, cd) = synth_deep_dir();
    let value = run_json(&[
        "vm-backtree",
        "--idx",
        "4",
        "--vm-slot-bytes",
        "8",
        "--vm-ip-reg",
        "x9",
        "--vm-state-reg",
        "x10",
        "--vm-dispatch-reg",
        "x11",
        cd.to_str().unwrap(),
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "start", "nodes", "nodes_returned", "depth_requested", "max_nodes", "truncated"],
            "properties": {
                "nodes": {"type": "array"},
                "nodes_returned": {"type": "integer"},
                "truncated": {"type": "boolean"},
            },
        }),
        &value,
    );
}

#[test]
fn vm_profile_requires_an_explicit_slot_layout() {
    let (_tmp, cd) = synth_deep_dir();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tracemiku-cli"))
        .args([
            "vm-slice",
            cd.to_str().unwrap(),
            "--start",
            "0",
            "--count",
            "1",
            "--vm-ip-reg",
            "x2",
            "--vm-state-reg",
            "x3",
            "--vm-dispatch-reg",
            "x4",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let error: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("--vm-slot-bytes"));
}
