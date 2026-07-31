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
        cd.to_str().unwrap(),
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "start", "end", "returned", "records", "only_vm", "vm_profile"],
            "properties": {
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
    let value = run_json(&["vm-backstep", "--idx", "4", cd.to_str().unwrap()]);
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
    let value = run_json(&["vm-backchain", "--idx", "4", cd.to_str().unwrap()]);
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
    let value = run_json(&["vm-backtree", "--idx", "4", cd.to_str().unwrap()]);
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
