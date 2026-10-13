//! Black-box contract tests for the query command family.
//!
//! Contract = output validates against JSON Schema. Schemas lock top-level
//! structure and key field types; volatile values stay loose.

mod common;

use common::{assert_valid, run_json, synth_call_dir};

#[test]
fn records_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["records", cd.to_str().unwrap()]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["count", "returned", "start", "end", "records", "truncated"],
            "properties": {
                "count": {"const": 9},
                "records": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["idx", "pc", "off", "func", "module", "asm"],
                    },
                },
            },
        }),
        &value,
    );
}

#[test]
fn backward_taint_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&[
        "taint-bwd",
        cd.to_str().unwrap(),
        "--start",
        "4",
        "--reg",
        "x0",
        "--max-count",
        "10",
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "from", "reg", "chain", "graph", "count"],
            "properties": {
                "from": {"type": "integer"},
                "chain": {"type": "array"},
                "graph": {
                    "type": "object",
                    "required": ["nodes", "edges", "node_count", "edge_count"],
                },
            },
        }),
        &value,
    );
}

#[test]
fn resolve_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&[
        "resolve",
        cd.to_str().unwrap(),
        "--so",
        "libt.so",
        "--off",
        "0x100",
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "coord", "direction", "query"],
        }),
        &value,
    );
}

#[test]
fn search_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["search", cd.to_str().unwrap(), "nop"]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["count", "returned", "hits", "pattern", "total_matches", "truncated"],
            "properties": {
                "hits": {"type": "array"},
                "pattern": {"type": "string"},
                "truncated": {"type": "boolean"},
            },
        }),
        &value,
    );
}

#[test]
fn functions_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["functions", cd.to_str().unwrap()]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["functions", "total_functions", "returned_functions", "truncated"],
            "properties": {"functions": {"type": "array"}, "truncated": {"type": "boolean"}},
        }),
        &value,
    );
}

#[test]
fn coverage_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["coverage", cd.to_str().unwrap(), "--fn", "f"]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "function", "executed_blocks"],
            "properties": {"executed_blocks": {"type": "integer"}},
        }),
        &value,
    );
}

#[test]
fn call_tree_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["call-tree", cd.to_str().unwrap()]);
    assert_valid(
        serde_json::json!({"type": "object", "required": ["tree"]}),
        &value,
    );
}

#[test]
fn reg_at_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&[
        "reg-at",
        cd.to_str().unwrap(),
        "--addr",
        "0x100000",
        "--reg",
        "x0",
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "source", "reg", "hits", "exec_count", "hits_capped"],
            "properties": {
                "status": {"const": "hit"},
                "reg": {"const": "x0"},
                "hits": {"type": "array", "minItems": 1},
                "exec_count": {"const": 1}
            },
        }),
        &value,
    );
    assert_eq!(value["hits"][0]["idx"], 0);
    assert_eq!(value["hits"][0]["value"], "0x0");
}

#[test]
fn cfg_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["cfg", cd.to_str().unwrap()]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "blocks", "edges", "total_blocks", "total_edges", "truncated"],
            "properties": {"blocks": {"type": "array"}, "edges": {"type": "array"}},
        }),
        &value,
    );
}
