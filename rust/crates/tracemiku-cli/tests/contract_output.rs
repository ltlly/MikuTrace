//! Black-box contract tests for the output command family:
//! output-backtrace / base64-map / byte-lineage.
//!
//! These commands run on the deep synth trace (explicit output values +
//! memory stores). Schemas lock top-level structure and key nested shapes;
//! volatile values stay loose.

mod common;

use common::{assert_valid, run_json, synth_deep_dir};

#[test]
fn output_backtrace_matches_schema() {
    let (_tmp, cd) = synth_deep_dir();
    let value = run_json(&[
        "output-backtrace",
        cd.to_str().unwrap(),
        "--value",
        "qrvM3Q==",
        "--max-mem-hits",
        "3",
        "--writes-per-hit",
        "1",
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "strategy", "source", "patterns", "taint", "notes"],
            "properties": {
                "status": {"const": "ready"},
                "strategy": {"const": "output_to_input_backward_trace"},
                "source": {
                    "type": "object",
                    "required": ["kind", "value", "value_len"],
                    "properties": {"kind": {"const": "value"}},
                },
                "patterns": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["kind", "length", "bytes_hex", "find_mem_pattern", "hit_reports"],
                    },
                },
            },
        }),
        &value,
    );
    let patterns = value["patterns"].as_array().unwrap();
    assert!(
        !patterns.is_empty(),
        "output-backtrace must report patterns"
    );
    assert!(patterns.iter().any(|p| p["kind"] == "observed"));
}

#[test]
fn byte_lineage_matches_schema() {
    let (_tmp, cd) = synth_deep_dir();
    let value = run_json(&[
        "byte-lineage",
        cd.to_str().unwrap(),
        "--addr",
        "0x2000",
        "--before-idx",
        "12",
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "start", "steps", "steps_returned", "depth_requested", "stop_reason"],
            "properties": {
                "steps": {"type": "array"},
                "steps_returned": {"type": "integer"},
            },
        }),
        &value,
    );
}
