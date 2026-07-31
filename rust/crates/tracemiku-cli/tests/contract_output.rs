//! Black-box contract tests for the output command family:
//! output-backtrace / output-map / byte-lineage.
//!
//! These commands run on the deep synth trace (JNI NewStringUTF pairs +
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
        "--key",
        "apro.oghvalue!",
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
                    "required": ["kind", "key", "pair"],
                    "properties": {"kind": {"const": "jni_output_string_pair"}},
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
fn output_map_summary_matches_schema() {
    let (_tmp, cd) = synth_deep_dir();
    let value = run_json(&[
        "output-map",
        cd.to_str().unwrap(),
        "--key",
        "apro.oghvalue!",
        "--summary",
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "strategy", "source", "text_len", "base64_context", "group_total", "groups"],
            "properties": {
                "status": {"const": "ready"},
                "strategy": {"const": "output_base64_group_map"},
                "group_total": {"type": "integer"},
                "groups": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["group", "offset", "end", "chars", "decoded", "decoded_hex"],
                    },
                },
            },
        }),
        &value,
    );
    assert!(value["group_total"].as_u64().unwrap() > 0);
}

#[test]
fn output_map_full_matches_schema() {
    let (_tmp, cd) = synth_deep_dir();
    let value = run_json(&[
        "output-map",
        cd.to_str().unwrap(),
        "--key",
        "apro.oghvalue!",
        "--groups",
        "1",
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "groups", "selected_hit_order", "selected_hit_rank"],
            "properties": {
                "groups": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["group", "chars", "base64", "runs", "trees"],
                    },
                },
            },
        }),
        &value,
    );
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
