//! Black-box contract tests for the dec command family.
//!
//! Contract = output validates against JSON Schema. Local analysis must not
//! depend on LLM availability, so these tests run without any LLM key.

mod common;

use common::{assert_valid, run_json, synth_call_dir};

#[test]
fn dec_summary_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["dec-summary", cd.to_str().unwrap()]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["fns", "module_name", "module_base", "module_size", "records", "vm_candidates"],
            "properties": {
                "fns": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["id", "name", "module", "entry_idx", "exit_idx", "source"],
                    },
                },
                "records": {"type": "integer"},
                "vm_candidates": {"type": "array"},
            },
        }),
        &value,
    );
    let fns = value["fns"].as_array().unwrap();
    assert!(!fns.is_empty(), "dec-summary must list functions");
    assert!(fns.iter().all(|f| f["name"].as_str().is_some()));
}

#[test]
fn dec_fn_matches_schema_without_llm() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["dec-fn", cd.to_str().unwrap(), "trace:F0"]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["fn_id", "name", "markdown", "tier"],
            "properties": {
                "fn_id": {"type": "string"},
                "markdown": {"type": "string"},
                "tier": {"type": "string"},
            },
        }),
        &value,
    );
    assert_eq!(value["fn_id"], "trace:F0");
}

#[test]
fn dec_models_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["dec-models", cd.to_str().unwrap()]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["models", "api_keys_configured"],
            "properties": {
                "models": {"type": "array", "items": {"type": "string"}},
                "api_keys_configured": {"type": "object"},
            },
        }),
        &value,
    );
    assert!(!value["models"].as_array().unwrap().is_empty());
}
