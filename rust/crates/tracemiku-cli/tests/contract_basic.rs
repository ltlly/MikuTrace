//! Black-box contract tests for the simple CLI command family:
//! capabilities / stats / meta / list / info.

mod common;

use common::{assert_valid, run_json, synth_call_dir};

#[test]
fn capabilities_matches_output_contract_schema() {
    let value = run_json(&["capabilities"]);
    let schema = serde_json::json!({
        "type": "object",
        "required": ["schema_version", "tool", "version", "output_contract", "commands"],
        "properties": {
            "schema_version": {"const": 1},
            "tool": {"const": "tracemiku-cli"},
            "output_contract": {
                "type": "object",
                "required": ["stdout", "stderr", "success_exit_code", "address_default", "preferred_interface"],
            },
            "commands": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["name", "about", "args", "subcommands"],
                },
            },
        },
    });
    assert_valid(schema, &value);
    let names: Vec<&str> = value["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    for expected in ["records", "backtrace", "vm-ops", "output-backtrace"] {
        assert!(names.contains(&expected), "missing {expected}");
    }
}

#[test]
fn stats_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["stats", cd.to_str().unwrap()]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["path", "records", "module", "modules"],
            "properties": {
                "records": {"type": "integer", "const": 9},
                "module": {"type": "object", "required": ["name", "base", "size"]},
                "modules": {"type": "array"},
            },
        }),
        &value,
    );
}

#[test]
fn meta_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["meta", cd.to_str().unwrap()]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["path", "records", "record_size", "format_version", "module", "truncated"],
            "properties": {
                "records": {"const": 9},
                "record_size": {"const": 272},
                "format_version": {"type": "integer"},
                "truncated": {"type": "boolean"},
                "module": {"type": "object"},
            },
        }),
        &value,
    );
}

#[test]
fn list_matches_schema() {
    let (_tmp, _cd) = synth_call_dir();
    let value = run_json(&["list", "--dir", _tmp.path().to_str().unwrap()]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["kind", "name", "records", "calls", "max_records"],
            "properties": {
                "kind": {"const": "per-call"},
                "records": {"type": "integer"},
                "calls": {"type": "integer"},
            },
        }),
        &value,
    );
}

#[test]
fn info_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["info", cd.to_str().unwrap()]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["path", "records", "tid", "ms", "retval", "truncated", "last_insn_is_ret"],
            "properties": {
                "records": {"const": 9},
                "tid": {"type": "integer"},
                "truncated": {"type": "boolean"},
                "last_insn_is_ret": {"type": "boolean"},
            },
        }),
        &value,
    );
}
