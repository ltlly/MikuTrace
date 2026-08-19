//! Black-box semantic assertions for CLI output.
//!
//! Schema tests prove shape; these prove the *values* match the synthetic
//! trace's known facts. A test that passes with wrong values is broken.

mod common;

use common::{run_json, synth_call_dir};

#[test]
fn records_count_matches_meta() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["records", cd.to_str().unwrap()]);
    assert_eq!(value["count"], 9, "trace has exactly 9 records");
    assert_eq!(value["returned"], 9);
    assert_eq!(value["truncated"], false);
}

#[test]
fn record_funcs_resolve_from_known_offsets() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["records", cd.to_str().unwrap()]);
    let records = value["records"].as_array().unwrap();
    let first = &records[0];
    assert_eq!(first["off"], "0x0");
    assert_eq!(first["func"], "f");
    assert_eq!(first["module"], "libt.so");
}

#[test]
fn records_resolve_all_known_functions() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["records", cd.to_str().unwrap()]);
    let funcs: Vec<&str> = value["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["func"].as_str().unwrap())
        .collect();
    for expected in ["f", "f_alpha", "f_beta"] {
        assert!(funcs.contains(&expected), "missing {expected} in {funcs:?}");
    }
}

#[test]
fn resolve_off_maps_to_known_function() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&[
        "resolve",
        cd.to_str().unwrap(),
        "--so",
        "libt.so",
        "--off",
        "0x100",
    ]);
    assert_eq!(value["status"], "hit", "resolve must hit: {value:?}");
    assert_eq!(value["query"]["off"], "0x100");
    assert_eq!(value["query"]["so"], "libt.so");
}

#[test]
fn stats_reports_known_module_and_records() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["stats", cd.to_str().unwrap()]);
    assert_eq!(value["records"], 9);
    assert_eq!(value["module"]["name"], "libt.so");
    assert_eq!(value["module"]["base"], "0x100000");
}

#[test]
fn meta_reports_record_size_272() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["meta", cd.to_str().unwrap()]);
    assert_eq!(value["record_size"], 272, "272-byte record contract");
    assert_eq!(value["records"], 9);
    assert_eq!(value["truncated"], false);
}

#[test]
fn info_reports_call_identity() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["info", cd.to_str().unwrap()]);
    assert_eq!(value["tid"], 100);
    assert_eq!(value["ms"], 2);
    assert_eq!(value["records"], 9);
    assert_eq!(value["last_insn_is_ret"], false, "9 nop records, no ret");
}

#[test]
fn capabilities_lock_output_contract() {
    let value = run_json(&["capabilities"]);
    assert_eq!(value["output_contract"]["success_exit_code"], 0);
    assert_eq!(
        value["output_contract"]["address_default"],
        "hexadecimal; use the command help for explicit decimal syntax"
    );
    let names: Vec<&str> = value["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"output-backtrace"));
    assert!(names.contains(&"vm-ops"));
}
