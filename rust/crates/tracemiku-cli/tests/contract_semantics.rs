//! Black-box semantic assertions for CLI output.
//!
//! Schema tests prove shape; these prove the *values* match the synthetic
//! trace's known facts. A test that passes with wrong values is broken.

mod common;

use common::{run_json, synth_call_dir, synth_deep_dir};

#[test]
fn documented_negative_sentinels_are_accepted_as_separate_arguments() {
    let (_tmp, cd) = synth_deep_dir();
    let call = cd.to_str().unwrap();
    for args in [
        vec!["block-hits", call, "--pc", "100000", "--near", "-1"],
        vec!["strings", call, "--cursor", "-1"],
        vec![
            "last-write-of-addr",
            call,
            "--addr",
            "2000",
            "--before-idx",
            "-1",
        ],
        vec![
            "find-mem-pattern",
            call,
            "--bytes-hex",
            "6170",
            "--since",
            "-1",
        ],
        vec!["reg-timeline", call, "--reg", "x0", "--end", "-1"],
        vec![
            "mem-writes-in-range",
            call,
            "--idx-lo",
            "0",
            "--idx-hi",
            "-1",
        ],
        vec![
            "byte-writer-map",
            call,
            "--addr",
            "2000",
            "--size",
            "8",
            "--idx-hi",
            "-1",
        ],
        vec![
            "jni-object-history",
            call,
            "--jobject",
            "2222",
            "--end",
            "-1",
        ],
    ] {
        let output = run_json(&args);
        assert_ne!(output["status"], "error", "{args:?}");
    }
}

#[test]
fn addresses_share_hex_default_and_explicit_decimal_across_queries() {
    let (_tmp, cd) = synth_deep_dir();
    let call = cd.to_str().unwrap();
    for variants in [
        ["0x100000", "100000", "d1048576"],
        ["0x2000", "2000", "d8192"],
    ] {
        let commands: Vec<Vec<&str>> = if variants[0] == "0x100000" {
            vec![vec!["pc-hits", call], vec!["block", call, "--pc"]]
        } else {
            vec![
                vec!["mem-accesses", call, "--addr"],
                vec!["mem-range-accesses", call, "--addr"],
                vec!["mem-dump", call, "--count", "8", "--addr"],
                vec!["mem-byte-history", call, "--length", "8", "--addr"],
                vec!["mem-provenance", call, "--length", "8", "--addr"],
                vec!["mem-flow", call, "--addr"],
                vec!["mem-diff", call, "--idx", "1", "--addr"],
                vec!["last-write-of-addr", call, "--addr"],
                vec!["dep-graph", call, "--addr"],
            ]
        };
        for command in commands {
            let mut outputs = Vec::new();
            for raw in variants {
                let mut args = command.clone();
                args.push(raw);
                let mut value = run_json(&args);
                if let Some(object) = value.as_object_mut() {
                    // Some commands intentionally echo the exact user input.
                    object.remove("addr");
                    object.remove("pc");
                }
                outputs.push(value);
            }
            assert_eq!(outputs[0], outputs[1], "{} bare hex", command[0]);
            assert_eq!(outputs[0], outputs[2], "{} explicit decimal", command[0]);
            if command[0] == "dep-graph" {
                assert_eq!(outputs[0]["seed"]["idx"], 7);
                assert!(outputs[0]["graph"]["node_count"].as_u64().unwrap() > 0);
            }
            if command[0] == "mem-range-accesses" {
                assert!(outputs[0]["writers_total"].as_u64().unwrap() > 0);
            }
        }
    }
}

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
    let capture = &value["capture_extensions"];
    assert_eq!(capture["command"], "trace");
    assert_eq!(capture["profile_argument"], "--target-profile");
    assert_eq!(capture["transport_argument"], "--transport");
    assert_eq!(capture["call_limit_argument"], "--max-calls");
    assert_eq!(capture["transports"], serde_json::json!(["frida", "adb"]));
    assert_eq!(capture["agent_plugin_api_version"], 1);
    assert_eq!(capture["host_plugin_api_version"], 1);
    assert_eq!(capture["trusted_code_only"], true);
}
