//! 收敛后的公共入口：同一问题共享筛选、时间边界和结果结构。
mod common;
use common::{assert_valid, run_json, synth_call_dir, synth_deep_dir};
use std::process::Command;

#[test]
fn removed_commands_are_absent_and_vm_requires_experimental_namespace() {
    let catalog = run_json(&["capabilities"]);
    let names: Vec<_> = catalog["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    for old in [
        "meta",
        "record",
        "reg-value-at",
        "resolve-map-addr",
        "resolve-elf-symbol",
        "block",
        "block-hits",
        "branch-coverage",
        "fn-summary",
        "call-chain",
        "watch",
        "mem-byte-history",
        "mem-flow",
        "mem-range-accesses",
        "mem-writes-in-range",
        "mem-export",
        "mem-diff",
        "byte-writer-map",
        "dep-graph",
        "forward-dep-graph",
        "jni-object-history",
        "jni-strings",
        "jni-events",
        "fork-events",
        "hash-input-search",
        "base64-map",
        "mem-write-bursts",
        "reg-chase",
        "vm-slice",
        "vm-ops",
        "vm-backstep",
        "vm-backchain",
        "vm-backtree",
    ] {
        assert!(!names.contains(&old), "obsolete public command {old}");
        assert!(!Command::new(env!("CARGO_BIN_EXE_tracemiku-cli"))
            .args([old, "--help"])
            .output()
            .unwrap()
            .status
            .success());
    }
    let experimental = catalog["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "experimental")
        .unwrap();
    assert_eq!(experimental["stability"], "experimental");
    assert_eq!(experimental["subcommands"].as_array().unwrap().len(), 5);
}

#[test]
fn records_selected_indices_honor_register_filter_and_share_pagination_shape() {
    let (_tmp, cd) = synth_deep_dir();
    let path = cd.to_str().unwrap();
    let rows = run_json(&["records", path, "--indices", "7,1", "--regs", "x0"]);
    assert_eq!(rows["returned"], 2);
    assert_eq!(rows["records"][0]["idx"], 7);
    assert_eq!(rows["records"][0]["regs"], serde_json::json!({"x0":"0x21"}));
    assert_eq!(rows["detail"], false);
    let detail = run_json(&["records", path, "--start", "7", "--count", "1", "--detail"]);
    assert_eq!(detail["records"][0]["detail"]["regs"]["x0"], "0x21");
    assert_eq!(detail["returned"], 1);
}

#[test]
fn memory_accesses_share_range_kind_and_half_open_time_filter() {
    let (_tmp, cd) = synth_deep_dir();
    let v = run_json(&[
        "mem-accesses",
        cd.to_str().unwrap(),
        "--addr",
        "2000",
        "--size",
        "12",
        "--start",
        "4",
        "--end",
        "8",
        "--kind",
        "write",
        "--limit",
        "1",
    ]);
    assert_valid(
        serde_json::json!({"type":"object", "required":["start","end","returned","truncated","next_cursor","events"], "properties":{"returned":{"const":1},"truncated":{"const":true},"events":{"type":"array","items":{"type":"object","required":["idx","kind","addr","size","source"]}}}}),
        &v,
    );
    assert!(v["events"][0]["idx"].as_u64().unwrap() >= 4);
    assert!(v["events"][0]["idx"].as_u64().unwrap() < 8);
}

#[test]
fn memory_dump_comparison_preserves_unknown_bytes_and_limits() {
    let (_tmp, cd) = synth_deep_dir();
    let v = run_json(&[
        "mem-dump",
        cd.to_str().unwrap(),
        "--addr",
        "2000",
        "--count",
        "2",
        "--at",
        "7",
        "--compare-at",
        "0",
    ]);
    assert_eq!(v["bytes"][0]["byte"], 33);
    assert!(v["bytes"][0]["comparison"]["byte"].is_null());
    assert_eq!(v["bytes"][0]["comparison"]["change"], "unknown");
    assert_eq!(v["requested_count"], 2);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["addr", "at", "count", "requested_count", "truncated", "observed_count", "bytes"],
            "properties": {
                "at": {"const": 7},
                "bytes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["addr", "byte", "kind", "src_idx", "comparison"],
                        "properties": {
                            "comparison": {
                                "type": "object",
                                "required": ["at", "byte", "kind", "src_idx", "change"],
                                "properties": {"change": {"enum": ["changed", "unchanged", "unknown"]}}
                            }
                        }
                    }
                }
            }
        }),
        &v,
    );
}

#[test]
fn memory_export_writes_known_bytes_and_never_overwrites_on_unknown_or_truncated_input() {
    let (_tmp, cd) = synth_deep_dir();
    let call = cd.to_str().unwrap();
    let output = cd.join("memory.bin");
    run_json(&[
        "mem-dump",
        call,
        "--addr",
        "2000",
        "--count",
        "1",
        "--at",
        "7",
        "--out",
        output.to_str().unwrap(),
    ]);
    assert_eq!(std::fs::read(&output).unwrap(), vec![33]);
    for args in [
        vec!["--addr", "999999", "--count", "1"],
        vec!["--addr", "2000", "--count", "4097"],
        vec!["--addr", "2000", "--at", "99999"],
        vec!["--addr", "ffffffffffffffff", "--count", "2"],
        vec!["--so", "libt.so", "--off", "ffffffffffffffff"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_tracemiku-cli"))
            .args(["mem-dump", call])
            .args(args)
            .args(["--out", output.to_str().unwrap()])
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        let error: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(error["status"], "error");
        assert_eq!(std::fs::read(&output).unwrap(), vec![33]);
    }
    let by_pc = run_json(&["mem-dump", call, "--addr", "100000", "--count", "2"]);
    let by_module = run_json(&[
        "mem-dump", call, "--so", "libt.so", "--off", "0", "--count", "2",
    ]);
    assert_eq!(by_pc, by_module);
}

#[test]
fn sidecar_events_do_not_require_trace_or_build_indexes() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("jni_hooks.jsonl"), "{\"trace_idx\":3,\"id\":\"NewStringUTF\"}\ninvalid\n{\"trace_idx\":4,\"id\":\"NewStringUTF\"}\n").unwrap();
    let v = run_json(&[
        "events",
        tmp.path().to_str().unwrap(),
        "--source",
        "jni",
        "--start",
        "3",
        "--end",
        "4",
    ]);
    assert_eq!(v["returned"], 1);
    assert_eq!(v["events"][0]["source"], "jni");
    assert_eq!(v["invalid_lines"], 1);
    assert_eq!(v["truncated"], false);
}

#[test]
fn cfg_function_and_backtrace_merged_views_keep_evidence_separate() {
    let (_tmp, cd) = synth_call_dir();
    let p = cd.to_str().unwrap();
    let cfg = run_json(&["cfg", p, "--pc", "100000", "--hits", "--coverage"]);
    assert!(cfg["blocks"].is_array());
    assert!(cfg["block"].is_object());
    assert!(cfg["hits"].is_object());
    assert!(cfg["coverage"].is_object());
    let functions = run_json(&["functions", p, "--fn", "f"]);
    assert!(functions["summary"].is_object());
    let bt = run_json(&["backtrace", p, "--idx", "4", "--lr-clues"]);
    assert!(bt["lr_clues"].is_object());
}
