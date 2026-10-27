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
    assert_eq!(detail["records"][0]["detail"]["pointer_status"], "disabled");
    assert_eq!(detail["records"][0]["detail"]["memory_status"], "disabled");
    assert_eq!(detail["records"][0]["detail"]["cfg_status"], "disabled");
    assert!(detail["records"][0]["detail"]["memory_history"].is_null());
    assert!(detail["records"][0]["exec_count"].is_null());
    assert_eq!(detail["returned"], 1);
}

#[test]
fn records_detail_heavy_options_compose_and_restore_evidence() {
    let (_tmp, cd) = synth_deep_dir();
    let path = cd.to_str().unwrap();
    let value = run_json(&[
        "records",
        path,
        "--start",
        "1",
        "--count",
        "1",
        "--detail",
        "--detail-pointers",
        "--detail-memory",
        "--detail-cfg",
    ]);
    let row = &value["records"][0];
    let detail = &row["detail"];
    assert_eq!(detail["pointer_status"], "ready");
    assert_eq!(detail["memory_status"], "ready");
    assert_eq!(detail["cfg_status"], "ready");
    assert!(detail["regs_annotated"]["x1"]
        .as_str()
        .unwrap()
        .contains("apro.ogh"));
    let history = detail["memory_history"].as_array().unwrap();
    assert_eq!(history.len(), 8);
    assert!(history
        .iter()
        .all(|byte| !byte["events"].as_array().unwrap().is_empty()));
    assert!(row["exec_count"].as_u64().unwrap() >= 1);
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

#[test]
fn zero_memory_budget_keeps_light_detail_and_limits_heavy_analysis() {
    let (_tmp, cd) = synth_deep_dir();
    let path = cd.to_str().unwrap();
    let binary = env!("CARGO_BIN_EXE_tracemiku-cli");
    let light = Command::new(binary)
        .args(["records", path, "--start", "1", "--count", "1", "--detail"])
        .env("TRACEMIKU_MEMORY_BUDGET_MB", "0")
        .output()
        .unwrap();
    assert!(
        light.status.success(),
        "light detail failed: {}",
        String::from_utf8_lossy(&light.stdout)
    );
    let light: serde_json::Value = serde_json::from_slice(&light.stdout).unwrap();
    assert_eq!(light["records"][0]["detail"]["memory_status"], "disabled");

    for option in ["--detail-memory", "--detail-cfg"] {
        let output = Command::new(binary)
            .args([
                "records", path, "--start", "1", "--count", "1", "--detail", option,
            ])
            .env("TRACEMIKU_MEMORY_BUDGET_MB", "0")
            .env("TRACEMIKU_BUILD_WAIT_MS", "0")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let error: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(error["status"], "error", "{option}: {error}");
        assert_eq!(
            error["error"]["code"], "limit_exceeded",
            "{option}: {error}"
        );
    }
}

#[test]
fn concurrent_cold_cli_builds_queue_and_share_a_complete_sidecar() {
    let (_tmp, cd) = synth_deep_dir();
    let path = cd.to_str().unwrap();
    let binary = env!("CARGO_BIN_EXE_tracemiku-cli");
    let lock_path = cd.join("trace.bin.analysis-build.lock");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(lock_path)
        .unwrap();
    lock.lock().unwrap();

    let mut children = (0..2)
        .map(|_| {
            Command::new(binary)
                .args(["mem-dump", path, "--addr", "0x2000", "--count", "16"])
                .env("TRACEMIKU_BUILD_WAIT_MS", "10000")
                .env("TRACEMIKU_BUILD_CONCURRENCY", "1")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    std::thread::sleep(std::time::Duration::from_millis(150));
    for child in &mut children {
        assert!(
            child.try_wait().unwrap().is_none(),
            "child bypassed the build lock"
        );
    }
    lock.unlock().unwrap();

    let outputs = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect::<Vec<_>>();
    for output in &outputs {
        assert!(
            output.status.success(),
            "concurrent build failed\nstdout:{}\nstderr:{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let first: serde_json::Value = serde_json::from_slice(&outputs[0].stdout).unwrap();
    let second: serde_json::Value = serde_json::from_slice(&outputs[1].stdout).unwrap();
    assert_eq!(first, second);
    assert_eq!(first["status"], "ready");
    assert_eq!(first["bytes"].as_array().unwrap().len(), 16);
    assert!(cd.join("trace.bin.memshadow.v8.bin").is_file());

    let hot = Command::new(binary)
        .args(["mem-dump", path, "--addr", "0x2000", "--count", "16"])
        .env("TRACEMIKU_BUILD_WAIT_MS", "0")
        .output()
        .unwrap();
    assert!(hot.status.success());
    let hot: serde_json::Value = serde_json::from_slice(&hot.stdout).unwrap();
    assert_eq!(hot, first);
}
