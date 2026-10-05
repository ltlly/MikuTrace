//! Black-box contract tests for the simple CLI command family:
//! capabilities / stats / meta / list / info.

mod common;

use common::{assert_valid, run_json, synth_call_dir};

#[test]
fn capabilities_matches_output_contract_schema() {
    let value = run_json(&["capabilities"]);
    let schema = serde_json::json!({
        "type": "object",
        "required": ["schema_version", "tool", "version", "output_contract", "commands", "capture_extensions"],
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
            "capture_extensions": {
                "type": "object",
                "required": ["command", "implementation", "profile_argument", "profile_schema_version", "transport_argument", "transports", "call_limit_argument", "agent_plugin_api_version", "host_plugin_api_version", "trusted_code_only"],
                "properties": {
                    "profile_schema_version": {"type": "integer", "const": 1},
                    "trusted_code_only": {"type": "boolean", "const": true},
                    "transports": {"type": "array", "items": {"type": "string"}}
                }
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

#[test]
fn finalize_reports_structured_repair_report() {
    // finalize 的输出是 AI 消费契约: 字段名与嵌套结构由 schema 锁定。
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path().join("run");
    let call = run.join("calls").join("_pending_call_001");
    std::fs::create_dir_all(&call).unwrap();
    std::fs::write(
        call.join("meta.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "callIdx": 1, "pid": 7, "tid": 42, "ms": 12,
            "records": 0, "bytes": 0, "truncated": true,
            "last_insn_is_ret": null
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(run.join("meta.json"), br#"{"calls":[]}"#).unwrap();

    let value = run_json(&["finalize", &run.display().to_string()]);
    let schema = serde_json::json!({
        "type": "object",
        "required": ["run", "calls", "repaired", "pending", "renamed"],
        "properties": {
            "run": {"type": "string"},
            "repaired": {"type": "integer", "minimum": 0},
            "pending": {"type": "integer", "minimum": 0},
            "renamed": {"type": "integer", "minimum": 0},
            "calls": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["from", "to", "repaired", "pending", "records", "bytes",
                                 "renamed"],
                    "properties": {
                        "from": {"type": "string"},
                        "to": {"type": "string"},
                        "repaired": {"type": "boolean"},
                        "pending": {"type": "boolean"},
                        "renamed": {"type": "boolean"},
                        "records": {"type": "integer", "minimum": 0},
                        "bytes": {"type": "integer", "minimum": 0},
                        "first_pc": {"type": ["string", "null"]},
                        "last_pc": {"type": ["string", "null"]},
                        "last_insn_is_ret": {"type": ["boolean", "null"]},
                    },
                },
            },
        },
    });
    assert_valid(schema, &value);

    // 语义: 没有本地 trace.bin 的 call 必须保持 pending, 不得声称已修复
    let call0 = &value["calls"][0];
    assert_eq!(call0["pending"], true);
    assert_eq!(call0["repaired"], false);
    assert_eq!(value["pending"], 1);
    // 目录名不得改动
    assert_eq!(call0["from"], "_pending_call_001");
    assert_eq!(call0["to"], "_pending_call_001");
    assert!(call.join("meta.json").exists(), "pending 目录必须保留");
}
